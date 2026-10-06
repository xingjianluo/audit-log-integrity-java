package com.github.xingjianluo.auditlogintegrityjava.service;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationFailureReason;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationIssue;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingPolicy;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingService;
import com.github.xingjianluo.auditlogintegrityjava.storage.Anchor;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStore;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 审计链路核心服务。
 *
 * <p>所有写操作在同一把进程内锁下串行化（单写者），保证并发提交的顺序性与幂等性；
 * 完整性校验读取链与锚点两份独立持久化的证据，区分以下失败原因：
 * 篡改条目哈希、断链、序号空洞/重排、截断（删头/去尾/清空）、锚点不符、条目损坏。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditStore store;
    private final ChainHasher hasher;
    private final MaskingService maskingService;
    private final Object writeLock = new Object();

    public AuditService(AuditStore store, ChainHasher hasher, MaskingService maskingService) {
        this.store = store;
        this.hasher = hasher;
        this.maskingService = maskingService;
    }

    /**
     * 追加事件（幂等）。
     * <ul>
     *   <li>相同 eventId 且 actor/action/resource 一致：视为重复提交，返回已存在事件，不新增记录；</li>
     *   <li>相同 eventId 但身份字段不同：抛 {@link DuplicateEventException}；</li>
     *   <li>链当前不完整：抛 {@link IntegrityException}（拒绝在破损链上续写）。</li>
     * </ul>
     */
    public AuditEvent append(EventInput input) {
        validate(input);
        synchronized (writeLock) {
            CheckedChain chain = loadAndCheck();
            List<AuditEvent> events = chain.events;

            for (AuditEvent existing : events) {
                if (existing.eventId().equals(input.eventId())) {
                    if (sameIdentity(existing, input)) {
                        log.info("重复事件被幂等忽略: eventId={}, seq={}", input.eventId(), existing.seq());
                        return existing;
                    }
                    throw new DuplicateEventException("eventId=" + input.eventId()
                            + " 已存在但提交内容不同，拒绝写入");
                }
            }
            if (!chain.report.valid()) {
                throw new IntegrityException("完整性校验未通过，拒绝追加事件: " + input.eventId(), chain.report);
            }

            MaskingPolicy policy = maskingService.current();
            long seq = events.isEmpty() ? 1L : events.get(events.size() - 1).seq() + 1;
            String prevHash = events.isEmpty() ? ChainHasher.GENESIS_HASH : events.get(events.size() - 1).hash();

            AuditEvent candidate = new AuditEvent(
                    input.eventId(), seq, System.currentTimeMillis(),
                    input.actor(), input.action(), input.resource(),
                    maskingService.mask(input.payload(), policy), policy.version(),
                    prevHash, "");
            String hash = hasher.computeHash(candidate);
            AuditEvent event = new AuditEvent(candidate.eventId(), candidate.seq(), candidate.timestamp(),
                    candidate.actor(), candidate.action(), candidate.resource(),
                    candidate.payload(), candidate.policyVersion(), candidate.prevHash(), hash);

            store.append(event);
            Anchor newAnchor;
            if (events.isEmpty()) {
                newAnchor = new Anchor(event.seq(), event.hash(), event.seq(), event.hash(), 1);
            } else {
                AuditEvent head = events.get(0);
                newAnchor = new Anchor(head.seq(), head.hash(), event.seq(), event.hash(), events.size() + 1);
            }
            store.writeAnchor(newAnchor);
            log.info("审计事件已追加: eventId={}, seq={}, policyVersion={}, prevHash={}, hash={}",
                    event.eventId(), event.seq(), event.policyVersion(),
                    abbreviate(event.prevHash()), abbreviate(event.hash()));
            return event;
        }
    }

    /**
     * 校验整条链。校验过程同时对“文件已追加但锚点落后”的合法崩溃状态做对账修复。
     */
    public VerificationReport verify() {
        synchronized (writeLock) {
            return loadAndCheck().report;
        }
    }

    /**
     * 按批次保留：保留最新 keepBatches 批、每批 batchSize 条，其余按批次删除。
     * 清理是“整体重写链文件 + 刷新锚点”的单步可恢复操作；清理后重新校验必须通过。
     *
     * @return 实际删除条数
     */
    public int retainByBatch(int keepBatches, int batchSize) {
        if (keepBatches < 0 || batchSize <= 0) {
            throw new IllegalArgumentException("keepBatches >= 0 且 batchSize > 0");
        }
        synchronized (writeLock) {
            CheckedChain chain = loadAndCheck();
            if (!chain.report.valid()) {
                throw new IntegrityException("完整性校验未通过，拒绝执行保留期清理", chain.report);
            }
            List<AuditEvent> events = chain.events;
            int keep = keepBatches * batchSize;
            if (events.size() <= keep) {
                log.info("无需清理: 当前 {} 条, 保留窗口 {} 条", events.size(), keep);
                return 0;
            }
            long keepBeforeSeq = events.get(events.size() - keep).seq();
            log.info("按批次清理: 删除 seq < {} 的事件, 保留 {} 条", keepBeforeSeq, keep);

            List<AuditEvent> retained = store.pruneBefore(keepBeforeSeq);

            VerificationReport after = loadAndCheck().report;
            if (!after.valid()) {
                throw new IntegrityException("清理后完整性校验失败", after);
            }
            return events.size() - retained.size();
        }
    }

    public List<AuditEvent> readAll() {
        synchronized (writeLock) {
            return store.readAll();
        }
    }

    /**
     * 把归档包中的事件并入本地链，使其成为本环境自己的记录。
     *
     * <p>并入规则（全部在同一把写锁内完成，与追加/清理/其他导入互斥）：
     * <ul>
     *   <li>本地链校验不通过 → CHAIN_INVALID，零改动；</li>
     *   <li>本环境自己导出的区间若已被保留期清理（包起点早于当前链头）
     *       → PRUNED_RANGE，拒绝让已清理记录复活，零改动；</li>
     *   <li>幂等：并入后的事件以 {@code 来源环境:原eventId} 落库（本环境包也兼容匹配原 id），
     *       全部已存在 → DUPLICATE_IGNORED；部分已存在 → 跳过已有、只补缺失，
     *       结果与一次性并入相同；</li>
     *   <li>同一事件 ID 内容不一致 → EVENT_CONFLICT，零改动；</li>
     *   <li>写入：重链（新 seq、新 prevHash、本地复算 hash，其余字段原样保留）后
     *       整体重写链文件 + 刷新锚点，中途失败原有记录一字节不变。</li>
     * </ul>
     *
     * @param sourceEnvironmentId 包来源环境 id（用于生成并入事件的限定 id）
     * @param sameEnvironment     包是否来自本环境（本环境包按原始 eventId 判重，并做清理区间检查）
     * @param imported            包内事件（已通过离线核验，顺序与包内一致）
     */
    public ImportMergeResult mergeImported(String sourceEnvironmentId, boolean sameEnvironment,
                                           List<AuditEvent> imported) {
        if (imported == null || imported.isEmpty()) {
            throw new IllegalArgumentException("并入事件列表不能为空");
        }
        synchronized (writeLock) {
            CheckedChain chain = loadAndCheck();
            List<AuditEvent> events = chain.events;
            if (!chain.report.valid()) {
                log.warn("归档并入拒绝: 本地链完整性校验未通过, 问题数={}", chain.report.issues().size());
                return new ImportMergeResult(ImportMergeOutcome.CHAIN_INVALID, 0, events.size(),
                        "本地审计链完整性校验未通过，拒绝在破损链上并入（本地记录零改动）");
            }
            if (sameEnvironment && !events.isEmpty()
                    && imported.get(0).seq() < events.get(0).seq()) {
                log.warn("归档并入拒绝: 本环境区间起点 seq={} 早于当前链头 seq={}，该段已被保留期清理",
                        imported.get(0).seq(), events.get(0).seq());
                return new ImportMergeResult(ImportMergeOutcome.PRUNED_RANGE, 0, events.size(),
                        "包内区间 [" + imported.get(0).seq() + "," + imported.get(imported.size() - 1).seq()
                                + "] 是本环境已被保留期清理的区段（当前链头 seq=" + events.get(0).seq()
                                + "），为避免已清理记录复活，拒绝并入（本地记录零改动）");
            }

            Map<String, AuditEvent> byId = new HashMap<>();
            for (AuditEvent e : events) {
                byId.put(e.eventId(), e);
            }
            List<AuditEvent> missing = new ArrayList<>();
            for (AuditEvent e : imported) {
                String qualifiedId = sourceEnvironmentId + ":" + e.eventId();
                AuditEvent existing = byId.get(qualifiedId);
                if (existing == null && sameEnvironment) {
                    existing = byId.get(e.eventId());
                }
                if (existing != null) {
                    if (!sameIdentity(existing, e)) {
                        log.warn("归档并入拒绝: 事件 {} 与本地已有记录 {} 内容冲突", e.eventId(), existing.eventId());
                        return new ImportMergeResult(ImportMergeOutcome.EVENT_CONFLICT, 0, events.size(),
                                "包内事件 " + e.eventId() + " 与本地已有记录 " + existing.eventId()
                                        + " 事件 ID 相同但内容不同，存在矛盾（本地记录零改动），应与提供方核对");
                    }
                    continue; // 已在本地：幂等跳过
                }
                missing.add(e);
                byId.put(qualifiedId, e); // 包内重复 id 按同一批幂等处理
            }
            if (missing.isEmpty()) {
                log.info("归档并入幂等忽略: 来源={}, 包内 {} 条全部已在本地链中", sourceEnvironmentId, imported.size());
                return new ImportMergeResult(ImportMergeOutcome.DUPLICATE_IGNORED, 0, events.size(),
                        "这批记录已全部并入过本地链，幂等忽略，未新增记录");
            }

            // 重链：并入事件获得本环境的新 seq / prevHash / hash，业务字段原样保留
            long seq = events.isEmpty() ? 1L : events.get(events.size() - 1).seq() + 1;
            String prevHash = events.isEmpty() ? ChainHasher.GENESIS_HASH
                    : events.get(events.size() - 1).hash();
            List<AuditEvent> merged = new ArrayList<>(events.size() + missing.size());
            merged.addAll(events);
            for (AuditEvent e : missing) {
                AuditEvent candidate = new AuditEvent(
                        sourceEnvironmentId + ":" + e.eventId(), seq, e.timestamp(),
                        e.actor(), e.action(), e.resource(),
                        e.payload(), e.policyVersion(), prevHash, "");
                String hash = hasher.computeHash(candidate);
                merged.add(new AuditEvent(candidate.eventId(), candidate.seq(), candidate.timestamp(),
                        candidate.actor(), candidate.action(), candidate.resource(),
                        candidate.payload(), candidate.policyVersion(), candidate.prevHash(), hash));
                prevHash = hash;
                seq++;
            }

            store.rewriteAll(merged);
            AuditEvent head = merged.get(0);
            AuditEvent tail = merged.get(merged.size() - 1);
            store.writeAnchor(new Anchor(head.seq(), head.hash(), tail.seq(), tail.hash(), merged.size()));

            VerificationReport after = loadAndCheck().report;
            if (!after.valid()) {
                // 构造上不应发生：若发生说明实现有缺陷，按内部错误上抛而非假装成功
                throw new IllegalStateException("并入后链校验未通过: " + after.issues());
            }
            log.info("归档并入完成: 来源={}, 新并入={} 条, 跳过已有={} 条, 本地链总数={}, 新区间尾 seq={}",
                    sourceEnvironmentId, missing.size(), imported.size() - missing.size(),
                    merged.size(), tail.seq());
            return new ImportMergeResult(ImportMergeOutcome.MERGED, missing.size(), merged.size(),
                    "已把 " + missing.size() + " 条记录并入本地链（事件 ID 以 " + sourceEnvironmentId
                            + ": 前缀落库），可与本地记录一起查询、整体校验通过、可继续追加");
        }
    }

    // ---- 内部：链校验 + 锚点对账 ----

    private record CheckedChain(List<AuditEvent> events, Anchor anchor, VerificationReport report) {
    }

    private CheckedChain loadAndCheck() {
        List<AuditEvent> events;
        try {
            events = store.readAll();
        } catch (AuditStoreException malformed) {
            // 文件存在但条目损坏/无法解析：无法继续密码学校验，按 MALFORMED_ENTRY 报告
            VerificationIssue issue = new VerificationIssue(
                    VerificationFailureReason.MALFORMED_ENTRY, null, null, malformed.getMessage());
            Anchor anchor = safeReadAnchor();
            log.warn("校验结论=无效 原因=MALFORMED_ENTRY 依据={}", malformed.getMessage());
            return new CheckedChain(List.of(), anchor,
                    new VerificationReport(false, 0, 0, 0, List.of(issue)));
        }
        Anchor anchor = store.readAnchor();
        List<VerificationIssue> issues = new ArrayList<>();

        if (events.isEmpty()) {
            if (!anchor.isEmpty()) {
                issues.add(new VerificationIssue(VerificationFailureReason.TRUNCATED, null, null,
                        "链文件为空但锚点记录 count=" + anchor.count() + "，链被整体清空"));
            }
            return finish(events, anchor, issues);
        }

        AuditEvent first = events.get(0);
        AuditEvent last = events.get(events.size() - 1);

        // 合法崩溃形态：链是文件的一个真前缀（锚点落后于文件尾部）。
        // 条件：链头与锚点一致、链尾晚于锚点尾；此时不报告锚点问题，稍后对账前滚。
        boolean anchorLagging = !anchor.isEmpty()
                && first.seq() == anchor.headSeq()
                && Objects.equals(first.hash(), anchor.headHash())
                && last.seq() > anchor.tailSeq();

        // 头部与锚点
        if (!anchorLagging) {
            if (anchor.isEmpty()) {
                if (first.seq() != 1L) {
                    issues.add(new VerificationIssue(VerificationFailureReason.TRUNCATED, first.seq(), first.eventId(),
                            "锚点为空且链从 seq=" + first.seq() + " 开始（应从 1 开始），疑似头部被删除"));
                }
            } else {
                if (first.seq() != anchor.headSeq()) {
                    VerificationFailureReason reason = first.seq() > anchor.headSeq()
                            ? VerificationFailureReason.TRUNCATED : VerificationFailureReason.ANCHOR_MISMATCH;
                    issues.add(new VerificationIssue(reason, first.seq(), first.eventId(),
                            "链头 seq=" + first.seq() + " 与锚点 headSeq=" + anchor.headSeq() + " 不一致"));
                } else if (!Objects.equals(first.hash(), anchor.headHash())) {
                    issues.add(new VerificationIssue(VerificationFailureReason.ANCHOR_MISMATCH, first.seq(),
                            first.eventId(), "链头 hash 与锚点 headHash 不一致"));
                }
                if (events.size() != anchor.count()) {
                    issues.add(new VerificationIssue(VerificationFailureReason.ANCHOR_MISMATCH, first.seq(),
                            first.eventId(), "链条目数=" + events.size() + " 与锚点 count=" + anchor.count()
                                    + " 不一致，存在删除/插入"));
                }
            }
        }

        // 逐条：哈希、链节、序号
        String expectedPrev = null;
        long expectedSeq = first.seq();
        for (int i = 0; i < events.size(); i++) {
            AuditEvent e = events.get(i);
            String recomputed = hasher.computeHash(e);
            if (!recomputed.equals(e.hash())) {
                issues.add(new VerificationIssue(VerificationFailureReason.ENTRY_HASH_MISMATCH, e.seq(), e.eventId(),
                        "存储 hash=" + abbreviate(e.hash()) + " 与复算 hash=" + abbreviate(recomputed) + " 不一致"));
            }
            if (i == 0) {
                if (e.seq() == 1L && !ChainHasher.GENESIS_HASH.equals(e.prevHash())) {
                    issues.add(new VerificationIssue(VerificationFailureReason.LINK_MISMATCH, e.seq(), e.eventId(),
                            "首条事件 prevHash 不是创世哈希"));
                }
            } else if (!Objects.equals(e.prevHash(), expectedPrev)) {
                issues.add(new VerificationIssue(VerificationFailureReason.LINK_MISMATCH, e.seq(), e.eventId(),
                        "prevHash=" + abbreviate(e.prevHash()) + " 与上一条 hash="
                                + abbreviate(expectedPrev) + " 不一致"));
            }
            if (e.seq() != expectedSeq) {
                issues.add(new VerificationIssue(VerificationFailureReason.SEQUENCE_GAP, e.seq(), e.eventId(),
                        "期望 seq=" + expectedSeq + " 实际 seq=" + e.seq()));
            }
            expectedPrev = e.hash();
            expectedSeq = e.seq() + 1;
        }

        // 尾部与锚点：落后于文件即“追加后崩溃”，合法对账；文件落后于锚点即截断
        if (!anchor.isEmpty() && !anchorLagging) {
            if (last.seq() < anchor.tailSeq()) {
                issues.add(new VerificationIssue(VerificationFailureReason.TRUNCATED, last.seq(), last.eventId(),
                        "链尾 seq=" + last.seq() + " 早于锚点 tailSeq=" + anchor.tailSeq() + "，尾部被截断"));
            } else if (last.seq() == anchor.tailSeq() && !Objects.equals(last.hash(), anchor.tailHash())) {
                issues.add(new VerificationIssue(VerificationFailureReason.ANCHOR_MISMATCH, last.seq(), last.eventId(),
                        "链尾 hash 与锚点 tailHash 不一致"));
            }
        }

        return finish(events, anchor, issues);
    }

    private CheckedChain finish(List<AuditEvent> events, Anchor anchor, List<VerificationIssue> issues) {
        boolean valid = issues.isEmpty();
        // 合法对账：仅当密码学链本身完全有效、且锚点只是“落后于文件尾部”时，前滚锚点
        if (valid && !events.isEmpty()) {
            AuditEvent first = events.get(0);
            AuditEvent last = events.get(events.size() - 1);
            boolean anchorStale = anchor.isEmpty()
                    || last.seq() > anchor.tailSeq()
                    || events.size() != anchor.count();
            if (anchorStale) {
                Anchor advanced = new Anchor(first.seq(), first.hash(), last.seq(), last.hash(), events.size());
                store.writeAnchor(advanced);
                anchor = advanced;
                log.info("锚点对账前滚: headSeq={}, tailSeq={}, count={}",
                        advanced.headSeq(), advanced.tailSeq(), advanced.count());
            }
        }
        long headSeq = events.isEmpty() ? 0 : events.get(0).seq();
        long tailSeq = events.isEmpty() ? 0 : events.get(events.size() - 1).seq();
        VerificationReport report = new VerificationReport(valid, events.size(), headSeq, tailSeq, List.copyOf(issues));
        log.info("完整性校验: 结论={}, 扫描条目={}, 区间=[{},{}], 问题数={}",
                valid ? "有效" : "无效", report.scannedEntries(), headSeq, tailSeq, issues.size());
        issues.forEach(i -> log.warn("  判定依据: reason={}, seq={}, eventId={}, detail={}",
                i.reason(), i.seq(), i.eventId(), i.detail()));
        return new CheckedChain(events, anchor, report);
    }

    private Anchor safeReadAnchor() {
        try {
            return store.readAnchor();
        } catch (AuditStoreException e) {
            return Anchor.empty();
        }
    }

    private static boolean sameIdentity(AuditEvent existing, EventInput input) {
        return Objects.equals(existing.actor(), input.actor())
                && Objects.equals(existing.action(), input.action())
                && Objects.equals(existing.resource(), input.resource());
    }

    private static boolean sameIdentity(AuditEvent a, AuditEvent b) {
        return Objects.equals(a.actor(), b.actor())
                && Objects.equals(a.action(), b.action())
                && Objects.equals(a.resource(), b.resource());
    }

    private static void validate(EventInput input) {
        if (input == null || input.eventId() == null || input.eventId().isBlank()) {
            throw new IllegalArgumentException("eventId 不能为空");
        }
    }

    private static String abbreviate(String h) {
        if (h == null) {
            return "null";
        }
        return h.length() <= 12 ? h : h.substring(0, 12) + "...";
    }
}
