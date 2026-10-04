package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationFailureReason;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationIssue;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import com.github.xingjianluo.auditlogintegrityjava.storage.Anchor;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStore;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * 归档导出服务：把指定序号区间导出为自包含、可离线核验的签名归档包。
 *
 * <p>导出前对整条链做单趟流式校验（内存 O(1)，只把区间内事件收集进包），
 * 链不完好则整体拒绝导出。包内容即当时落盘的事件本体（含当时的脱敏值与策略版本），
 * 之后的策略调整、保留期清理都不会改变已导出包的核验结论。
 */
@Service
public class ArchiveExportService {

    private static final Logger log = LoggerFactory.getLogger(ArchiveExportService.class);

    private final AuditStore store;
    private final ChainHasher hasher;
    private final ArchiveKeyService keyService;
    private final ObjectMapper mapper;

    public ArchiveExportService(AuditStore store, ChainHasher hasher,
                                ArchiveKeyService keyService, ObjectMapper mapper) {
        this.store = store;
        this.hasher = hasher;
        this.keyService = keyService;
        this.mapper = mapper;
    }

    /**
     * 导出 [fromSeq, toSeq] 闭区间为一个归档包。
     */
    public synchronized ArchiveExportResult exportRange(long fromSeq, long toSeq) {
        if (fromSeq < 1 || toSeq < fromSeq) {
            throw new IllegalArgumentException("非法区间: fromSeq=" + fromSeq + ", toSeq=" + toSeq);
        }
        Anchor anchor = store.readAnchor();
        if (anchor.isEmpty()) {
            log.info("归档导出结论: outcome={}, 区间=[{},{}], 依据=链为空", ArchiveExportOutcome.EMPTY_CHAIN, fromSeq, toSeq);
            return new ArchiveExportResult(ArchiveExportOutcome.EMPTY_CHAIN, null, null,
                    fromSeq, toSeq, 0, List.of(), "链为空，无可导出记录");
        }
        if (fromSeq < anchor.headSeq()) {
            log.info("归档导出结论: outcome={}, 区间=[{},{}], 依据=fromSeq 早于当前链头 {}",
                    ArchiveExportOutcome.RANGE_PRUNED, fromSeq, toSeq, anchor.headSeq());
            return new ArchiveExportResult(ArchiveExportOutcome.RANGE_PRUNED, null, null,
                    fromSeq, toSeq, 0, List.of(),
                    "区间起点 seq=" + fromSeq + " 已被保留期清理（当前链头 seq=" + anchor.headSeq() + "），无法导出");
        }
        if (fromSeq > anchor.tailSeq()) {
            log.info("归档导出结论: outcome={}, 区间=[{},{}], 依据=区间超出链尾 {}",
                    ArchiveExportOutcome.RANGE_NOT_FOUND, fromSeq, toSeq, anchor.tailSeq());
            return new ArchiveExportResult(ArchiveExportOutcome.RANGE_NOT_FOUND, null, null,
                    fromSeq, toSeq, 0, List.of(),
                    "区间起点 seq=" + fromSeq + " 超出当前链尾 seq=" + anchor.tailSeq());
        }

        List<AuditEvent> inRange = new ArrayList<>();
        List<VerificationIssue> issues = new ArrayList<>();
        long[] scanned = {0};
        AuditEvent[] prev = {null};
        AuditEvent[] first = {null};
        AuditEvent[] last = {null};
        try (Stream<AuditEvent> stream = store.streamEvents()) {
            stream.forEach(e -> {
                scanned[0]++;
                if (first[0] == null) {
                    first[0] = e;
                }
                last[0] = e;
                String recomputed = hasher.computeHash(e);
                if (!recomputed.equals(e.hash())) {
                    issues.add(new VerificationIssue(VerificationFailureReason.ENTRY_HASH_MISMATCH,
                            e.seq(), e.eventId(), "存储 hash 与复算 hash 不一致"));
                }
                if (prev[0] == null) {
                    if (e.seq() == 1L && !ChainHasher.GENESIS_HASH.equals(e.prevHash())) {
                        issues.add(new VerificationIssue(VerificationFailureReason.LINK_MISMATCH,
                                e.seq(), e.eventId(), "首条事件 prevHash 不是创世哈希"));
                    }
                } else {
                    if (!Objects.equals(e.prevHash(), prev[0].hash())) {
                        issues.add(new VerificationIssue(VerificationFailureReason.LINK_MISMATCH,
                                e.seq(), e.eventId(), "prevHash 与上一条 hash 不一致"));
                    }
                    if (e.seq() != prev[0].seq() + 1) {
                        issues.add(new VerificationIssue(VerificationFailureReason.SEQUENCE_GAP,
                                e.seq(), e.eventId(), "期望 seq=" + (prev[0].seq() + 1)
                                + " 实际 seq=" + e.seq()));
                    }
                }
                prev[0] = e;
                if (e.seq() >= fromSeq && e.seq() <= toSeq) {
                    inRange.add(e);
                }
            });
        } catch (AuditStoreException malformed) {
            issues.add(new VerificationIssue(VerificationFailureReason.MALFORMED_ENTRY,
                    null, null, malformed.getMessage()));
        }

        // 锚点核对（与 AuditService 同一套判定：合法的“锚点落后”崩溃窗口不算篡改）
        if (first[0] != null && issues.isEmpty()) {
            boolean anchorLagging = !anchor.isEmpty()
                    && first[0].seq() == anchor.headSeq()
                    && Objects.equals(first[0].hash(), anchor.headHash())
                    && last[0].seq() > anchor.tailSeq();
            if (!anchorLagging) {
                if (first[0].seq() != anchor.headSeq()) {
                    issues.add(new VerificationIssue(
                            first[0].seq() > anchor.headSeq()
                                    ? VerificationFailureReason.TRUNCATED
                                    : VerificationFailureReason.ANCHOR_MISMATCH,
                            first[0].seq(), first[0].eventId(),
                            "链头 seq=" + first[0].seq() + " 与锚点 headSeq=" + anchor.headSeq() + " 不一致"));
                } else if (!Objects.equals(first[0].hash(), anchor.headHash())) {
                    issues.add(new VerificationIssue(VerificationFailureReason.ANCHOR_MISMATCH,
                            first[0].seq(), first[0].eventId(), "链头 hash 与锚点 headHash 不一致"));
                }
                if (scanned[0] != anchor.count()) {
                    issues.add(new VerificationIssue(VerificationFailureReason.ANCHOR_MISMATCH,
                            null, null, "条目数=" + scanned[0] + " 与锚点 count=" + anchor.count() + " 不一致"));
                }
                if (last[0].seq() < anchor.tailSeq()) {
                    issues.add(new VerificationIssue(VerificationFailureReason.TRUNCATED,
                            last[0].seq(), last[0].eventId(),
                            "链尾 seq=" + last[0].seq() + " 早于锚点 tailSeq=" + anchor.tailSeq()));
                } else if (last[0].seq() == anchor.tailSeq()
                        && !Objects.equals(last[0].hash(), anchor.tailHash())) {
                    issues.add(new VerificationIssue(VerificationFailureReason.ANCHOR_MISMATCH,
                            last[0].seq(), last[0].eventId(), "链尾 hash 与锚点 tailHash 不一致"));
                }
            }
        }

        if (!issues.isEmpty()) {
            log.warn("归档导出结论: outcome={}, 区间=[{},{}], 问题数={}, 首个问题={}",
                    ArchiveExportOutcome.INTEGRITY_FAILED, fromSeq, toSeq, issues.size(), issues.get(0));
            return new ArchiveExportResult(ArchiveExportOutcome.INTEGRITY_FAILED, null, null,
                    fromSeq, toSeq, 0, List.copyOf(issues), "本地链完整性校验未通过，未导出");
        }
        if (inRange.isEmpty() || inRange.size() != toSeq - fromSeq + 1) {
            // 锚点称区间在链内但实际未收集全：区间尾部超出链尾
            log.info("归档导出结论: outcome={}, 区间=[{},{}], 依据=区间尾部超出链尾 {}",
                    ArchiveExportOutcome.RANGE_NOT_FOUND, fromSeq, toSeq, last[0] == null ? 0 : last[0].seq());
            return new ArchiveExportResult(ArchiveExportOutcome.RANGE_NOT_FOUND, null, null,
                    fromSeq, toSeq, 0, List.of(),
                    "区间尾部 seq=" + toSeq + " 超出当前链尾，无法导出完整区间");
        }

        AuditEvent head = inRange.get(0);
        AuditEvent tail = inRange.get(inRange.size() - 1);
        TreeSet<Integer> policyVersions = new TreeSet<>();
        inRange.forEach(e -> policyVersions.add(e.policyVersion()));

        ArchiveManifest manifest = new ArchiveManifest(
                ArchiveFormat.FORMAT, ArchiveFormat.VERSION,
                UUID.randomUUID().toString(),
                keyService.environmentId(),
                System.currentTimeMillis(),
                fromSeq, toSeq, inRange.size(),
                head.prevHash(), head.hash(), tail.hash(),
                List.copyOf(policyVersions));
        String signature = keyService.sign(ArchiveFormat.canonicalManifestBytes(manifest));
        ArchivePackage pkg = new ArchivePackage(manifest, List.copyOf(inRange), signature);
        final byte[] bytes;
        try {
            bytes = mapper.writeValueAsBytes(pkg);
        } catch (IOException e) {
            throw new AuditStoreException("序列化归档包失败", e);
        }
        log.info("归档导出结论: outcome={}, archiveId={}, env={}, 区间=[{},{}], 条数={}, 包大小={}B",
                ArchiveExportOutcome.EXPORTED, manifest.archiveId(), manifest.environmentId(),
                fromSeq, toSeq, inRange.size(), bytes.length);
        return new ArchiveExportResult(ArchiveExportOutcome.EXPORTED, bytes, manifest.archiveId(),
                fromSeq, toSeq, inRange.size(), List.of(), "导出成功");
    }
}
