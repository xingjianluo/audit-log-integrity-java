package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 归档包离线核验器：只依赖包字节与来源环境公钥（带外获得），
 * 不接触来源服务的存储与运行时状态；来源环境之后的策略变更、保留期清理
 * 都不影响对包内当时证据的复算。
 *
 * <p>判定顺序（先外后内，结论互相可区分）：
 * <ol>
 *   <li>包可解析、格式版本相符，否则 {@link ArchiveConclusion#MALFORMED_PACKAGE}；</li>
 *   <li>清单签名用所持公钥核验，否则 {@link ArchiveConclusion#SIGNATURE_INVALID}（掉包/伪造）；</li>
 *   <li>清单环境标识与公钥派生标识一致，否则 {@link ArchiveConclusion#ENVIRONMENT_MISMATCH}；</li>
 *   <li>逐条复算事件哈希，否则 {@link ArchiveConclusion#CONTENT_TAMPERED}；</li>
 *   <li>序号自 fromSeq 连续递增：出现空洞为 {@link ArchiveConclusion#RECORDS_DELETED}，
 *       非递增为 {@link ArchiveConclusion#ORDER_SHUFFLED}；</li>
 *   <li>数量不足但现存部分是合法前缀为 {@link ArchiveConclusion#TAIL_TRUNCATED}，
 *       数量超出清单为 {@link ArchiveConclusion#CONTENT_TAMPERED}；</li>
 *   <li>链节指向包内不存在的前驱（内容被重写过的特征）为
 *       {@link ArchiveConclusion#CONTENT_TAMPERED}，指向包内其他位置为
 *       {@link ArchiveConclusion#ORDER_SHUFFLED}；</li>
 *   <li>链头/链尾与清单绑定一致，否则 {@link ArchiveConclusion#CONTENT_TAMPERED}。</li>
 * </ol>
 */
@Component
public class ArchiveVerifier {

    private static final Logger log = LoggerFactory.getLogger(ArchiveVerifier.class);

    private final ChainHasher hasher;
    private final ObjectMapper mapper = new ObjectMapper();

    public ArchiveVerifier(ChainHasher hasher) {
        this.hasher = hasher;
    }

    /**
     * 离线核验归档包。
     *
     * @param packageBytes       包字节
     * @param trustedPublicKey   来源环境公钥（带外获得，环境标识由它派生）
     */
    public ArchiveVerification verify(byte[] packageBytes, byte[] trustedPublicKey) {
        ArchivePackage pkg = parse(packageBytes);
        if (pkg == null) {
            return conclude(ArchiveConclusion.MALFORMED_PACKAGE, null, null, 0, 0, 0,
                    List.of("包字节无法解析为合法归档包（被截断/损坏/格式版本不符）"));
        }
        ArchiveManifest m = pkg.manifest();

        if (!ArchiveKeyService.verifySignature(trustedPublicKey,
                ArchiveFormat.canonicalManifestBytes(m), nullToEmpty(pkg.signature()))) {
            return conclude(ArchiveConclusion.SIGNATURE_INVALID, m, pkg,
                    List.of("清单签名无法用所持公钥核验通过，包被掉包或伪造"));
        }
        String derivedEnv = ArchiveKeyService.environmentIdOf(trustedPublicKey);
        if (!derivedEnv.equals(m.environmentId())) {
            return conclude(ArchiveConclusion.ENVIRONMENT_MISMATCH, m, pkg,
                    List.of("清单 environmentId=" + m.environmentId()
                            + " 与公钥派生标识 " + derivedEnv + " 不一致，包来自其他环境"));
        }
        if (m.count() != m.toSeq() - m.fromSeq() + 1 || m.fromSeq() < 1 || m.count() < 1) {
            return conclude(ArchiveConclusion.MALFORMED_PACKAGE, m, pkg,
                    List.of("清单自相矛盾: fromSeq=" + m.fromSeq() + " toSeq=" + m.toSeq()
                            + " count=" + m.count()));
        }

        List<AuditEvent> events = pkg.events();
        for (AuditEvent e : events) {
            if (e.eventId() == null || e.hash() == null || e.prevHash() == null) {
                return conclude(ArchiveConclusion.CONTENT_TAMPERED, m, pkg,
                        List.of("事件缺少必要字段（eventId/hash/prevHash）: seq=" + e.seq()));
            }
            String recomputed = hasher.computeHash(e);
            if (!recomputed.equals(e.hash())) {
                return conclude(ArchiveConclusion.CONTENT_TAMPERED, m, pkg,
                        List.of("事件内容被改: seq=" + e.seq() + " eventId=" + e.eventId()
                                + " 存储hash=" + abbreviate(e.hash())
                                + " 复算hash=" + abbreviate(recomputed)));
            }
        }

        // 序号：自 fromSeq 连续递增。先判断序号集合是否完整（一条不缺）：
        // 完整而顺序不对是“顺序被打乱”；有缺失才是“记录被删”。
        Set<Long> seqSet = new HashSet<>();
        events.forEach(e -> seqSet.add(e.seq()));
        boolean seqSetComplete = seqSet.size() == m.count();
        if (seqSetComplete) {
            for (long s = m.fromSeq(); s <= m.toSeq(); s++) {
                if (!seqSet.contains(s)) {
                    seqSetComplete = false;
                    break;
                }
            }
        }
        long expectedSeq = m.fromSeq();
        Set<String> hashSet = new HashSet<>();
        events.forEach(e -> hashSet.add(e.hash()));
        for (int i = 0; i < events.size(); i++) {
            AuditEvent e = events.get(i);
            if (e.seq() != expectedSeq) {
                if (seqSetComplete) {
                    return conclude(ArchiveConclusion.ORDER_SHUFFLED, m, pkg,
                            List.of("位置 " + (i + 1) + " 处 seq=" + e.seq()
                                    + "（期望 " + expectedSeq + "），记录一条不缺但顺序被打乱"));
                }
                if (e.seq() > expectedSeq) {
                    return conclude(ArchiveConclusion.RECORDS_DELETED, m, pkg,
                            List.of("序号出现空洞: 期望 seq=" + expectedSeq + " 实际 seq=" + e.seq()
                                    + "，区间内有记录被删除"));
                }
                return conclude(ArchiveConclusion.RECORDS_DELETED, m, pkg,
                        List.of("位置 " + (i + 1) + " 处 seq=" + e.seq() + " 重复/错位"
                                + "且区间内有记录缺失（期望 " + expectedSeq + "）"));
            }
            expectedSeq++;
        }

        // 数量：不足为尾部截断（现存部分是合法前缀），超出为清单外混入
        if (events.size() < m.count()) {
            return conclude(ArchiveConclusion.TAIL_TRUNCATED, m, pkg,
                    List.of("清单声明 count=" + m.count() + "（至 seq=" + m.toSeq() + "），"
                            + "包内仅 " + events.size() + " 条，尾部被截断"));
        }
        if (events.size() > m.count()) {
            return conclude(ArchiveConclusion.CONTENT_TAMPERED, m, pkg,
                    List.of("包内事件数 " + events.size() + " 超出清单 count=" + m.count()
                            + "，混入了清单之外的记录"));
        }

        // 链节：前驱必须存在且就是上一条
        if (events.isEmpty()) {
            return conclude(ArchiveConclusion.TAIL_TRUNCATED, m, pkg,
                    List.of("包内无任何事件但清单声明 count=" + m.count() + "，内容被整体截除"));
        }
        AuditEvent first = events.get(0);
        if (!nullToEmpty(m.precedingHash()).equals(first.prevHash())) {
            return conclude(ArchiveConclusion.CONTENT_TAMPERED, m, pkg,
                    List.of("首条事件 prevHash 与清单 precedingHash 不一致，区间锚定信息被改"));
        }
        for (int i = 1; i < events.size(); i++) {
            AuditEvent e = events.get(i);
            String actualPrev = events.get(i - 1).hash();
            if (!e.prevHash().equals(actualPrev)) {
                if (hashSet.contains(e.prevHash())) {
                    return conclude(ArchiveConclusion.ORDER_SHUFFLED, m, pkg,
                            List.of("seq=" + e.seq() + " 的 prevHash 指向包内其他记录而非上一条，"
                                    + "顺序被打乱"));
                }
                return conclude(ArchiveConclusion.CONTENT_TAMPERED, m, pkg,
                        List.of("seq=" + e.seq() + " 的 prevHash 指向包内不存在的前驱，"
                                + "链节被重写过（内容被改后重算哈希的特征）"));
            }
        }

        // 链头/链尾与签名清单绑定
        AuditEvent last = events.get(events.size() - 1);
        if (!first.hash().equals(m.headHash()) || !last.hash().equals(m.tailHash())) {
            return conclude(ArchiveConclusion.CONTENT_TAMPERED, m, pkg,
                    List.of("包内链头/链尾哈希与签名清单不一致，事件被整体替换"));
        }

        return conclude(ArchiveConclusion.VALID, m, pkg,
                List.of("签名有效，" + events.size() + " 条事件哈希/序号/链节/清单绑定全部复算一致"));
    }

    // ---- 内部 ----

    private ArchivePackage parse(byte[] packageBytes) {
        try {
            JsonNode root = mapper.readTree(packageBytes);
            if (root == null || !root.isObject() || !root.hasNonNull("manifest")
                    || !root.has("events") || !root.get("events").isArray()
                    || !root.hasNonNull("signature")) {
                return null;
            }
            ArchiveManifest manifest = mapper.treeToValue(root.get("manifest"), ArchiveManifest.class);
            if (manifest == null || !ArchiveFormat.FORMAT.equals(manifest.format())
                    || manifest.version() != ArchiveFormat.VERSION) {
                return null;
            }
            List<AuditEvent> events = new ArrayList<>();
            for (JsonNode node : root.get("events")) {
                events.add(mapper.treeToValue(node, AuditEvent.class));
            }
            return new ArchivePackage(manifest, events, root.get("signature").asText());
        } catch (IOException | IllegalArgumentException e) {
            log.warn("归档包解析失败: {}", e.getMessage());
            return null;
        }
    }

    private ArchiveVerification conclude(ArchiveConclusion conclusion, ArchiveManifest m,
                                         ArchivePackage pkg, List<String> details) {
        return conclude(conclusion,
                m == null ? null : m.archiveId(),
                m == null ? null : m.environmentId(),
                m == null ? 0 : m.fromSeq(),
                m == null ? 0 : m.toSeq(),
                pkg == null ? 0 : pkg.events().size(),
                details);
    }

    private ArchiveVerification conclude(ArchiveConclusion conclusion, String archiveId,
                                         String environmentId, long fromSeq, long toSeq,
                                         int eventCount, List<String> details) {
        ArchiveVerification report = new ArchiveVerification(conclusion, archiveId,
                environmentId, fromSeq, toSeq, eventCount, List.copyOf(details));
        if (report.valid()) {
            log.info("归档包离线核验: 结论={}, archiveId={}, env={}, 区间=[{},{}], 条数={}",
                    conclusion, archiveId, environmentId, fromSeq, toSeq, eventCount);
        } else {
            log.warn("归档包离线核验: 结论={}, archiveId={}, env={}, 区间=[{},{}], 条数={}, 依据={}",
                    conclusion, archiveId, environmentId, fromSeq, toSeq, eventCount, details);
        }
        return report;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String abbreviate(String h) {
        if (h == null) {
            return "null";
        }
        return h.length() <= 12 ? h : h.substring(0, 12) + "...";
    }
}
