package com.github.xingjianluo.auditlogintegrityjava;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveConclusion;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveFormat;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveManifest;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerification;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 归档包导出 + 离线核验：各类破坏都要有各自可区分的结论。
 * 每个用例日志都打印输入（区间/破坏手段）与判定依据。
 */
class ArchiveOfflineVerificationTest {

    private static final Logger log = LoggerFactory.getLogger(ArchiveOfflineVerificationTest.class);
    private final ObjectMapper mapper = new ObjectMapper();

    @TempDir
    Path dir;

    private AuditTestSupport.Harness newChain(int events) {
        AuditTestSupport.Harness h = AuditTestSupport.harness(dir.resolve("env-" + System.nanoTime()));
        for (int i = 1; i <= events; i++) {
            h.events().append("actor" + i, "ACTION" + i, "res" + i,
                    AuditTestSupport.payload("password", "secret" + i, "note", "n" + i));
        }
        return h;
    }

    private byte[] exportRange(AuditTestSupport.Harness h, long from, long to) {
        ArchiveExportResult result = h.archiveExporter().exportRange(from, to);
        log.info("[输入] 导出区间=[{},{}] -> 导出结论={}", from, to, result.outcome());
        assertEquals(ArchiveExportOutcome.EXPORTED, result.outcome());
        return result.packageBytes();
    }

    private ArchiveVerification verify(AuditTestSupport.Harness source, byte[] pkg) {
        ArchiveVerification v = source.archiveVerifier().verify(pkg, source.archiveKeys().publicKeyBytes());
        log.info("[判定依据] 离线核验结论={}, 依据={}", v.conclusion(), v.details());
        return v;
    }

    private byte[] tamper(byte[] pkg, Consumer<ObjectNode> mutation) {
        try {
            ObjectNode root = (ObjectNode) mapper.readTree(pkg);
            mutation.accept(root);
            return mapper.writeValueAsBytes(root);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void validPackageVerifiesOffline() {
        AuditTestSupport.Harness h = newChain(10);
        byte[] pkg = exportRange(h, 3, 7);
        ArchiveVerification v = verify(h, pkg);
        assertEquals(ArchiveConclusion.VALID, v.conclusion());
        assertEquals(3, v.fromSeq());
        assertEquals(7, v.toSeq());
        assertEquals(5, v.eventCount());
        assertEquals(h.archiveKeys().environmentId(), v.environmentId());
    }

    @Test
    void modifiedContentIsContentTampered() {
        AuditTestSupport.Harness h = newChain(10);
        byte[] pkg = exportRange(h, 3, 7);
        byte[] broken = tamper(pkg, root ->
                ((ObjectNode) ((ArrayNode) root.get("events")).get(1)).put("actor", "forged"));
        log.info("[输入] 篡改包内第 2 条事件的 actor 字段（不重算哈希）");
        assertEquals(ArchiveConclusion.CONTENT_TAMPERED, verify(h, broken).conclusion());
    }

    @Test
    void modifiedContentWithRecomputedHashIsStillContentTampered() {
        AuditTestSupport.Harness h = newChain(10);
        byte[] pkg = exportRange(h, 3, 7);
        byte[] broken = tamper(pkg, root -> {
            ArrayNode events = (ArrayNode) root.get("events");
            ObjectNode target = (ObjectNode) events.get(1);
            target.put("actor", "forged");
            try {
                AuditEvent modified = mapper.treeToValue(target, AuditEvent.class);
                // 攻击者重算被改事件的 hash，试图蒙混过关
                target.put("hash", h.hasher().computeHash(modified));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        log.info("[输入] 篡改第 2 条事件内容并重算其 hash（链节指向包内不存在的前驱）");
        assertEquals(ArchiveConclusion.CONTENT_TAMPERED, verify(h, broken).conclusion());
    }

    @Test
    void deletedMiddleRecordIsRecordsDeleted() {
        AuditTestSupport.Harness h = newChain(10);
        byte[] pkg = exportRange(h, 3, 7);
        byte[] broken = tamper(pkg, root -> ((ArrayNode) root.get("events")).remove(2));
        log.info("[输入] 删除区间中间一条记录（seq=5）");
        assertEquals(ArchiveConclusion.RECORDS_DELETED, verify(h, broken).conclusion());
    }

    @Test
    void truncatedTailIsTailTruncated() {
        AuditTestSupport.Harness h = newChain(10);
        byte[] pkg = exportRange(h, 3, 7);
        byte[] broken = tamper(pkg, root -> {
            ArrayNode events = (ArrayNode) root.get("events");
            events.remove(4);
            events.remove(3);
        });
        log.info("[输入] 截掉区间尾部两条记录（seq=6,7），现存部分是合法前缀");
        assertEquals(ArchiveConclusion.TAIL_TRUNCATED, verify(h, broken).conclusion());
    }

    @Test
    void shuffledOrderIsOrderShuffled() {
        AuditTestSupport.Harness h = newChain(10);
        byte[] pkg = exportRange(h, 3, 7);
        byte[] broken = tamper(pkg, root -> {
            ArrayNode events = (ArrayNode) root.get("events");
            var a = events.get(1);
            var b = events.get(3);
            events.set(1, b);
            events.set(3, a);
        });
        log.info("[输入] 交换区间内两条记录的位置（seq=4 与 seq=6）");
        assertEquals(ArchiveConclusion.ORDER_SHUFFLED, verify(h, broken).conclusion());
    }

    @Test
    void forgedSelfConsistentPackageFailsSignature() throws Exception {
        AuditTestSupport.Harness victim = newChain(5);
        byte[] genuine = exportRange(victim, 1, 5);
        // 攻击者用自己的密钥造一个内容自洽的假包
        AuditTestSupport.Harness attacker = AuditTestSupport.harness(dir.resolve("attacker"));
        for (int i = 1; i <= 5; i++) {
            attacker.events().append("fake", "LOGIN", "res", AuditTestSupport.payload("k", "v"));
        }
        byte[] forged = exportRange(attacker, 1, 5);
        log.info("[输入] 攻击者自造的自洽假包，拿真实环境的公钥核验");
        ArchiveVerification v = verify(victim, forged);
        assertEquals(ArchiveConclusion.SIGNATURE_INVALID, v.conclusion());
        // 真包不受影响
        assertEquals(ArchiveConclusion.VALID, verify(victim, genuine).conclusion());
    }

    @Test
    void packageFromOtherEnvironmentCannotSubstitute() {
        AuditTestSupport.Harness envA = newChain(5);
        AuditTestSupport.Harness envB = AuditTestSupport.harness(dir.resolve("envB"));
        for (int i = 1; i <= 5; i++) {
            envB.events().append("b", "ACT", "res", AuditTestSupport.payload("k", "v" + i));
        }
        byte[] pkgB = exportRange(envB, 1, 5);
        log.info("[输入] 环境B的包，拿环境A的公钥核验（跨环境顶替）");
        ArchiveVerification v = envA.archiveVerifier().verify(pkgB, envA.archiveKeys().publicKeyBytes());
        log.info("[判定依据] 结论={}, 依据={}", v.conclusion(), v.details());
        assertEquals(ArchiveConclusion.SIGNATURE_INVALID, v.conclusion());
        // 用 B 自己的公钥核 B 的包则有效
        assertEquals(ArchiveConclusion.VALID,
                envB.archiveVerifier().verify(pkgB, envB.archiveKeys().publicKeyBytes()).conclusion());
    }

    @Test
    void resignedManifestWithWrongEnvironmentIdIsEnvironmentMismatch() {
        AuditTestSupport.Harness h = newChain(5);
        byte[] pkg = exportRange(h, 1, 5);
        byte[] broken = tamper(pkg, root -> {
            ObjectNode manifest = (ObjectNode) root.get("manifest");
            manifest.put("environmentId", "env-0000000000000000");
            try {
                ArchiveManifest m = mapper.treeToValue(manifest, ArchiveManifest.class);
                // 持有私钥的一方把 environmentId 改错并重签（模拟标识与密钥不匹配的交付错误）
                root.put("signature", h.archiveKeys().sign(ArchiveFormat.canonicalManifestBytes(m)));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        log.info("[输入] 清单 environmentId 与公钥派生标识不一致（签名本身有效）");
        assertEquals(ArchiveConclusion.ENVIRONMENT_MISMATCH, verify(h, broken).conclusion());
    }

    @Test
    void truncatedPackageFileIsMalformed() {
        AuditTestSupport.Harness h = newChain(5);
        byte[] pkg = exportRange(h, 1, 5);
        byte[] cut = new byte[pkg.length / 2];
        System.arraycopy(pkg, 0, cut, 0, cut.length);
        log.info("[输入] 包文件被截断一半（{} -> {} 字节）", pkg.length, cut.length);
        assertEquals(ArchiveConclusion.MALFORMED_PACKAGE, verify(h, cut).conclusion());
    }

    @Test
    void emptyChainExportIsDistinctOutcome() {
        AuditTestSupport.Harness h = AuditTestSupport.harness(dir.resolve("empty"));
        ArchiveExportResult result = h.archiveExporter().exportRange(1, 10);
        log.info("[输入] 空链导出 -> 结论={}, 依据={}", result.outcome(), result.detail());
        assertEquals(ArchiveExportOutcome.EMPTY_CHAIN, result.outcome());
    }

    @Test
    void singleEventChainExportsAndVerifies() {
        AuditTestSupport.Harness h = newChain(1);
        byte[] pkg = exportRange(h, 1, 1);
        ArchiveVerification v = verify(h, pkg);
        assertEquals(ArchiveConclusion.VALID, v.conclusion());
        assertEquals(1, v.eventCount());
    }

    @Test
    void prunedRangeIsDistinctOutcomeAndRemainingRangeStillExports() {
        AuditTestSupport.Harness h = newChain(10);
        int removed = h.auditService().retainByBatch(1, 4); // 保留 seq 7..10
        log.info("[输入] 保留期清理删除 {} 条后导出已清理区间 [2,5]", removed);
        ArchiveExportResult pruned = h.archiveExporter().exportRange(2, 5);
        log.info("[判定依据] 结论={}, 依据={}", pruned.outcome(), pruned.detail());
        assertEquals(ArchiveExportOutcome.RANGE_PRUNED, pruned.outcome());

        byte[] pkg = exportRange(h, 7, 10);
        assertEquals(ArchiveConclusion.VALID, verify(h, pkg).conclusion());
    }

    @Test
    void rangeBeyondTailIsNotFound() {
        AuditTestSupport.Harness h = newChain(5);
        ArchiveExportResult result = h.archiveExporter().exportRange(8, 12);
        log.info("[输入] 导出超出链尾的区间 [8,12]（链尾=5）-> 结论={}", result.outcome());
        assertEquals(ArchiveExportOutcome.RANGE_NOT_FOUND, result.outcome());
    }

    @Test
    void laterPolicyChangeDoesNotAffectExportedPackage() {
        AuditTestSupport.Harness h = newChain(5);
        byte[] pkg = exportRange(h, 1, 5);
        h.maskingService().updatePolicy(java.util.Set.of("password", "note", "extra"), "***");
        log.info("[输入] 导出后变更脱敏策略（version -> {}），再核验旧包", h.maskingService().current().version());
        assertEquals(ArchiveConclusion.VALID, verify(h, pkg).conclusion());
    }

    @Test
    void laterSourcePruningDoesNotAffectExportedPackage() {
        AuditTestSupport.Harness h = newChain(10);
        byte[] pkg = exportRange(h, 2, 6);
        h.auditService().retainByBatch(1, 3); // 源环境把区间清理掉
        log.info("[输入] 导出后源环境按批次保留清理掉该区间，再核验旧包");
        ArchiveVerification v = verify(h, pkg);
        assertEquals(ArchiveConclusion.VALID, v.conclusion());
        assertEquals(5, v.eventCount());
    }

    @Test
    void localChainTamperingMakesExportRefuse() throws Exception {
        AuditTestSupport.Harness h = newChain(5);
        Path eventsFile = h.dir().resolve("events.jsonl");
        List<String> lines = java.nio.file.Files.readAllLines(eventsFile);
        ObjectNode node = (ObjectNode) mapper.readTree(lines.get(2));
        node.put("actor", "intruder");
        lines.set(2, mapper.writeValueAsString(node));
        java.nio.file.Files.write(eventsFile, lines);
        log.info("[输入] 本地链第 3 条被篡改后尝试导出 [1,5]");
        ArchiveExportResult result = h.archiveExporter().exportRange(1, 5);
        log.info("[判定依据] 结论={}, 问题={}", result.outcome(), result.integrityIssues());
        assertEquals(ArchiveExportOutcome.INTEGRITY_FAILED, result.outcome());
        assertTrue(result.packageBytes() == null);
    }
}
