package com.github.xingjianluo.auditlogintegrityjava;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveFailureReason;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerification;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 归档包离线核验：各类破坏各有可区分的结论；历史结论不随后续策略/清理变化。
 */
class ArchiveVerifyTest {

    private static final Logger log = LoggerFactory.getLogger(ArchiveVerifyTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path dir;

    private AuditTestSupport.Harness envA() {
        return AuditTestSupport.harness(dir.resolve("a"), List.of("password"),
                "envA", "key-A", Map.of());
    }

    private Path exportSample(AuditTestSupport.Harness h, int events, long from, long to) {
        for (int i = 1; i <= events; i++) {
            h.events().append("actor" + i, "ACTION" + i, "res" + i,
                    AuditTestSupport.payload("password", "secret" + i, "note", "n" + i));
        }
        ArchiveExportResult result = h.archiveService().exportRange(from, to);
        log.info("[输入] 导出区间=[{},{}] 共 {} 条, outcome={}", from, to, events, result.outcome());
        assertEquals(ArchiveExportOutcome.EXPORTED, result.outcome());
        return Path.of(result.archiveFile());
    }

    private void tamper(Path archive, Consumer<ObjectNode> mutation, String desc) throws Exception {
        ObjectNode root = (ObjectNode) MAPPER.readTree(Files.readAllBytes(archive));
        mutation.accept(root);
        MAPPER.writeValue(archive.toFile(), root);
        log.info("[输入] 破坏方式: {}", desc);
    }

    private void logVerdict(String caseName, ArchiveVerification v) {
        log.info("[判定依据] {}: valid={}, primaryReason={}, scanned={}, issues={}",
                caseName, v.valid(), v.primaryReason(), v.scannedEntries(),
                v.issues().stream().map(i -> i.reason() + (i.seq() != null ? "@seq" + i.seq() : ""))
                        .toList());
    }

    @Test
    void validArchiveVerifiesOffline() {
        var h = envA();
        Path archive = exportSample(h, 10, 3, 8);

        ArchiveVerification v = h.archiveService().verify(archive, "envA");
        logVerdict("完整包", v);
        assertTrue(v.valid());
        assertEquals(ArchiveFailureReason.OK, v.primaryReason());
        assertEquals(6, v.scannedEntries());
        assertEquals(3, v.fromSeq());
        assertEquals(8, v.toSeq());
        assertEquals("envA", v.environmentId());
    }

    @Test
    void contentTamperIsEntryHashMismatch() throws Exception {
        var h = envA();
        Path archive = exportSample(h, 5, 1, 5);
        tamper(archive, root -> ((ObjectNode) root.withArray("events").get(1))
                .put("action", "HACKED"), "改动第 2 条事件的 action 字段");

        ArchiveVerification v = h.archiveService().verify(archive, null);
        logVerdict("内容被改", v);
        assertFalse(v.valid());
        assertEquals(ArchiveFailureReason.ENTRY_HASH_MISMATCH, v.primaryReason());
    }

    @Test
    void deletedMiddleRecordIsSequenceGap() throws Exception {
        var h = envA();
        Path archive = exportSample(h, 6, 1, 6);
        tamper(archive, root -> ((ArrayNode) root.get("events")).remove(2),
                "删除包内第 3 条事件（seq=3）");

        ArchiveVerification v = h.archiveService().verify(archive, null);
        logVerdict("记录被删", v);
        assertFalse(v.valid());
        assertEquals(ArchiveFailureReason.SEQUENCE_GAP, v.primaryReason());
    }

    @Test
    void truncatedTailIsTruncated() throws Exception {
        var h = envA();
        Path archive = exportSample(h, 6, 1, 6);
        tamper(archive, root -> {
            ArrayNode events = (ArrayNode) root.get("events");
            events.remove(5);
            events.remove(4);
        }, "删掉包内最后 2 条事件（逻辑截尾）");

        ArchiveVerification v = h.archiveService().verify(archive, null);
        logVerdict("尾部被截", v);
        assertFalse(v.valid());
        assertEquals(ArchiveFailureReason.TRUNCATED, v.primaryReason());
    }

    @Test
    void physicallyTruncatedFileIsTruncated() throws Exception {
        var h = envA();
        Path archive = exportSample(h, 10, 1, 10);
        byte[] bytes = Files.readAllBytes(archive);
        byte[] cut = new byte[bytes.length * 3 / 5];
        System.arraycopy(bytes, 0, cut, 0, cut.length);
        Files.write(archive, cut);
        log.info("[输入] 破坏方式: 文件物理截断到原大小的 60%");

        ArchiveVerification v = h.archiveService().verify(archive, null);
        logVerdict("物理截断", v);
        assertFalse(v.valid());
        assertEquals(ArchiveFailureReason.TRUNCATED, v.primaryReason());
    }

    @Test
    void reorderedEventsAreOrderViolation() throws Exception {
        var h = envA();
        Path archive = exportSample(h, 5, 1, 5);
        tamper(archive, root -> {
            ArrayNode events = (ArrayNode) root.get("events");
            var second = events.get(1);
            events.set(1, events.get(2));
            events.set(2, second);
        }, "交换包内第 2、3 条事件的顺序");

        ArchiveVerification v = h.archiveService().verify(archive, null);
        logVerdict("顺序被打乱", v);
        assertFalse(v.valid());
        assertEquals(ArchiveFailureReason.ORDER_VIOLATION, v.primaryReason());
    }

    @Test
    void forgedSignatureIsSignatureMismatch() throws Exception {
        var h = envA();
        Path archive = exportSample(h, 4, 1, 4);
        tamper(archive, root -> root.put("signature", "0".repeat(64)),
                "把签名替换为伪造值（内容不动）");

        ArchiveVerification v = h.archiveService().verify(archive, null);
        logVerdict("伪造签名", v);
        assertFalse(v.valid());
        assertEquals(ArchiveFailureReason.SIGNATURE_MISMATCH, v.primaryReason());
    }

    @Test
    void metadataTamperIsManifestMismatch() throws Exception {
        var h = envA();
        Path archive = exportSample(h, 4, 1, 4);
        tamper(archive, root -> root.put("exportedAt", 1L), "改动清单元数据 exportedAt");

        ArchiveVerification v = h.archiveService().verify(archive, null);
        logVerdict("清单被改", v);
        assertFalse(v.valid());
        assertEquals(ArchiveFailureReason.MANIFEST_MISMATCH, v.primaryReason());
    }

    @Test
    void selfConsistentForgedPackageFromUnknownEnvIsUntrusted() {
        // 攻击者用自己的环境与密钥造一个完全自洽的假包
        var evil = AuditTestSupport.harness(dir.resolve("evil"), List.of("password"),
                "evilEnv", "evil-key", Map.of());
        Path forged = exportSample(evil, 3, 1, 3);

        var h = envA();
        ArchiveVerification v = h.archiveService().verify(forged, null);
        logVerdict("未知环境的自洽假包", v);
        assertFalse(v.valid());
        assertEquals(ArchiveFailureReason.UNTRUSTED_ENVIRONMENT, v.primaryReason());
    }

    @Test
    void crossEnvironmentSubstitutionIsDetected() {
        var b = AuditTestSupport.harness(dir.resolve("b"), List.of("password"),
                "envB", "key-B", Map.of());
        Path fromB = exportSample(b, 3, 1, 3);

        // envA 信任 envB 的密钥，但期望收到 envA 自己的包
        var a = AuditTestSupport.harness(dir.resolve("a"), List.of("password"),
                "envA", "key-A", Map.of("envB", "key-B"));
        ArchiveVerification v = a.archiveService().verify(fromB, "envA");
        logVerdict("跨环境顶替", v);
        assertFalse(v.valid());
        assertEquals(ArchiveFailureReason.ENVIRONMENT_MISMATCH, v.primaryReason());
    }

    @Test
    void emptyChainAndSingleEventChainHaveDistinctOutcomes() {
        var h = envA();
        ArchiveExportResult empty = h.archiveService().exportRange(1, 10);
        log.info("[判定依据] 空链导出: outcome={}", empty.outcome());
        assertEquals(ArchiveExportOutcome.EMPTY_CHAIN, empty.outcome());

        h.events().append("only", "ONE", "r", AuditTestSupport.payload());
        ArchiveExportResult single = h.archiveService().exportRange(1, 1);
        log.info("[判定依据] 单条链导出: outcome={}, count={}", single.outcome(), single.eventCount());
        assertEquals(ArchiveExportOutcome.EXPORTED, single.outcome());
        ArchiveVerification v = h.archiveService().verify(Path.of(single.archiveFile()), null);
        logVerdict("单条记录的包", v);
        assertTrue(v.valid());
        assertEquals(1, v.scannedEntries());
    }

    @Test
    void prunedRangeIsRangeUnavailable() {
        var h = envA();
        for (int i = 1; i <= 10; i++) {
            h.events().append("a" + i, "A", "r", AuditTestSupport.payload());
        }
        int removed = h.auditService().retainByBatch(1, 4);
        log.info("[输入] 保留期清理删除 {} 条后，导出已被清理的区间 [1,4]", removed);

        ArchiveExportResult result = h.archiveService().exportRange(1, 4);
        log.info("[判定依据] outcome={}, detail={}", result.outcome(), result.detail());
        assertEquals(ArchiveExportOutcome.RANGE_UNAVAILABLE, result.outcome());
    }

    @Test
    void historicalVerdictSurvivesPolicyChangeAndRetentionCleanup() {
        var h = envA();
        Path archive = exportSample(h, 10, 2, 9);
        ArchiveVerification before = h.archiveService().verify(archive, null);
        logVerdict("导出当时", before);
        assertTrue(before.valid());

        // 之后：脱敏策略调整 + 来源环境做保留期清理（把导出的区间清掉）
        h.maskingService().updatePolicy(new TreeSet<>(List.of("password", "note")), "**MASK**");
        h.auditService().retainByBatch(1, 2);
        log.info("[输入] 导出后: 脱敏策略升级 + 保留期清理（来源区间已不存在）");

        ArchiveVerification after = h.archiveService().verify(archive, null);
        logVerdict("事后复现", after);
        assertTrue(after.valid(), "历史结论必须能按包内证据复现，不受后续策略/清理影响");
        assertEquals(before.scannedEntries(), after.scannedEntries());
    }
}
