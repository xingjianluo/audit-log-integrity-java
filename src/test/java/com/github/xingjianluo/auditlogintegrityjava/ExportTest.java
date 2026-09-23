package com.github.xingjianluo.auditlogintegrityjava;

import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationFailureReason;
import com.github.xingjianluo.auditlogintegrityjava.export.ExportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.export.ExportResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 导出流程：正常、接收端失败（可重试、不破坏本地）、重复与乱序幂等、完整性失败优先拦截。
 */
class ExportTest {

    private static final Logger log = LoggerFactory.getLogger(ExportTest.class);

    @TempDir
    Path dir;

    @Test
    void exportDeliversOnceAndReExportIsDuplicateIgnored() {
        var h = AuditTestSupport.harness(dir);
        h.events().append("a", "A", "r", AuditTestSupport.payload());
        h.events().append("b", "B", "r", AuditTestSupport.payload());

        ExportResult first = h.exportService().exportAll();
        ExportResult second = h.exportService().exportAll();
        log.info("[判定依据] 首次 outcome={} delivered={}; 第二次 outcome={} duplicate={}",
                first.outcome(), first.delivered(), second.outcome(), second.duplicateIgnored());
        assertEquals(ExportOutcome.DELIVERED, first.outcome());
        assertEquals(2, first.delivered());
        assertEquals(ExportOutcome.DUPLICATE_IGNORED, second.outcome());
        assertEquals(2, second.duplicateIgnored());
        assertTrue(h.auditService().verify().valid());
    }

    @Test
    void outOfOrderDeliveryIsIdempotent() {
        var h = AuditTestSupport.harness(dir);
        for (int i = 1; i <= 3; i++) {
            h.events().appendWithId("x" + i, "u", "A", "r", AuditTestSupport.payload());
        }
        // 乱序 + 重复投递：x2, x1, x2, x3, x1
        ExportResult result = h.exportService().exportInOrder(List.of("x2", "x1", "x2", "x3", "x1"));
        log.info("[输入] 乱序+重复投递顺序=[x2,x1,x2,x3,x1]");
        log.info("[判定依据] outcome={}, attempted={}, delivered={}, duplicate={}",
                result.outcome(), result.attempted(), result.delivered(), result.duplicateIgnored());
        assertEquals(ExportOutcome.DELIVERED, result.outcome());
        assertEquals(3, result.delivered());
        assertEquals(2, result.duplicateIgnored());
    }

    @Test
    void receiverFailureIsDistinctFromIntegrityFailureAndKeepsLocalIntact() throws Exception {
        var h = AuditTestSupport.harness(dir);
        h.events().append("a", "A", "r", AuditTestSupport.payload());
        h.events().append("b", "B", "r", AuditTestSupport.payload());
        byte[] before = Files.readAllBytes(dir.resolve("events.jsonl"));

        h.receiver().setFailing(true);
        ExportResult failed = h.exportService().exportAll();
        log.info("[输入] 接收端置为故障后导出");
        log.info("[判定依据] outcome={}, failedEventIds={}, integrityIssues={}",
                failed.outcome(), failed.failedEventIds(), failed.integrityIssues());
        assertEquals(ExportOutcome.RECEIVER_FAILED, failed.outcome());
        assertEquals(List.of("evt-1", "evt-2"), failed.failedEventIds());
        assertTrue(failed.integrityIssues().isEmpty(), "接收端失败不得附带完整性问题");

        h.receiver().setFailing(false);
        ExportResult retry = h.exportService().exportAll();
        byte[] after = Files.readAllBytes(dir.resolve("events.jsonl"));
        log.info("[判定依据] 恢复后重试 outcome={} delivered={}; 本地链文件字节级不变={}; 校验={}",
                retry.outcome(), retry.delivered(), java.util.Arrays.equals(before, after),
                h.auditService().verify().valid());
        assertEquals(ExportOutcome.DELIVERED, retry.outcome());
        assertEquals(2, retry.delivered());
        assertTrue(java.util.Arrays.equals(before, after), "导出失败不得改动本地审计记录");
        assertTrue(h.auditService().verify().valid());
    }

    @Test
    void integrityFailureBlocksExportAndIsReportedAsIntegrityNotReceiver() throws Exception {
        var h = AuditTestSupport.harness(dir);
        h.events().append("a", "A", "r", AuditTestSupport.payload());
        h.events().append("b", "B", "r", AuditTestSupport.payload());

        Path file = dir.resolve("events.jsonl");
        List<String> lines = Files.readAllLines(file);
        log.info("[输入] 篡改第 1 行后导出（接收端本身健康）");
        lines.set(0, lines.get(0).replace("\"action\":\"A\"", "\"action\":\"HACKED\""));
        Files.write(file, lines);

        ExportResult result = AuditTestSupport.harness(dir).exportService().exportAll();
        log.info("[判定依据] outcome={}, issues={}, failedEventIds={}",
                result.outcome(),
                result.integrityIssues().stream().map(i -> i.reason() + "@seq" + i.seq()).toList(),
                result.failedEventIds());
        assertEquals(ExportOutcome.INTEGRITY_FAILED, result.outcome());
        assertNotEquals(ExportOutcome.RECEIVER_FAILED, result.outcome());
        assertTrue(result.integrityIssues().stream()
                .anyMatch(i -> i.reason() == VerificationFailureReason.ENTRY_HASH_MISMATCH));
        assertTrue(result.failedEventIds().isEmpty(), "完整性失败时不得产生任何投递");
    }
}
