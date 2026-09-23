package com.github.xingjianluo.auditlogintegrityjava.export;

import com.github.xingjianluo.auditlogintegrityjava.model.ExportStatus;
import com.github.xingjianluo.auditlogintegrityjava.model.FailureReason;
import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;
import com.github.xingjianluo.auditlogintegrityjava.model.VerificationResult;
import com.github.xingjianluo.auditlogintegrityjava.support.AuditTestKit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditExporterTest {

    private static final Logger log = LoggerFactory.getLogger(AuditExporterTest.class);

    private AuditTestKit seed(Path dir, int n) {
        AuditTestKit kit = AuditTestKit.create(dir, 30, 10);
        for (int i = 1; i <= n; i++) {
            kit.service.record(AuditTestKit.event("x" + i, 1_000L + i, "LOGIN"));
        }
        return kit;
    }

    @Test
    void exportDeliversAllPendingAndIsIdempotent(@TempDir Path dir) {
        AuditTestKit kit = seed(dir, 4);
        var first = kit.exporter.exportToReceiver();
        log.info("[input] 4 pending records, healthy receiver -> [decision] status={} delivered={} cursor={}",
                first.status(), first.deliveredCount(), first.lastExportedSeq());
        assertEquals(ExportStatus.DELIVERED, first.status());
        assertEquals(4, first.deliveredCount());
        assertEquals(4, kit.receiver.received().size());

        var second = kit.exporter.exportToReceiver();
        log.info("[input] repeat export with no new records -> [decision] status={} delivered={}",
                second.status(), second.deliveredCount());
        assertEquals(ExportStatus.NOTHING_TO_EXPORT, second.status());
        assertEquals(4, kit.receiver.received().size(), "receiver side stays duplicate-free");

        kit.service.record(AuditTestKit.event("x5", 2_000L, "LOGIN"));
        var third = kit.exporter.exportToReceiver();
        log.info("[input] 1 new record after prior export -> [decision] status={} delivered={} cursor={}",
                third.status(), third.deliveredCount(), third.lastExportedSeq());
        assertEquals(ExportStatus.DELIVERED, third.status());
        assertEquals(1, third.deliveredCount());
        assertEquals(5, kit.receiver.received().size());
    }

    @Test
    void receiverFailureIsDistinguishableAndDoesNotTouchLocalChain(@TempDir Path dir) {
        AuditTestKit kit = seed(dir, 3);
        // Simulate duplicate + out-of-order redelivery against the receiver:
        // manually deliver seq=3 first, then seq=3 again.
        StoredRecord r3 = kit.store.readSnapshot().records().get(2);
        try {
            kit.receiver.deliver(r3);
            kit.receiver.deliver(r3);
        } catch (ReceiverException e) {
            throw new AssertionError(e);
        }
        log.info("[input] out-of-order duplicate seq=3 pre-delivered twice -> receiverSize={}",
                kit.receiver.received().size());
        assertEquals(1, kit.receiver.received().size());

        kit.receiver.setFailing(true);
        var failed = kit.exporter.exportToReceiver();
        log.info("[input] receiver failing, 3 pending -> [decision] status={} delivered={} cursor={} verificationNull={}",
                failed.status(), failed.deliveredCount(), failed.lastExportedSeq(),
                failed.verification() == null ? "n/a" : failed.verification().valid());
        assertEquals(ExportStatus.RECEIVER_FAILED, failed.status());
        assertEquals(0, failed.deliveredCount());
        assertEquals(0, kit.store.getExportCursor(), "cursor must not advance on receiver failure");
        assertNull(failed.verification() == null ? null : failed.verification().reason(),
                "local verification was fine; only the receiver failed");

        VerificationResult local = kit.service.verify();
        log.info("[input] local chain after failed export -> [decision] valid={} count={}",
                local.valid(), local.recordCount());
        assertTrue(local.valid(), "export failure must never corrupt/modify local audit data");
        assertEquals(3, kit.service.allRecords().size());

        kit.receiver.setFailing(false);
        var retry = kit.exporter.exportToReceiver();
        log.info("[input] retry with healthy receiver -> [decision] status={} delivered={} cursor={}",
                retry.status(), retry.deliveredCount(), retry.lastExportedSeq());
        assertEquals(ExportStatus.DELIVERED, retry.status());
        assertEquals(3, retry.deliveredCount());
        assertEquals(3, kit.receiver.received().size(), "idempotent retry, still no duplicates");
    }

    @Test
    void integrityFailureBlocksExportAndIsDistinguishableFromReceiverFailure(@TempDir Path dir) throws Exception {
        AuditTestKit kit = seed(dir, 3);
        Path logFile = dir.resolve("audit.log");
        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        // Tamper seq=2 action field inside its JSON line.
        String tampered = lines.get(1).replace("\"action\":\"LOGIN\"", "\"action\":\"HACKED\"");
        lines.set(1, tampered);
        Files.write(logFile, lines, StandardCharsets.UTF_8);
        log.info("[input] action of seq=2 changed on disk (LOGIN->HACKED), receiver healthy"
                + " -> [decision] exporting...");

        var result = kit.exporter.exportToReceiver();
        log.info("[decision] status={} integrityReason={} offendingSeq={} basis={} delivered={}",
                result.status(),
                result.verification() == null ? null : result.verification().reason(),
                result.verification() == null ? null : result.verification().offendingSeq(),
                result.message(), result.deliveredCount());
        assertEquals(ExportStatus.INTEGRITY_CHECK_FAILED, result.status());
        assertNotNull(result.verification());
        assertEquals(FailureReason.CONTENT_TAMPERED, result.verification().reason());
        assertEquals(0, result.deliveredCount(), "no delivery may happen after tamper detection");
        assertEquals(0, kit.receiver.received().size());
    }

    @Test
    void tailTruncationBlocksExportWithDistinctReason(@TempDir Path dir) throws Exception {
        AuditTestKit kit = seed(dir, 4);
        Path logFile = dir.resolve("audit.log");
        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        Files.write(logFile, lines.subList(0, 2), StandardCharsets.UTF_8);
        log.info("[input] last 2 lines physically deleted, audit.tail untouched -> [decision] exporting...");

        var result = kit.exporter.exportToReceiver();
        log.info("[decision] status={} integrityReason={} basis={}",
                result.status(),
                result.verification() == null ? null : result.verification().reason(),
                result.message());
        assertEquals(ExportStatus.INTEGRITY_CHECK_FAILED, result.status());
        assertEquals(FailureReason.TRUNCATED_AT_TAIL, result.verification().reason());
        assertEquals(0, kit.receiver.received().size());
    }
}
