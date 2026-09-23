package com.github.xingjianluo.auditlogintegrityjava.store;

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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tamper scenarios performed directly on the on-disk files, including after
 * a simulated process restart (a fresh store instance over the same dir).
 */
class FileAuditLogStoreTest {

    private static final Logger log = LoggerFactory.getLogger(FileAuditLogStoreTest.class);

    private AuditTestKit seed(Path dir, int n) {
        AuditTestKit kit = AuditTestKit.create(dir, 30, 10);
        for (int i = 1; i <= n; i++) {
            kit.service.record(AuditTestKit.event("d" + i, 1_000L + i, "LOGIN"));
        }
        return kit;
    }

    private void assertReason(AuditTestKit kit, FailureReason expected, String scenario) {
        VerificationResult r = kit.service.verify();
        log.info("[input] {} -> [decision] valid={} reason={} offendingSeq={} basis={}",
                scenario, r.valid(), r.reason(), r.offendingSeq(), r.detail());
        assertFalse(r.valid());
        assertEquals(expected, r.reason());
    }

    @Test
    void intactChainSurvivesRestart(@TempDir Path dir) {
        AuditTestKit kit = seed(dir, 3);
        AuditTestKit reopened = kit.reopen();
        VerificationResult r = reopened.service.verify();
        log.info("[input] reopen store over intact 3-record log -> [decision] valid={} basis={}",
                r.valid(), r.detail());
        assertTrue(r.valid());
        assertEquals(3, reopened.service.allRecords().size());
        assertEquals(4L, reopened.store.nextSeq(), "seq continuity survives restart");
    }

    @Test
    void headTruncationDetectedOnRestart(@TempDir Path dir) throws Exception {
        AuditTestKit kit = seed(dir, 4);
        Path logFile = dir.resolve("audit.log");
        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        // Delete the first two lines (simulate removing head records).
        Files.write(logFile, lines.subList(2, 4), StandardCharsets.UTF_8);
        AuditTestKit reopened = kit.reopen();
        assertReason(reopened, FailureReason.TRUNCATED_AT_HEAD,
                "first 2 lines deleted from log, no GENESIS anchor present (first seq=3 != 1)");
    }

    @Test
    void corruptedLineReportedAfterRestart(@TempDir Path dir) throws Exception {
        AuditTestKit kit = seed(dir, 3);
        Path logFile = dir.resolve("audit.log");
        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        lines.set(1, "{this is not valid json");
        Files.write(logFile, lines, StandardCharsets.UTF_8);
        AuditTestKit reopened = kit.reopen();
        LogSnapshot snapshot = reopened.store.readSnapshot();
        log.info("[input] line 2 replaced with garbage -> corruptLineNumbers={}",
                snapshot.corruptLineNumbers());
        assertEquals(List.of(2), snapshot.corruptLineNumbers());
        VerificationResult r = reopened.service.verify();
        log.info("[decision] valid={} reason={} basis={}", r.valid(), r.reason(), r.detail());
        assertFalse(r.valid());
        assertEquals(FailureReason.CORRUPTED_RECORD, r.reason());
    }

    @Test
    void externalContentEditDetectedWithoutRestart(@TempDir Path dir) throws Exception {
        AuditTestKit kit = seed(dir, 3);
        Path logFile = dir.resolve("audit.log");
        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        Files.writeString(logFile, lines.get(0).replace("alice", "eve")
                + System.lineSeparator() + lines.get(1) + System.lineSeparator()
                + lines.get(2) + System.lineSeparator(), StandardCharsets.UTF_8);
        assertReason(kit, FailureReason.CONTENT_TAMPERED,
                "actor of seq=1 edited on disk while process is running");
    }

    @Test
    void tailFileForgeryDetected(@TempDir Path dir) throws Exception {
        AuditTestKit kit = seed(dir, 3);
        // Advance tail pointer beyond the real last record (claim extra records).
        Files.writeString(dir.resolve("audit.tail"),
                "seq=99\nhash=" + "0".repeat(64) + "\n", StandardCharsets.UTF_8);
        AuditTestKit reopened = kit.reopen();
        assertReason(reopened, FailureReason.TRUNCATED_AT_TAIL,
                "audit.tail claims seq=99 but the log ends at seq=3");
    }

    @Test
    void anchorAfterCleanupMakesHeadTrimLegitimate(@TempDir Path dir) {
        AuditTestKit kit = AuditTestKit.create(dir, 10, 2);
        long now = 5_000_000L;
        for (int i = 1; i <= 6; i++) {
            kit.service.record(AuditTestKit.event("a" + i,
                    i <= 4 ? now - 20L * 86_400_000L : now - 1, "LOGIN"));
        }
        var cleanup = kit.service.cleanupExpired(now);
        assertTrue(cleanup.verificationAfter().valid());
        // Reopen: the legitimate anchor must make the trimmed head acceptable.
        AuditTestKit reopened = kit.reopen();
        VerificationResult r = reopened.service.verify();
        List<StoredRecord> survivors = reopened.service.allRecords();
        log.info("[input] restart after batched cleanup (4 removed, 2 survive) anchorSeq={}"
                + " -> [decision] valid={} firstSeq={} basis={}",
                reopened.store.getAnchor().seq(), r.valid(),
                survivors.get(0).seq(), r.detail());
        assertTrue(r.valid());
        assertEquals(5L, survivors.get(0).seq());
        assertEquals(5L, reopened.store.getAnchor().seq() + 1);
    }
}
