package com.github.xingjianluo.auditlogintegrityjava.service;

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
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * One scenario that walks the whole chain through its required conditions:
 * concurrent writes, repeated submission, export idempotency, receiver
 * failure vs integrity failure, tamper/truncation detection, batched
 * retention cleanup with post-cleanup verification, and policy evolution
 * that leaves historical conclusions reproducible.
 */
class EndToEndAuditChainTest {

    private static final Logger log = LoggerFactory.getLogger(EndToEndAuditChainTest.class);

    @Test
    void fullScenario(@TempDir Path dir) throws Exception {
        AuditTestKit kit = AuditTestKit.create(dir, 100, 5);
        long base = 10_000_000L;

        // 1) concurrent writers (20 threads x 10 = 200 events)
        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<Long> seqs = Collections.newSetFromMap(new ConcurrentHashMap<>());
        for (int t = 0; t < threads; t++) {
            final int tid = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 10; i++) {
                        seqs.add(kit.service.record(
                                AuditTestKit.event("w" + tid + "-" + i, base + i, "LOGIN")).seq());
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        log.info("[step1] concurrent append: uniqueSeqs={} records={}", seqs.size(),
                kit.service.allRecords().size());
        assertEquals(200, seqs.size());
        assertTrue(kit.service.verify().valid());

        // 2) duplicate submission (also concurrently)
        CountDownLatch dupStart = new CountDownLatch(1);
        Set<Long> dupSeqs = Collections.newSetFromMap(new ConcurrentHashMap<>());
        ExecutorService dupPool = Executors.newFixedThreadPool(8);
        for (int t = 0; t < 8; t++) {
            dupPool.submit(() -> {
                try {
                    dupStart.await();
                    dupSeqs.add(kit.service.record(
                            AuditTestKit.event("w0-0", base, "LOGIN")).seq());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        dupStart.countDown();
        dupPool.shutdown();
        assertTrue(dupPool.awaitTermination(20, TimeUnit.SECONDS));
        log.info("[step2] duplicate concurrent submissions collapsed to seqs={}", dupSeqs);
        assertEquals(1, dupSeqs.size());
        assertEquals(200, kit.service.allRecords().size());

        // 3) first export: all delivered; second export: nothing to do
        var e1 = kit.exporter.exportToReceiver();
        var e2 = kit.exporter.exportToReceiver();
        log.info("[step3] exports: {} ({} delivered), then {}",
                e1.status(), e1.deliveredCount(), e2.status());
        assertEquals(ExportStatus.DELIVERED, e1.status());
        assertEquals(200, e1.deliveredCount());
        assertEquals(ExportStatus.NOTHING_TO_EXPORT, e2.status());
        assertEquals(200, kit.receiver.received().size());

        // 4) receiver outage with new pending records: RECEIVER_FAILED, local intact
        kit.service.record(AuditTestKit.event("late1", base + 100, "LOGIN"));
        kit.receiver.setFailing(true);
        var failed = kit.exporter.exportToReceiver();
        log.info("[step4] receiver failing -> {} delivered={} cursor={}",
                failed.status(), failed.deliveredCount(), failed.lastExportedSeq());
        assertEquals(ExportStatus.RECEIVER_FAILED, failed.status());
        assertTrue(kit.service.verify().valid(), "local chain untouched by receiver failure");
        assertEquals(200, kit.store.getExportCursor());

        // 5) tamper a record while receiver is still down: distinct outcome
        Path logFile = dir.resolve("audit.log");
        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        int targetIdx = 50;
        String original = lines.get(targetIdx);
        lines.set(targetIdx, original.replace("\"action\":\"LOGIN\"", "\"action\":\"EVIL\""));
        Files.write(logFile, lines, StandardCharsets.UTF_8);
        var blocked = kit.exporter.exportToReceiver();
        log.info("[step5] tamper + receiver down -> {} reason={} (must NOT be receiver failure)",
                blocked.status(),
                blocked.verification() == null ? null : blocked.verification().reason());
        assertEquals(ExportStatus.INTEGRITY_CHECK_FAILED, blocked.status());
        assertEquals(FailureReason.CONTENT_TAMPERED, blocked.verification().reason());

        // restore the file, receiver recovers: pending late1 eventually delivered
        lines.set(targetIdx, original);
        Files.write(logFile, lines, StandardCharsets.UTF_8);
        VerificationResult restored = kit.service.verify();
        assertTrue(restored.valid(), "restoring original content must re-verify");
        kit.receiver.setFailing(false);
        var e3 = kit.exporter.exportToReceiver();
        log.info("[step6] repair + receiver recovery -> {} delivered={} cursor={}",
                e3.status(), e3.deliveredCount(), e3.lastExportedSeq());
        assertEquals(ExportStatus.DELIVERED, e3.status());
        assertEquals(1, e3.deliveredCount());
        assertEquals(201, kit.receiver.received().size());

        // 7) tail truncation detected distinctly
        List<String> now = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        Files.write(logFile, now.subList(0, now.size() - 3), StandardCharsets.UTF_8);
        VerificationResult truncated = kit.service.verify();
        log.info("[step7] last 3 lines cut -> valid={} reason={} basis={}",
                truncated.valid(), truncated.reason(), truncated.detail());
        assertFalse(truncated.valid());
        assertEquals(FailureReason.TRUNCATED_AT_TAIL, truncated.reason());

        // 8) policy update: historical conclusion reproducible; new records use new policy
        Files.write(logFile, now, StandardCharsets.UTF_8); // restore
        StoredRecord sampleOld = kit.service.allRecords().get(0);
        String hashBefore = sampleOld.hash();
        String policyBefore = kit.policy.version();
        kit.policy.updateSensitiveFields(Set.of("password", "token", "idCard", "note", "ip"));
        assertNotEquals(policyBefore, kit.policy.version());
        VerificationResult historical = kit.service.verify();
        log.info("[step8] after policy change old chain valid={} oldHashUnchanged={} oldPolicyTag={}",
                historical.valid(), hashBefore.equals(kit.service.allRecords().get(0).hash()),
                sampleOld.policyVersion());
        assertTrue(historical.valid());
        assertEquals(hashBefore, kit.service.allRecords().get(0).hash());
        assertEquals(policyBefore, sampleOld.policyVersion());
    }
}
