package com.github.xingjianluo.auditlogintegrityjava.service;

import com.github.xingjianluo.auditlogintegrityjava.model.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.model.CleanupResult;
import com.github.xingjianluo.auditlogintegrityjava.model.FailureReason;
import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;
import com.github.xingjianluo.auditlogintegrityjava.model.VerificationResult;
import com.github.xingjianluo.auditlogintegrityjava.support.AuditTestKit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AuditServiceTest.class);

    private void logVerify(String scenario, VerificationResult r) {
        log.info("[scenario] {} -> [decision] valid={} reason={} count={} basis={}",
                scenario, r.valid(), r.reason(), r.recordCount(), r.detail());
    }

    @Test
    void appendAndVerifyIntactChain(@TempDir Path dir) {
        AuditTestKit kit = AuditTestKit.create(dir, 30, 2);
        for (int i = 1; i <= 5; i++) {
            kit.service.record(AuditTestKit.event("e" + i, 1_000L + i, "LOGIN"));
        }
        VerificationResult r = kit.service.verify();
        logVerify("append 5 events sequentially", r);
        assertTrue(r.valid());
        assertEquals(5, r.recordCount());
        assertEquals(1L, kit.service.allRecords().get(0).seq());
        assertEquals(5L, kit.service.allRecords().get(4).seq());
    }

    @Test
    void duplicateSubmissionIsIdempotent(@TempDir Path dir) {
        AuditTestKit kit = AuditTestKit.create(dir, 30, 2);
        AuditEvent event = AuditTestKit.event("dup-1", 1_000L, "LOGIN");
        StoredRecord first = kit.service.record(event);
        StoredRecord again = kit.service.record(event);
        StoredRecord third = kit.service.record(AuditTestKit.event("dup-1", 9_999L, "OTHER"));
        log.info("[input] same eventId 'dup-1' submitted 3 times (3rd with different content)"
                + " -> [decision] seqs=({},{}) chainSize={}",
                first.seq(), again.seq(), kit.service.allRecords().size());
        assertEquals(first.seq(), again.seq());
        assertEquals(first.hash(), again.hash());
        assertEquals(first.seq(), third.seq(), "duplicate id must return original record");
        assertEquals(1, kit.service.allRecords().size(), "no duplicate record may be appended");
        VerificationResult r = kit.service.verify();
        logVerify("chain after repeated submissions", r);
        assertTrue(r.valid());
    }

    @Test
    void sensitiveFieldsAreMaskedIrreversibly(@TempDir Path dir) {
        AuditTestKit kit = AuditTestKit.create(dir, 30, 2);
        kit.service.record(AuditTestKit.event("m1", 1_000L, "GRANT"));
        StoredRecord stored = kit.service.allRecords().get(0);
        log.info("[input] plaintext password='p@ssw0rd-m1' token='bearer-m1' note='ordinary-note-m1'"
                + " -> [stored] password={} token={} note={} policyVersion={}",
                stored.detail().get("password"), stored.detail().get("token"),
                stored.detail().get("note"), stored.policyVersion());
        assertTrue(stored.detail().get("password").startsWith("mask:v1:"));
        assertTrue(stored.detail().get("token").startsWith("mask:v1:"));
        assertEquals("ordinary-note-m1", stored.detail().get("note"),
                "non-sensitive field must stay in clear text");
        assertFalse(stored.detail().containsValue("p@ssw0rd-m1"),
                "plaintext password must never be persisted");
        assertFalse(stored.detail().containsValue("bearer-m1"),
                "plaintext token must never be persisted");
    }

    @Test
    void concurrentWritersProduceOneGaplessChain(@TempDir Path dir) throws Exception {
        AuditTestKit kit = AuditTestKit.create(dir, 30, 50);
        int threads = 16;
        int perThread = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<Long> seqs = Collections.newSetFromMap(new ConcurrentHashMap<>());
        List<Exception> errors = Collections.synchronizedList(new ArrayList<>());
        for (int t = 0; t < threads; t++) {
            final int tid = t;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        StoredRecord r = kit.service.record(
                                AuditTestKit.event("c-" + tid + "-" + i, 1_000L + i, "LOGIN"));
                        seqs.add(r.seq());
                    }
                } catch (Exception e) {
                    errors.add(e);
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        log.info("[input] {} threads x {} events = {} concurrent submissions"
                + " -> [decision] uniqueSeqs={} chainSize={} errors={}",
                threads, perThread, threads * perThread, seqs.size(),
                kit.service.allRecords().size(), errors.size());
        assertEquals(0, errors.size(), "no writer may see a storage failure");
        assertEquals(threads * perThread, seqs.size(), "every append gets a unique seq");
        assertEquals(threads * perThread, kit.service.allRecords().size());
        VerificationResult r = kit.service.verify();
        logVerify("chain under concurrent writes", r);
        assertTrue(r.valid(), "concurrent appends must leave a valid chain: " + r.detail());
    }

    @Test
    void duplicateUnderConcurrencyAppendsExactlyOnce(@TempDir Path dir) throws Exception {
        AuditTestKit kit = AuditTestKit.create(dir, 30, 10);
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        Set<Long> seqs = Collections.newSetFromMap(new ConcurrentHashMap<>());
        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                try {
                    start.await();
                    seqs.add(kit.service.record(AuditTestKit.plain("same-id", 1_000L)).seq());
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
        log.info("[input] {} threads submit the SAME eventId concurrently -> [decision] distinctSeqs={} chainSize={}",
                threads, seqs.size(), kit.service.allRecords().size());
        assertEquals(1, seqs.size());
        assertEquals(1, kit.service.allRecords().size());
        assertTrue(kit.service.verify().valid());
    }

    @Test
    void cleanupRunsInBatchesAndChainStaysVerifiable(@TempDir Path dir) {
        AuditTestKit kit = AuditTestKit.create(dir, 10, 2); // batchSize=2
        long now = 1_000_000L;
        // 5 old, 2 young
        for (int i = 1; i <= 5; i++) {
            kit.service.record(AuditTestKit.event("old" + i, now - 20L * 86_400_000L, "LOGIN"));
        }
        for (int i = 1; i <= 2; i++) {
            kit.service.record(AuditTestKit.event("new" + i, now - 1L, "LOGIN"));
        }
        CleanupResult result = kit.service.cleanupExpired(now);
        log.info("[input] 7 records (5 expired), batchSize=2 -> [decision] batches={} removed={} anchorSeq={} postVerify={} basis={}",
                result.batches(), result.removedRecords(), result.anchorSeq(),
                result.verificationAfter().valid(), result.verificationAfter().detail());
        assertEquals(3, result.batches(), "5 expired records / 2 per batch => 3 batches");
        assertEquals(5, result.removedRecords());
        assertEquals(2, kit.service.allRecords().size());
        assertEquals(5L, result.anchorSeq(), "anchor must sit on the last removed record");
        assertTrue(result.verificationAfter().valid());
        assertTrue(kit.service.allRecords().stream().noneMatch(r -> r.eventId().startsWith("old")));
    }

    @Test
    void cleaningEverythingResetsToGenesisAndStillVerifies(@TempDir Path dir) {
        AuditTestKit kit = AuditTestKit.create(dir, 10, 2);
        long now = 2_000_000L;
        for (int i = 1; i <= 3; i++) {
            kit.service.record(AuditTestKit.event("g" + i, now - 30L * 86_400_000L, "LOGIN"));
        }
        CleanupResult result = kit.service.cleanupExpired(now);
        log.info("[input] 3 expired records, batchSize=2 -> [decision] batches={} removed={} survivors={} anchorSeq={}",
                result.batches(), result.removedRecords(), kit.service.allRecords().size(),
                result.anchorSeq());
        assertEquals(2, result.batches());
        assertEquals(0, kit.service.allRecords().size());
        assertEquals(0, result.anchorSeq());
        assertTrue(result.verificationAfter().valid());

        // Chain must accept new records after a full reset.
        kit.service.record(AuditTestKit.event("after-1", now, "LOGIN"));
        VerificationResult r = kit.service.verify();
        logVerify("append after full cleanup reset", r);
        assertTrue(r.valid());
        assertEquals(1L, kit.service.allRecords().get(0).seq());
    }

    @Test
    void policyUpdateKeepsHistoricalVerificationReproducible(@TempDir Path dir) {
        AuditTestKit kit = AuditTestKit.create(dir, 30, 10);
        kit.service.record(AuditTestKit.event("h1", 1_000L, "LOGIN"));
        StoredRecord historical = kit.service.allRecords().get(0);
        String oldPolicy = historical.policyVersion();

        String recomputedBefore = kit.verifier.contentHash(historical);
        // change the sensitive-field set => new policy version
        kit.policy.updateSensitiveFields(new HashSet<>(Set.of("password", "token", "idCard", "note")));
        String newPolicy = kit.policy.version();
        log.info("[input] policy updated: oldVersion={} newVersion={} -> [decision] storedPolicy={} unchangedHash={}",
                oldPolicy, newPolicy, historical.policyVersion(), historical.hash());
        assertNotEquals(oldPolicy, newPolicy);

        VerificationResult oldChain = kit.service.verify();
        logVerify("historical chain after policy change", oldChain);
        assertTrue(oldChain.valid(), "old conclusions must remain reproducible");
        assertEquals(recomputedBefore, historical.hash());

        kit.service.record(AuditTestKit.event("h2", 2_000L, "LOGIN"));
        StoredRecord fresh = kit.service.allRecords().get(1);
        assertEquals(newPolicy, fresh.policyVersion(), "new records use the new policy");
        assertTrue(fresh.detail().get("note").startsWith("mask:"),
                "newly sensitive field is masked under the new policy");
        VerificationResult mixed = kit.service.verify();
        logVerify("mixed chain spanning policy versions", mixed);
        assertTrue(mixed.valid());
    }
}
