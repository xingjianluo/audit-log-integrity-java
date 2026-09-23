package com.github.xingjianluo.auditlogintegrityjava.service;

import com.github.xingjianluo.auditlogintegrityjava.crypto.HashService;
import com.github.xingjianluo.auditlogintegrityjava.crypto.Sha256HashService;
import com.github.xingjianluo.auditlogintegrityjava.model.FailureReason;
import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;
import com.github.xingjianluo.auditlogintegrityjava.model.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for hash-chain verification. Each test logs the constructed
 * input chain and the reason/evidence the decision is based on.
 */
class ChainIntegrityVerifierTest {

    private static final Logger log = LoggerFactory.getLogger(ChainIntegrityVerifierTest.class);

    private HashService hashes;
    private ChainIntegrityVerifier verifier;

    @BeforeEach
    void setUp() {
        hashes = new Sha256HashService();
        verifier = new ChainIntegrityVerifier(hashes);
    }

    private StoredRecord record(long seq, String eventId, String action, String prevHash) {
        StoredRecord r = new StoredRecord(seq, eventId, 1000L + seq, "alice", action,
                "/res/" + seq, Map.of("k", "v" + seq), "policy-v1", prevHash, null);
        return new StoredRecord(r.seq(), r.eventId(), r.timestamp(), r.actor(), r.action(),
                r.resource(), r.detail(), r.policyVersion(), r.prevHash(), verifier.contentHash(r));
    }

    private List<StoredRecord> chain(int n) {
        List<StoredRecord> list = new ArrayList<>();
        String prev = ChainIntegrityVerifier.GENESIS;
        for (long i = 1; i <= n; i++) {
            StoredRecord r = record(i, "evt-" + i, "LOGIN", prev);
            list.add(r);
            prev = r.hash();
        }
        return list;
    }

    private VerificationResult verify(List<StoredRecord> records) {
        StoredRecord last = records.get(records.size() - 1);
        return verifier.verify(records, null, List.of(), last.seq(), last.hash());
    }

    private void assertFailure(VerificationResult result, FailureReason expected,
                               String inputDescription) {
        log.info("[input] {} -> [decision] valid={} reason={} offendingSeq={} expected={} actual={} basis={}",
                inputDescription, result.valid(), result.reason(), result.offendingSeq(),
                result.expectedHash(), result.actualHash(), result.detail());
        assertFalse(result.valid(), "must be invalid: " + inputDescription);
        assertEquals(expected, result.reason(),
                "failure reason must be distinguishable for: " + inputDescription);
    }

    @Test
    @DisplayName("valid chain verifies")
    void validChain() {
        List<StoredRecord> records = chain(4);
        VerificationResult result = verify(records);
        log.info("[input] intact chain of 4 -> [decision] valid={} basis={}",
                result.valid(), result.detail());
        assertTrue(result.valid());
        assertEquals(4, result.recordCount());
    }

    @Test
    @DisplayName("modified field of a stored record -> CONTENT_TAMPERED")
    void contentTampered() {
        List<StoredRecord> records = chain(3);
        StoredRecord tampered = new StoredRecord(2, "evt-2", records.get(1).timestamp(),
                "attacker", "GRANT", records.get(1).resource(), records.get(1).detail(),
                records.get(1).policyVersion(), records.get(1).prevHash(), records.get(1).hash());
        records.set(1, tampered);
        assertFailure(verify(records), FailureReason.CONTENT_TAMPERED,
                "seq=2 actor/action modified, stored hash left unchanged");
        assertEquals(2L, result2(records).offendingSeq());
    }

    @Test
    @DisplayName("record replaced with internally-consistent forgery -> CHAIN_BROKEN")
    void chainBroken() {
        List<StoredRecord> records = chain(4);
        StoredRecord forged = new StoredRecord(2, "evt-2", records.get(1).timestamp(),
                "mallory", "DELETE", "/x", Map.of("k", "forged"), "policy-v1",
                records.get(1).prevHash(), null);
        forged = new StoredRecord(forged.seq(), forged.eventId(), forged.timestamp(),
                forged.actor(), forged.action(), forged.resource(), forged.detail(),
                forged.policyVersion(), forged.prevHash(), verifier.contentHash(forged));
        records.set(1, forged);
        assertFailure(verify(records), FailureReason.CHAIN_BROKEN,
                "seq=2 replaced by recomputed forgery; seq=3 still links to old hash");
        assertEquals(3L, result2(records).offendingSeq());
    }

    @Test
    @DisplayName("middle record deleted -> SEQUENCE_GAP_OR_REORDER")
    void middleDeleted() {
        List<StoredRecord> records = chain(4);
        records.remove(1);
        assertFailure(verify(records), FailureReason.SEQUENCE_GAP_OR_REORDER,
                "seq=2 line removed from middle of the chain");
    }

    @Test
    @DisplayName("two records swapped -> SEQUENCE_GAP_OR_REORDER")
    void reordered() {
        List<StoredRecord> records = chain(4);
        StoredRecord a = records.get(1);
        records.set(1, records.get(2));
        records.set(2, a);
        assertFailure(verify(records), FailureReason.SEQUENCE_GAP_OR_REORDER,
                "lines for seq=2 and seq=3 swapped");
    }

    @Test
    @DisplayName("tail records cut off -> TRUNCATED_AT_TAIL")
    void tailTruncated() {
        List<StoredRecord> records = chain(5);
        List<StoredRecord> cut = new ArrayList<>(records.subList(0, 3));
        StoredRecord originalTail = records.get(4);
        VerificationResult result = verifier.verify(cut, null, List.of(),
                originalTail.seq(), originalTail.hash());
        log.info("[input] 5-record chain tail pointer with only first 3 lines present"
                + " -> [decision] valid={} reason={} basis={}",
                result.valid(), result.reason(), result.detail());
        assertFalse(result.valid());
        assertEquals(FailureReason.TRUNCATED_AT_TAIL, result.reason());
    }

    @Test
    @DisplayName("head cut after anchor without anchor update -> TRUNCATED_AT_HEAD")
    void headTruncated() {
        List<StoredRecord> all = chain(4);
        List<StoredRecord> survivors = new ArrayList<>(all.subList(2, 4));
        com.github.xingjianluo.auditlogintegrityjava.model.ChainAnchor anchor =
                new com.github.xingjianluo.auditlogintegrityjava.model.ChainAnchor(
                        1, all.get(0).hash(), 1000L);
        StoredRecord last = survivors.get(survivors.size() - 1);
        VerificationResult result = verifier.verify(survivors, anchor, List.of(),
                last.seq(), last.hash());
        log.info("[input] anchor at seq=1 but first surviving line is seq=3"
                + " -> [decision] valid={} reason={} basis={}",
                result.valid(), result.reason(), result.detail());
        assertFalse(result.valid());
        assertEquals(FailureReason.TRUNCATED_AT_HEAD, result.reason());
    }

    @Test
    @DisplayName("garbage line -> CORRUPTED_RECORD")
    void corruptedLine() {
        List<StoredRecord> records = chain(2);
        StoredRecord last = records.get(records.size() - 1);
        VerificationResult result = verifier.verify(records, null, List.of(7),
                last.seq(), last.hash());
        log.info("[input] unparseable line 7 reported by store -> [decision] valid={} reason={} basis={}",
                result.valid(), result.reason(), result.detail());
        assertFalse(result.valid());
        assertEquals(FailureReason.CORRUPTED_RECORD, result.reason());
    }

    private VerificationResult result2(List<StoredRecord> records) {
        StoredRecord last = records.get(records.size() - 1);
        return verifier.verify(records, null, List.of(), last.seq(), last.hash());
    }
}
