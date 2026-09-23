package com.github.xingjianluo.auditlogintegrityjava.service;

import com.github.xingjianluo.auditlogintegrityjava.crypto.HashService;
import com.github.xingjianluo.auditlogintegrityjava.masking.FieldMaskingPolicy;
import com.github.xingjianluo.auditlogintegrityjava.masking.RetentionPolicy;
import com.github.xingjianluo.auditlogintegrityjava.model.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.model.ChainAnchor;
import com.github.xingjianluo.auditlogintegrityjava.model.CleanupResult;
import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;
import com.github.xingjianluo.auditlogintegrityjava.model.VerificationResult;
import com.github.xingjianluo.auditlogintegrityjava.store.AuditLogStore;
import com.github.xingjianluo.auditlogintegrityjava.store.LogSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Application service for the tamper-evident audit chain.
 *
 * <p>Appends are idempotent on {@code eventId}, mask sensitive fields under
 * the current versioned policy before persistence, and extend the SHA-256
 * hash chain. Retention cleanup runs strictly in bounded batches, each batch
 * being an atomic rewrite plus an anchor advance; after every batch the
 * remaining chain is re-verified.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditLogStore store;
    private final HashService hashService;
    private final FieldMaskingPolicy maskingPolicy;
    private final RetentionPolicy retentionPolicy;
    private final ChainIntegrityVerifier verifier;

    public AuditService(AuditLogStore store, HashService hashService,
                        FieldMaskingPolicy maskingPolicy, RetentionPolicy retentionPolicy,
                        ChainIntegrityVerifier verifier) {
        this.store = store;
        this.hashService = hashService;
        this.maskingPolicy = maskingPolicy;
        this.retentionPolicy = retentionPolicy;
        this.verifier = verifier;
    }

    /**
     * Record an event. A repeated eventId returns the already-stored record
     * and does not append a duplicate or disturb chain continuity.
     */
    public synchronized StoredRecord record(AuditEvent event) {
        if (store.existsByEventId(event.eventId())) {
            StoredRecord existing = findByEventId(event.eventId());
            log.info("duplicate event ignored eventId={} existingSeq={}", event.eventId(),
                    existing == null ? null : existing.seq());
            return existing;
        }

        long seq = store.nextSeq();
        String prevHash = store.headHash();
        String policyVersion = maskingPolicy.version();
        StoredRecord candidate = new StoredRecord(
                seq,
                event.eventId(),
                event.timestamp(),
                event.actor(),
                event.action(),
                event.resource(),
                maskingPolicy.apply(event.detail()),
                policyVersion,
                prevHash,
                null);
        String hash = verifier.contentHash(candidate);
        StoredRecord toStore = new StoredRecord(seq, candidate.eventId(), candidate.timestamp(),
                candidate.actor(), candidate.action(), candidate.resource(), candidate.detail(),
                policyVersion, prevHash, hash);
        store.append(toStore);
        log.info("appended audit record seq={} eventId={} action={} policy={} prevHash={} hash={}",
                seq, event.eventId(), event.action(), policyVersion, prevHash, hash);
        return toStore;
    }

    private StoredRecord findByEventId(String eventId) {
        for (StoredRecord r : store.readSnapshot().records()) {
            if (r.eventId().equals(eventId)) {
                return r;
            }
        }
        return null;
    }

    public VerificationResult verify() {
        LogSnapshot snapshot = store.readSnapshot();
        return verifier.verify(snapshot.records(), store.getAnchor(),
                snapshot.corruptLineNumbers(), snapshot.tailSeq(), snapshot.tailHash());
    }

    public List<StoredRecord> allRecords() {
        return store.readSnapshot().records();
    }

    /**
     * Prune expired records in batches of at most {@link RetentionPolicy#batchSize()}.
     * Each batch removes a contiguous head prefix of expired records; a batch
     * boundary that would land in the middle of the log (survivors remain)
     * advances the anchor, while a batch removing the final surviving records
     * resets the chain to GENESIS. The surviving chain is verified after each
     * batch and the run aborts on the first integrity failure.
     */
    public synchronized CleanupResult cleanupExpired(long nowMillis) {
        long cutoff = nowMillis - retentionPolicy.maxAgeMillis();
        int batchSize = retentionPolicy.batchSize();
        int batches = 0;
        int removed = 0;

        while (true) {
            List<StoredRecord> all = store.readSnapshot().records();
            // Only a contiguous expired head prefix is removable, and every
            // batch prunes at most batchSize records (never a bigger "last batch").
            int expiredPrefix = 0;
            while (expiredPrefix < all.size()
                    && all.get(expiredPrefix).timestamp() < cutoff) {
                expiredPrefix++;
            }
            int removable = Math.min(expiredPrefix, batchSize);
            if (removable == 0) {
                break;
            }
            List<StoredRecord> survivors = List.copyOf(all.subList(removable, all.size()));
            StoredRecord lastRemoved = all.get(removable - 1);
            ChainAnchor newAnchor;
            if (survivors.isEmpty()) {
                newAnchor = null;
            } else {
                newAnchor = new ChainAnchor(lastRemoved.seq(), lastRemoved.hash(), nowMillis);
            }
            store.pruneHead(survivors, newAnchor);
            batches++;
            removed += removable;
            log.info("cleanup batch #{} removed {} record(s) up to seq={} survivors={}",
                    batches, removable, lastRemoved.seq(), survivors.size());

            VerificationResult after = verify();
            if (!after.valid()) {
                log.error("post-cleanup verification FAILED after batch #{}: reason={} detail={}",
                        batches, after.reason(), after.detail());
                return new CleanupResult(batches, removed,
                        store.getAnchor() == null ? 0 : store.getAnchor().seq(),
                        store.getAnchor() == null ? ChainIntegrityVerifier.GENESIS
                                : store.getAnchor().hash(),
                        after);
            }
            if (survivors.isEmpty()) {
                break;
            }
        }

        VerificationResult finalCheck = verify();
        ChainAnchor anchor = store.getAnchor();
        return new CleanupResult(batches, removed,
                anchor == null ? 0 : anchor.seq(),
                anchor == null ? ChainIntegrityVerifier.GENESIS : anchor.hash(),
                finalCheck);
    }
}
