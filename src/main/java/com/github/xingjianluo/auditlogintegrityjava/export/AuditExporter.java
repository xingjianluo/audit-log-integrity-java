package com.github.xingjianluo.auditlogintegrityjava.export;

import com.github.xingjianluo.auditlogintegrityjava.model.ExportResult;
import com.github.xingjianluo.auditlogintegrityjava.model.ExportStatus;
import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;
import com.github.xingjianluo.auditlogintegrityjava.model.VerificationResult;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.service.ChainIntegrityVerifier;
import com.github.xingjianluo.auditlogintegrityjava.store.AuditLogStore;
import com.github.xingjianluo.auditlogintegrityjava.store.AuditStorageException;
import com.github.xingjianluo.auditlogintegrityjava.store.LogSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Streams not-yet-exported records (seq &gt; cursor) to a receiver.
 *
 * <p>Local chain integrity is verified before any delivery is attempted, so
 * an integrity failure is reported as {@link ExportStatus#INTEGRITY_CHECK_FAILED}
 * with zero delivery side effects. A receiver-side problem is reported as
 * {@link ExportStatus#RECEIVER_FAILED}: the cursor is not advanced past the
 * failed record and local audit data is never modified by an export, making
 * the run safely retriable and the two failure classes distinguishable.
 */
@Service
public class AuditExporter {

    private static final Logger log = LoggerFactory.getLogger(AuditExporter.class);

    private final AuditLogStore store;
    private final AuditService auditService;
    private final ChainIntegrityVerifier verifier;
    private final AuditEventReceiver receiver;

    public AuditExporter(AuditLogStore store, AuditService auditService,
                         ChainIntegrityVerifier verifier, AuditEventReceiver receiver) {
        this.store = store;
        this.auditService = auditService;
        this.verifier = verifier;
        this.receiver = receiver;
    }

    public synchronized ExportResult exportToReceiver() {
        VerificationResult verification;
        List<StoredRecord> pending;
        try {
            LogSnapshot snapshot = store.readSnapshot();
            verification = verifier.verify(snapshot.records(), store.getAnchor(),
                    snapshot.corruptLineNumbers(), snapshot.tailSeq(), snapshot.tailHash());
            long cursor = store.getExportCursor();
            pending = snapshot.records().stream().filter(r -> r.seq() > cursor).toList();
        } catch (AuditStorageException e) {
            log.error("export aborted: local storage failure: {}", e.getMessage());
            return new ExportResult(ExportStatus.STORAGE_FAILED, 0, store.getExportCursor(),
                    null, "local storage failure: " + e.getMessage());
        }

        if (!verification.valid()) {
            log.error("export blocked: INTEGRITY failure reason={} offendingSeq={} detail={}",
                    verification.reason(), verification.offendingSeq(), verification.detail());
            return new ExportResult(ExportStatus.INTEGRITY_CHECK_FAILED, 0,
                    store.getExportCursor(), verification,
                    "export blocked by integrity failure: " + verification.reason());
        }

        if (pending.isEmpty()) {
            log.info("export nothing-to-do cursor={}", store.getExportCursor());
            return new ExportResult(ExportStatus.NOTHING_TO_EXPORT, 0,
                    store.getExportCursor(), verification, "no pending records");
        }

        int delivered = 0;
        long lastDelivered = store.getExportCursor();
        for (StoredRecord r : pending) {
            try {
                receiver.deliver(r);
            } catch (ReceiverException e) {
                log.warn("export RECEIVER failure at seq={} (delivered so far={}); "
                        + "cursor stays at {} and local records are untouched: {}",
                        r.seq(), delivered, lastDelivered, e.getMessage());
                return new ExportResult(ExportStatus.RECEIVER_FAILED, delivered, lastDelivered,
                        verification, "receiver failure at seq=" + r.seq() + ": " + e.getMessage());
            }
            try {
                store.updateExportCursor(r.seq());
            } catch (AuditStorageException e) {
                log.error("export cursor persistence failed after seq={} was delivered",
                        r.seq());
                return new ExportResult(ExportStatus.STORAGE_FAILED, delivered, lastDelivered,
                        verification, "cursor persistence failed at seq=" + r.seq());
            }
            delivered++;
            lastDelivered = r.seq();
        }

        log.info("export DELIVERED count={} cursorNow={}", delivered, lastDelivered);
        return new ExportResult(ExportStatus.DELIVERED, delivered, lastDelivered,
                verification, "delivered " + delivered + " record(s)");
    }
}
