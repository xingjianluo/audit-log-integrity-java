package com.github.xingjianluo.auditlogintegrityjava.store;

import com.github.xingjianluo.auditlogintegrityjava.model.ChainAnchor;
import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;

/**
 * File-backed, append-only audit store. All mutating operations are
 * serialized; readers observe one consistent snapshot.
 */
public interface AuditLogStore {

    /** Append a record; the store validates seq/prevHash linkage. */
    void append(StoredRecord record);

    /** Read all surviving records in chain order, plus corruption/tail info. */
    LogSnapshot readSnapshot();

    /** Returns true if an event with this id has already been recorded. */
    boolean existsByEventId(String eventId);

    /** Next gap-less sequence number (anchor seq + 1 when anchored). */
    long nextSeq();

    /** Hash the new head must link to (anchor hash, else GENESIS). */
    String headHash();

    ChainAnchor getAnchor();

    /**
     * Atomically rewrite the log keeping only {@code survivors}, and advance
     * the anchor to the first surviving record. Used only by batched cleanup.
     */
    void pruneHead(java.util.List<StoredRecord> survivors, ChainAnchor newAnchor);

    long getExportCursor();
    void updateExportCursor(long seq);
}
