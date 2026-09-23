package com.github.xingjianluo.auditlogintegrityjava.model;

/**
 * Outcome of an export run. Receiver failure and integrity failure are
 * deliberately distinct outcomes.
 */
public enum ExportStatus {
    /** Every pending record was accepted by the receiver (or already present). */
    DELIVERED,
    /** Nothing new to deliver. */
    NOTHING_TO_EXPORT,
    /** Local chain failed verification before any delivery was attempted. */
    INTEGRITY_CHECK_FAILED,
    /** The receiver threw, timed out or rejected; local chain is untouched. */
    RECEIVER_FAILED,
    /** Local storage failed while reading/updating export progress. */
    STORAGE_FAILED
}
