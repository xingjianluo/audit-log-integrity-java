package com.github.xingjianluo.auditlogintegrityjava.model;

/**
 * Distinguishable causes of an integrity verification failure.
 */
public enum FailureReason {
    /** A record's stored hash does not match its recomputed content hash. */
    CONTENT_TAMPERED,
    /** prevHash of a record does not match the hash of the preceding record. */
    CHAIN_BROKEN,
    /** Sequence numbers are missing, duplicated or out of order. */
    SEQUENCE_GAP_OR_REORDER,
    /** The head record does not follow the retained anchor (illegal truncation). */
    TRUNCATED_AT_HEAD,
    /** Records are missing at the tail (file ends earlier than expected). */
    TRUNCATED_AT_TAIL,
    /** A stored line cannot be parsed. */
    CORRUPTED_RECORD
}
