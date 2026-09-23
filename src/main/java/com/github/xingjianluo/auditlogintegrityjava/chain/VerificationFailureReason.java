package com.github.xingjianluo.auditlogintegrityjava.chain;

/**
 * 完整性校验失败原因，彼此可区分。
 */
public enum VerificationFailureReason {
    OK,
    MALFORMED_ENTRY,
    ENTRY_HASH_MISMATCH,
    LINK_MISMATCH,
    SEQUENCE_GAP,
    TRUNCATED,
    ANCHOR_MISMATCH
}
