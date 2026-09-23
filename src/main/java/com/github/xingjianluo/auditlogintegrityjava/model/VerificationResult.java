package com.github.xingjianluo.auditlogintegrityjava.model;

/**
 * Outcome of verifying the audit chain. When {@link #valid} is false,
 * {@link #reason} explains the distinguishable cause and {@link #detail}
 * records the evidence used for the decision.
 */
public record VerificationResult(
        boolean valid,
        FailureReason reason,
        Long offendingSeq,
        String expectedHash,
        String actualHash,
        int recordCount,
        String headHash,
        String detail) {

    public static VerificationResult ok(int recordCount, String headHash) {
        return new VerificationResult(true, null, null, null, null,
                recordCount, headHash,
                "chain verified: " + recordCount + " record(s), head/tail hash=" + headHash);
    }

    public static VerificationResult failure(FailureReason reason, Long offendingSeq,
                                             String expectedHash, String actualHash,
                                             String detail) {
        return new VerificationResult(false, reason, offendingSeq, expectedHash, actualHash,
                -1, null, detail);
    }
}
