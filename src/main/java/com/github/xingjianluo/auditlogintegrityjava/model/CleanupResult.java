package com.github.xingjianluo.auditlogintegrityjava.model;

/**
 * Summary of one retention cleanup run, always executed in batches.
 */
public record CleanupResult(
        int batches,
        int removedRecords,
        long anchorSeq,
        String anchorHash,
        VerificationResult verificationAfter) {
}
