package com.github.xingjianluo.auditlogintegrityjava.model;

/**
 * Summary of one export run.
 */
public record ExportResult(
        ExportStatus status,
        int deliveredCount,
        long lastExportedSeq,
        VerificationResult verification,
        String message) {
}
