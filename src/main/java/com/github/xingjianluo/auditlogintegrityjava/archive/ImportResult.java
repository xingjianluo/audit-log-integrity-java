package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 一次归档导入的结论。
 */
public record ImportResult(
        ImportOutcome outcome,
        String archiveId,
        int importedCount,
        int skippedCount,
        ArchiveVerification verification,
        String detail) {
}
