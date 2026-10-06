package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 一次归档导入的结论。
 *
 * @param outcome     导入结论（各类失败可区分）
 * @param verification 包核验结论（完整性拒绝时携带具体判定依据）
 * @param mergedCount 本次新并入本地链的记录条数（未并入时为 0）
 * @param totalEvents 导入结束后本地链总条数（失败时为导入前条数）
 * @param detail      人类可读的判定依据
 */
public record ArchiveImportResult(
        ArchiveImportOutcome outcome,
        ArchiveVerification verification,
        int mergedCount,
        int totalEvents,
        String detail) {
}
