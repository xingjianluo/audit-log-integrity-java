package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 一次归档导入的结论。
 *
 * @param verification 包核验结论（完整性拒绝时携带具体判定依据）
 * @param storedAs     成功/幂等时留存的包副本文件名（imports/ 下，可作证据独立核验），否则为 null
 * @param mergedCount  本次新并入本地链的记录数（幂等忽略/失败时为 0）
 * @param detail       人类可读结论与处置建议
 */
public record ArchiveImportResult(
        ArchiveImportOutcome outcome,
        ArchiveVerification verification,
        String storedAs,
        int mergedCount,
        String detail) {
}
