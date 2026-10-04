package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 一次归档导入的结论。
 *
 * @param verification 包核验结论（完整性拒绝时携带具体判定依据）
 * @param storedAs     成功/幂等时落盘的导入段文件名，否则为 null
 */
public record ArchiveImportResult(
        ArchiveImportOutcome outcome,
        ArchiveVerification verification,
        String storedAs,
        String detail) {
}
