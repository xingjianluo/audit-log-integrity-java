package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 一次归档导出的结论。
 *
 * @param archiveFile 成功时归档包路径，否则为 null
 */
public record ArchiveExportResult(
        ArchiveExportOutcome outcome,
        long fromSeq,
        long toSeq,
        long eventCount,
        String archiveFile,
        String detail) {
}
