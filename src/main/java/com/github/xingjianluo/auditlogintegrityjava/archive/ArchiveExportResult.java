package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationIssue;

import java.util.List;

/**
 * 一次归档导出的结论。packageBytes 仅在 EXPORTED 时非空。
 */
public record ArchiveExportResult(
        ArchiveExportOutcome outcome,
        byte[] packageBytes,
        String archiveId,
        long fromSeq,
        long toSeq,
        int eventCount,
        List<VerificationIssue> integrityIssues,
        String detail) {
}
