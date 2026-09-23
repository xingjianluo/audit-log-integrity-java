package com.github.xingjianluo.auditlogintegrityjava.export;

import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationIssue;

import java.util.List;

/**
 * 一次导出的结论。
 */
public record ExportResult(
        ExportOutcome outcome,
        int attempted,
        int delivered,
        int duplicateIgnored,
        List<String> failedEventIds,
        List<VerificationIssue> integrityIssues,
        String detail) {
}
