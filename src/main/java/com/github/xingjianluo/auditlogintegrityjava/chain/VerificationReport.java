package com.github.xingjianluo.auditlogintegrityjava.chain;

import java.util.List;

/**
 * 一次完整性校验的结论。
 */
public record VerificationReport(
        boolean valid,
        int scannedEntries,
        long headSeq,
        long tailSeq,
        List<VerificationIssue> issues) {
}
