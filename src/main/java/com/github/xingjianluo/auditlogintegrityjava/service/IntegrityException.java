package com.github.xingjianluo.auditlogintegrityjava.service;

import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;

/**
 * 写入/清理/导出前置的完整性校验未通过。
 */
public class IntegrityException extends RuntimeException {

    private final transient VerificationReport report;

    public IntegrityException(String message, VerificationReport report) {
        super(message);
        this.report = report;
    }

    public VerificationReport getReport() {
        return report;
    }
}
