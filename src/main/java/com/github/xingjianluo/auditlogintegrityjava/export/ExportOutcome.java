package com.github.xingjianluo.auditlogintegrityjava.export;

/**
 * 导出结果，与完整性失败严格区分。
 */
public enum ExportOutcome {
    DELIVERED,
    RECEIVER_FAILED,
    DUPLICATE_IGNORED,
    INTEGRITY_FAILED
}
