package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 归档导出结论。
 */
public enum ArchiveExportOutcome {
    /** 归档包已生成 */
    EXPORTED,
    /** 本地链为空，无可归档记录（明确区分于“成功导出空包”） */
    EMPTY_CHAIN,
    /** 请求区间不在本地留存范围内（已被保留期清理或尚未到达） */
    RANGE_UNAVAILABLE,
    /** 本地链完整性校验未通过，拒绝导出 */
    INTEGRITY_FAILED,
    /** 写归档文件失败（本地存储问题，可重试） */
    STORAGE_FAILED
}
