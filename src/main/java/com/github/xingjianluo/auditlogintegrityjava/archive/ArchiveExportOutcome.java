package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 归档导出结论，彼此可区分。
 */
public enum ArchiveExportOutcome {
    EXPORTED,
    /** 链为空，无可导出记录（不产出包） */
    EMPTY_CHAIN,
    /** 请求区间（部分）已被保留期清理，无法导出 */
    RANGE_PRUNED,
    /** 请求区间超出链尾或区间非法 */
    RANGE_NOT_FOUND,
    /** 本地链完整性校验未通过，拒绝导出 */
    INTEGRITY_FAILED
}
