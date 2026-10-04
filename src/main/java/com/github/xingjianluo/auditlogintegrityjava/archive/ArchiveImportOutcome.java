package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 归档导入结论（包本身问题与接收/存储问题严格区分）。
 */
public enum ArchiveImportOutcome {
    /** 整体导入成功 */
    IMPORTED,
    /** 同一包已导入过，幂等忽略（结果与首次一致，不新增记录） */
    DUPLICATE_IGNORED,
    /** 包完整性/真实性核验未通过，本地零改动（应找对方核对，而非重试） */
    INTEGRITY_REJECTED,
    /** 来源环境不在信任列表，本地零改动 */
    UNTRUSTED_SOURCE,
    /** 包本身有效，但本地接收/存储失败，本地零改动（可重试） */
    STORAGE_FAILED
}
