package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 归档导入结论（包本身问题、本地配置/链状态问题、接收/存储问题严格区分）。
 */
public enum ArchiveImportOutcome {
    /** 整体导入成功：记录已并入本地链，可查询、参与整体校验、可继续追加 */
    IMPORTED,
    /** 该包此前导入过、记录后被保留期清理，本次已重新并入（明确区别于首次导入） */
    REIMPORTED_AFTER_PRUNE,
    /** 同一包的记录已全部在本地链中，幂等忽略（结果与首次一致，不新增记录） */
    DUPLICATE_IGNORED,
    /** 包完整性/真实性核验未通过，本地零改动（应找对方核对，而非重试） */
    INTEGRITY_REJECTED,
    /** 来源环境不在信任列表，本地零改动（需配置对应核验密钥或找对方确认来源） */
    UNTRUSTED_SOURCE,
    /** 包本身有效，但本地链当前完整性校验未通过，拒绝在破损链上合并（先处理本地链问题） */
    LOCAL_CHAIN_INVALID,
    /** 包本身有效，但本地接收/存储失败，本地零改动（可重试） */
    STORAGE_FAILED,
    /** 未预料的内部错误（与上述各类区分开；可重试，反复出现应排查环境） */
    INTERNAL_ERROR
}
