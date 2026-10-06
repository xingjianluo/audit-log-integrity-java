package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 归档导入结论（包本身问题、本地状态冲突、接收/存储问题、配置与内部错误严格区分）。
 */
public enum ArchiveImportOutcome {
    /** 并入成功：包内记录已成为本环境自己的记录，可查询、可整体校验、可继续追加 */
    IMPORTED,
    /** 同一批记录已并入过，幂等忽略（结果与首次一致，不新增记录） */
    DUPLICATE_IGNORED,
    /** 包完整性/真实性核验未通过，本地零改动（应找对方核对，而非重试） */
    INTEGRITY_REJECTED,
    /** 来源环境不在信任列表（或未配置对应核验密钥），本地零改动 */
    UNTRUSTED_SOURCE,
    /** 本环境自己导出的区间已被保留期清理，拒绝让已清理记录复活，本地零改动 */
    PRUNED_RANGE,
    /** 包内事件与本地已有记录冲突（同一事件 ID 内容不同），本地零改动，应找对方核对 */
    EVENT_CONFLICT,
    /** 本地链完整性校验未通过，拒绝在破损链上并入，本地零改动（先修复本地） */
    LOCAL_CHAIN_INVALID,
    /** 包本身有效，但本地接收/存储失败，本地零改动（可重试） */
    STORAGE_FAILED,
    /** 未预料的内部错误（携带异常详情，需排查；不要简单当作包问题或重试） */
    INTERNAL_ERROR
}
