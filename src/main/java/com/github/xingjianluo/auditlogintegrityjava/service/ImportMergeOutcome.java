package com.github.xingjianluo.auditlogintegrityjava.service;

/**
 * 把归档事件并入本地链的结论（彼此可区分，便于映射为对外的导入结论）。
 */
public enum ImportMergeOutcome {
    /** 并入成功：事件已按本地链规则重链追加，成为本环境自己的记录 */
    MERGED,
    /** 这批事件全部已在本地链中（同一包重复导入），幂等忽略，未新增记录 */
    DUPLICATE_IGNORED,
    /** 本环境自己导出的区间已被保留期清理，拒绝让已清理记录复活 */
    PRUNED_RANGE,
    /** 包内事件与本地已有记录冲突（同一事件 ID 内容不同），本地零改动 */
    EVENT_CONFLICT,
    /** 本地链完整性校验未通过，拒绝在破损链上并入，本地零改动 */
    CHAIN_INVALID
}
