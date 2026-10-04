package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 归档导入结论，彼此可区分。
 */
public enum ImportOutcome {
    /** 有新记录导入 */
    IMPORTED,
    /** 幂等命中：包中记录此前已全部导入，本次零改动 */
    ALREADY_IMPORTED,
    /** 包本身完整性有问题（核验未通过），本地零改动 */
    PACKAGE_INVALID,
    /** 本地链当前不完整，拒绝在其上导入，本地零改动 */
    LOCAL_CHAIN_INVALID,
    /** 包完好但本地接收/存储出错，已回滚到导入前状态，可重试 */
    IMPORT_STORAGE_FAILED
}
