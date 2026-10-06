package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 归档包离线核验的失败原因，彼此可区分（不混为一句“无效”）。
 */
public enum ArchiveFailureReason {
    /** 核验通过 */
    OK,
    /** 包文件不存在或不可读（路径错误或包未送达） */
    PACKAGE_NOT_FOUND,
    /** 包文件无法解析（非截断导致的结构损坏） */
    MALFORMED_PACKAGE,
    /** 包被截断：物理上提前结束，或事件数/尾部序号少于清单声明 */
    TRUNCATED,
    /** 不认识的格式或版本 */
    UNSUPPORTED_FORMAT,
    /** 没有该来源环境的核验密钥，无法确认来源 */
    UNTRUSTED_ENVIRONMENT,
    /** 包声明的环境与期望环境不符（跨环境顶替） */
    ENVIRONMENT_MISMATCH,
    /** 空包：没有任何事件，不能据此证明任何东西 */
    EMPTY_ARCHIVE,
    /** 某条事件内容被改动（复算哈希与存储哈希不一致） */
    ENTRY_HASH_MISMATCH,
    /** 中间记录被删除（序号出现向前的空洞） */
    SEQUENCE_GAP,
    /** 顺序被打乱（序号回退或重复） */
    ORDER_VIOLATION,
    /** 链节断裂：prevHash 与上一条 hash 不一致 */
    LINK_MISMATCH,
    /** 清单哈希与包内容不符（内容被改但未重签） */
    MANIFEST_MISMATCH,
    /** 签名不符：伪造、掉包或非本信任域密钥签发 */
    SIGNATURE_MISMATCH
}
