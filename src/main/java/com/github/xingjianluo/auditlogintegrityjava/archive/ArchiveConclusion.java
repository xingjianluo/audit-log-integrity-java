package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 归档包离线核验结论，彼此可区分。
 */
public enum ArchiveConclusion {
    /** 包完整且未被改动 */
    VALID,
    /** 包文件本身无法解析（被截断/损坏/不是归档包） */
    MALFORMED_PACKAGE,
    /** 签名无效：包被掉包或伪造 */
    SIGNATURE_INVALID,
    /** 签名有效但清单中的环境标识与所持公钥派生的环境标识不符 */
    ENVIRONMENT_MISMATCH,
    /** 条目内容被改（复算哈希与存储哈希不一致，或区间锚定信息被改） */
    CONTENT_TAMPERED,
    /** 区间中间/头部有记录被删除（序号出现空洞） */
    RECORDS_DELETED,
    /** 尾部被截断：现有事件是声明区间的合法前缀但数量不足 */
    TAIL_TRUNCATED,
    /** 顺序被打乱（序号非递增或链节接不上，但条目哈希本身有效） */
    ORDER_SHUFFLED
}
