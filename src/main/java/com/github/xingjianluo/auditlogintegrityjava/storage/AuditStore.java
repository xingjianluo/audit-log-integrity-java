package com.github.xingjianluo.auditlogintegrityjava.storage;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;

import java.util.List;

/**
 * 审计事件的追加型持久化存储。所有 IO 异常统一包装为 {@link AuditStoreException}。
 */
public interface AuditStore {

    void append(AuditEvent event);

    List<AuditEvent> readAll();

    Anchor readAnchor();

    void writeAnchor(Anchor anchor);

    /**
     * 按批次保留：删除 seq &lt; keepBeforeSeq 的事件并重写链文件；
     * 返回保留下来的事件（非空时第一条即新链头）。
     */
    List<AuditEvent> pruneBefore(long keepBeforeSeq);

    /**
     * 整体重写链文件（临时文件 + 原子移动）：要么整体生效，要么原文件一字节不变。
     * 不触碰锚点——调用方负责随后刷新锚点；两步骤之间崩溃留下的
     * “锚点落后于链尾”形态由校验侧自动对账。
     */
    void rewriteAll(List<AuditEvent> events);
}
