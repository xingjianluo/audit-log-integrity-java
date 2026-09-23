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
}
