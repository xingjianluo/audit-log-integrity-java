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
     * 把一批（已按本地链重新编号的）事件原子合并到链尾，并同时刷新锚点。
     * 整体是“写意图 → 重写链文件 → 刷新锚点 → 删意图”的单步可恢复操作：
     * 中途失败或崩溃，要么旧链分毫不动，要么重启后把合并推进完成，
     * 不会留下“链已变但锚点仍旧”的歧义状态。
     */
    void mergeAppend(List<AuditEvent> batch, Anchor anchor);
}
