package com.github.xingjianluo.auditlogintegrityjava.storage;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;

import java.util.List;
import java.util.stream.Stream;

/**
 * 审计事件的追加型持久化存储。所有 IO 异常统一包装为 {@link AuditStoreException}。
 */
public interface AuditStore {

    void append(AuditEvent event);

    List<AuditEvent> readAll();

    /**
     * 流式读取全部事件（调用方负责关闭流）。用于大规模导出等
     * 不能把整条链装入内存的场景；解析失败同样抛 {@link AuditStoreException}。
     */
    Stream<AuditEvent> streamEvents();

    Anchor readAnchor();

    void writeAnchor(Anchor anchor);

    /**
     * 按批次保留：删除 seq &lt; keepBeforeSeq 的事件并重写链文件；
     * 返回保留下来的事件（非空时第一条即新链头）。
     */
    List<AuditEvent> pruneBefore(long keepBeforeSeq);

    /**
     * 截断尾部：删除 seq &gt; keepSeq 的事件并重写链文件与锚点。
     * 用于批量导入失败时回滚到导入前状态；与 pruneBefore 一样可崩溃恢复。
     */
    List<AuditEvent> pruneAfter(long keepSeq);
}
