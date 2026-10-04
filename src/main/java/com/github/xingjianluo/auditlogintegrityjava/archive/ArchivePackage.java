package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;

import java.util.List;

/**
 * 自包含归档包：清单 + 事件本体 + 对清单的签名。
 * 核验不依赖来源服务的运行时数据。
 */
public record ArchivePackage(
        ArchiveManifest manifest,
        List<AuditEvent> events,
        String signature) {
}
