package com.github.xingjianluo.auditlogintegrityjava.archive;

import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

/**
 * 归档包格式常量与清单规范化串（签名与离线核验两端共用同一实现，保证字节级一致）。
 */
public final class ArchiveFormat {

    public static final String FORMAT = "audit-archive";
    public static final int VERSION = 1;

    private ArchiveFormat() {
    }

    /**
     * 清单的规范化签名串（UTF-8，字段顺序固定，\n 分隔）：
     * 签名只覆盖清单；事件本体由清单中的 precedingHash/headHash/tailHash
     * 与事件自身的链式哈希共同绑定。
     */
    public static byte[] canonicalManifestBytes(ArchiveManifest m) {
        String canonical = String.join("\n",
                nullToEmpty(m.format()),
                Integer.toString(m.version()),
                nullToEmpty(m.archiveId()),
                nullToEmpty(m.environmentId()),
                Long.toString(m.createdAt()),
                Long.toString(m.fromSeq()),
                Long.toString(m.toSeq()),
                Integer.toString(m.count()),
                nullToEmpty(m.precedingHash()),
                nullToEmpty(m.headHash()),
                nullToEmpty(m.tailHash()),
                m.policyVersions() == null ? "" : m.policyVersions().stream()
                        .map(String::valueOf).collect(Collectors.joining(",")));
        return canonical.getBytes(StandardCharsets.UTF_8);
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
