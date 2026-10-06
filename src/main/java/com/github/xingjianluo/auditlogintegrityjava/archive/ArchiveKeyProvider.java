package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 归档密钥与环境身份。
 *
 * <p>每个环境有独立 environmentId 与签名密钥；核验他人包时按包内 environmentId
 * 在信任列表（audit.trusted-archive-keys）中查 key，查不到即不可信。
 * 不同环境密钥不同，因此跨环境的包无法互相顶替。
 */
@Component
public class ArchiveKeyProvider {

    private final AuditProperties properties;

    public ArchiveKeyProvider(AuditProperties properties) {
        this.properties = properties;
    }

    public String localEnvironmentId() {
        return properties.getEnvironmentId();
    }

    /**
     * 本地签发归档包所缺的配置项列表（为空表示配置齐全）。
     * 用于把“没配置好”归类为可操作的结论，而不是导出中途抛异常。
     */
    public java.util.List<String> missingLocalConfig() {
        java.util.List<String> missing = new java.util.ArrayList<>();
        String envId = properties.getEnvironmentId();
        if (envId == null || envId.isBlank()) {
            missing.add("audit.environment-id");
        }
        String key = properties.getArchiveKey();
        if (key == null || key.isBlank()) {
            missing.add("audit.archive-key");
        }
        return missing;
    }

    /**
     * 本环境签名密钥（导出用）。未配置时抛异常，拒绝用默认弱密钥签发。
     */
    public String localKey() {
        String key = properties.getArchiveKey();
        if (key == null || key.isBlank()) {
            throw new IllegalStateException("未配置 audit.archive-key，无法签发归档包");
        }
        return key;
    }

    /**
     * 核验指定环境包所需的密钥：本环境用本地 key，其他环境查信任列表。
     */
    public Optional<String> keyFor(String environmentId) {
        if (environmentId == null || environmentId.isBlank()) {
            return Optional.empty();
        }
        if (environmentId.equals(properties.getEnvironmentId())) {
            String key = properties.getArchiveKey();
            return (key == null || key.isBlank()) ? Optional.empty() : Optional.of(key);
        }
        String key = properties.getTrustedArchiveKeys().get(environmentId);
        return (key == null || key.isBlank()) ? Optional.empty() : Optional.of(key);
    }
}
