package com.github.xingjianluo.auditlogintegrityjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Map;

/**
 * audit.* 配置：存储目录、初始脱敏字段、归档环境身份与密钥等。
 */
@ConfigurationProperties(prefix = "audit")
public class AuditProperties {

    private String dataDir = "audit-data";
    private List<String> sensitiveFields = List.of("password", "idCard", "phone", "token");
    private String maskToken = "***REDACTED***";
    /** 本环境标识，签发进归档包清单，防止跨环境顶替 */
    private String environmentId = "local";
    /** 本环境归档签名密钥（HMAC-SHA256） */
    private String archiveKey = "";
    /** 信任的其他环境归档密钥：environmentId -> key，用于核验/导入外部包 */
    private Map<String, String> trustedArchiveKeys = Map.of();

    public String getDataDir() {
        return dataDir;
    }

    public void setDataDir(String dataDir) {
        this.dataDir = dataDir;
    }

    public List<String> getSensitiveFields() {
        return sensitiveFields;
    }

    public void setSensitiveFields(List<String> sensitiveFields) {
        this.sensitiveFields = sensitiveFields;
    }

    public String getMaskToken() {
        return maskToken;
    }

    public void setMaskToken(String maskToken) {
        this.maskToken = maskToken;
    }

    public String getEnvironmentId() {
        return environmentId;
    }

    public void setEnvironmentId(String environmentId) {
        this.environmentId = environmentId;
    }

    public String getArchiveKey() {
        return archiveKey;
    }

    public void setArchiveKey(String archiveKey) {
        this.archiveKey = archiveKey;
    }

    public Map<String, String> getTrustedArchiveKeys() {
        return trustedArchiveKeys;
    }

    public void setTrustedArchiveKeys(Map<String, String> trustedArchiveKeys) {
        this.trustedArchiveKeys = trustedArchiveKeys;
    }
}
