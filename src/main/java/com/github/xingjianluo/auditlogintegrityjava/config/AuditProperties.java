package com.github.xingjianluo.auditlogintegrityjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * audit.* 配置：存储目录、初始脱敏字段等。
 */
@ConfigurationProperties(prefix = "audit")
public class AuditProperties {

    private String dataDir = "audit-data";
    private List<String> sensitiveFields = List.of("password", "idCard", "phone", "token");
    private String maskToken = "***REDACTED***";

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
}
