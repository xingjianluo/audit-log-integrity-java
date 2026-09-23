package com.github.xingjianluo.auditlogintegrityjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Configuration for the audit chain: storage directory, masking salt,
 * sensitive fields, retention window and cleanup batch size.
 */
@Component
@ConfigurationProperties(prefix = "audit")
public class AuditProperties {

    /** Directory holding audit.log, anchor file and export cursor. */
    private String storageDir = "data/audit";
    /** Salt mixed into masked sensitive values. */
    private String maskingSalt = "default-audit-salt";
    /** Names of sensitive detail fields, mask-keys case-sensitively. */
    private List<String> sensitiveFields = List.of("password", "token", "idCard");
    /** Records older than now - retentionDays are eligible for cleanup. */
    private long retentionDays = 30;
    /** Max records pruned per cleanup batch. */
    private int cleanupBatchSize = 100;

    public String getStorageDir() { return storageDir; }
    public void setStorageDir(String storageDir) { this.storageDir = storageDir; }
    public String getMaskingSalt() { return maskingSalt; }
    public void setMaskingSalt(String maskingSalt) { this.maskingSalt = maskingSalt; }
    public List<String> getSensitiveFields() { return sensitiveFields; }
    public void setSensitiveFields(List<String> sensitiveFields) { this.sensitiveFields = sensitiveFields; }
    public long getRetentionDays() { return retentionDays; }
    public void setRetentionDays(long retentionDays) { this.retentionDays = retentionDays; }
    public int getCleanupBatchSize() { return cleanupBatchSize; }
    public void setCleanupBatchSize(int cleanupBatchSize) { this.cleanupBatchSize = cleanupBatchSize; }
}
