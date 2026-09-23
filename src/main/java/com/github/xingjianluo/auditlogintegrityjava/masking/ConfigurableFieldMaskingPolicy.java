package com.github.xingjianluo.auditlogintegrityjava.masking;

import com.github.xingjianluo.auditlogintegrityjava.crypto.HashService;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Policy driven by a set of sensitive field names. Its version embeds a
 * digest of the sorted field set plus the masking strategy version, so:
 * records persist the policy version they were written under, and updating
 * the field set produces a new version without rewriting history.
 */
public class ConfigurableFieldMaskingPolicy implements FieldMaskingPolicy {

    private final MaskingStrategy strategy;
    private final HashService hashService;
    private Set<String> sensitiveFields;
    private String version;

    public ConfigurableFieldMaskingPolicy(MaskingStrategy strategy,
                                          HashService hashService,
                                          Set<String> sensitiveFields) {
        this.strategy = strategy;
        this.hashService = hashService;
        this.sensitiveFields = Set.copyOf(sensitiveFields);
        this.version = computeVersion(this.sensitiveFields);
    }

    private String computeVersion(Set<String> fields) {
        String joined = String.join(",", new TreeSet<>(fields));
        return "policy-" + strategy.version() + "-" + hashService.sha256Hex(joined).substring(0, 8);
    }

    public synchronized void updateSensitiveFields(Set<String> newSensitiveFields) {
        this.sensitiveFields = Set.copyOf(newSensitiveFields);
        this.version = computeVersion(this.sensitiveFields);
    }

    @Override
    public synchronized String version() {
        return version;
    }

    @Override
    public synchronized boolean isSensitive(String fieldName) {
        return sensitiveFields.contains(fieldName);
    }

    @Override
    public synchronized Map<String, String> apply(Map<String, String> detail) {
        if (detail == null) {
            return Map.of();
        }
        Map<String, String> masked = new LinkedHashMap<>(detail.size());
        for (Map.Entry<String, String> e : detail.entrySet()) {
            if (sensitiveFields.contains(e.getKey())) {
                masked.put(e.getKey(), strategy.mask(e.getValue()));
            } else {
                masked.put(e.getKey(), e.getValue());
            }
        }
        return Map.copyOf(masked);
    }
}
