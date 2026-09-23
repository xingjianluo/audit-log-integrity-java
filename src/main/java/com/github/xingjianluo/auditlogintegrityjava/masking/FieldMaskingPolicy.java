package com.github.xingjianluo.auditlogintegrityjava.masking;

import java.util.Map;

/**
 * Policy deciding which fields of an event are sensitive and must be masked
 * before persistence. Policies are versioned; each stored record keeps the
 * policy version under which it was written, so later policy changes never
 * invalidate historical verification conclusions.
 */
public interface FieldMaskingPolicy {
    String version();
    boolean isSensitive(String fieldName);
    Map<String, String> apply(Map<String, String> detail);
}
