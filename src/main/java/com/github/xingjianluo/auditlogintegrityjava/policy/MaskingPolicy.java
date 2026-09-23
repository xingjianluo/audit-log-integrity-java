package com.github.xingjianluo.auditlogintegrityjava.policy;

import java.util.Set;

/**
 * 脱敏策略（带版本号，事件落盘时记录所用版本）。
 */
public record MaskingPolicy(
        int version,
        Set<String> sensitiveFields,
        String maskToken) {
}
