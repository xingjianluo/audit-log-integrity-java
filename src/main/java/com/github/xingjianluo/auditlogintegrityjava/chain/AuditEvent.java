package com.github.xingjianluo.auditlogintegrityjava.chain;

import java.util.Map;

/**
 * 一条不可变的审计事件（落盘形态：payload 已按写入时策略脱敏）。
 */
public record AuditEvent(
        String eventId,
        long seq,
        long timestamp,
        String actor,
        String action,
        String resource,
        Map<String, String> payload,
        int policyVersion,
        String prevHash,
        String hash) {
}
