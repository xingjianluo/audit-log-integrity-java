package com.github.xingjianluo.auditlogintegrityjava.service;

import java.util.Map;

/**
 * 业务侧提交的审计事件输入（payload 为原始明文）。
 */
public record EventInput(
        String eventId,
        String actor,
        String action,
        String resource,
        Map<String, String> payload) {
}
