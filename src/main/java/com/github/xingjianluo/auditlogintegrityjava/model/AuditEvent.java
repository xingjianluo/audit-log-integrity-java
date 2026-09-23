package com.github.xingjianluo.auditlogintegrityjava.model;

import java.util.Map;

/**
 * A security-related audit event submitted by a caller.
 *
 * @param eventId    caller-supplied unique id used for idempotent de-duplication
 * @param timestamp  event time (epoch millis)
 * @param actor      the acting principal (may be sensitive)
 * @param action     operation type, e.g. LOGIN / GRANT
 * @param resource   target resource
 * @param detail     free-form detail fields, some of which may be sensitive
 */
public record AuditEvent(
        String eventId,
        long timestamp,
        String actor,
        String action,
        String resource,
        Map<String, String> detail) {
}
