package com.github.xingjianluo.auditlogintegrityjava.chain;

/**
 * 校验中发现的单个问题。
 */
public record VerificationIssue(
        VerificationFailureReason reason,
        Long seq,
        String eventId,
        String detail) {
}
