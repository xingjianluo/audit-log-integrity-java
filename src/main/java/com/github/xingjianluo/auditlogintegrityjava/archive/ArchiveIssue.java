package com.github.xingjianluo.auditlogintegrityjava.archive;

/**
 * 归档包核验中发现的单个问题。
 */
public record ArchiveIssue(
        ArchiveFailureReason reason,
        Long seq,
        String eventId,
        String detail) {
}
