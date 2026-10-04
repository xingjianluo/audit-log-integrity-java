package com.github.xingjianluo.auditlogintegrityjava.archive;

import java.util.List;

/**
 * 一次离线核验的结论。
 */
public record ArchiveVerification(
        ArchiveConclusion conclusion,
        String archiveId,
        String environmentId,
        long fromSeq,
        long toSeq,
        int eventCount,
        List<String> details) {

    public boolean valid() {
        return conclusion == ArchiveConclusion.VALID;
    }
}
