package com.github.xingjianluo.auditlogintegrityjava.archive;

import java.util.List;

/**
 * 归档包离线核验结论。
 *
 * <p>valid=false 时 primaryReason 给出最主要的失败类别（结构问题优先于清单/签名问题），
 * issues 按发现顺序列出全部判定依据。
 */
public record ArchiveVerification(
        boolean valid,
        ArchiveFailureReason primaryReason,
        String environmentId,
        long fromSeq,
        long toSeq,
        long scannedEntries,
        List<ArchiveIssue> issues) {

    public static ArchiveVerification ok(String environmentId, long fromSeq, long toSeq, long scanned) {
        return new ArchiveVerification(true, ArchiveFailureReason.OK,
                environmentId, fromSeq, toSeq, scanned, List.of());
    }

    public static ArchiveVerification invalid(String environmentId, long fromSeq, long toSeq,
                                              long scanned, List<ArchiveIssue> issues) {
        return new ArchiveVerification(false, primaryReasonOf(issues), environmentId,
                fromSeq, toSeq, scanned, List.copyOf(issues));
    }

    /**
     * 主因按类别优先级选取（而非发现顺序），保证同类破坏永远得到同类结论：
     * 例如重排会同时触发链节断裂，但主因必须是 ORDER_VIOLATION。
     */
    private static ArchiveFailureReason primaryReasonOf(List<ArchiveIssue> issues) {
        if (issues.isEmpty()) {
            return ArchiveFailureReason.MALFORMED_PACKAGE;
        }
        ArchiveFailureReason best = null;
        for (ArchiveIssue i : issues) {
            if (best == null || priority(i.reason()) < priority(best)) {
                best = i.reason();
            }
        }
        return best;
    }

    private static int priority(ArchiveFailureReason r) {
        return switch (r) {
            case MALFORMED_PACKAGE -> 0;
            case UNSUPPORTED_FORMAT -> 1;
            case UNTRUSTED_ENVIRONMENT -> 2;
            case ENVIRONMENT_MISMATCH -> 3;
            case EMPTY_ARCHIVE -> 4;
            case ORDER_VIOLATION -> 5;
            case SEQUENCE_GAP -> 6;
            case TRUNCATED -> 7;
            case ENTRY_HASH_MISMATCH -> 8;
            case LINK_MISMATCH -> 9;
            case MANIFEST_MISMATCH -> 10;
            case SIGNATURE_MISMATCH -> 11;
            case OK -> 12;
        };
    }
}
