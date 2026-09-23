package com.github.xingjianluo.auditlogintegrityjava.service;

import com.github.xingjianluo.auditlogintegrityjava.crypto.HashService;
import com.github.xingjianluo.auditlogintegrityjava.model.ChainAnchor;
import com.github.xingjianluo.auditlogintegrityjava.model.FailureReason;
import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;
import com.github.xingjianluo.auditlogintegrityjava.model.VerificationResult;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Verifies the hash chain:
 * <ol>
 *   <li>every line parses (else CORRUPTED_RECORD),</li>
 *   <li>the head links to the retained anchor (else TRUNCATED_AT_HEAD),</li>
 *   <li>sequence numbers are gap-less and ordered (else SEQUENCE_GAP_OR_REORDER),</li>
 *   <li>each prevHash equals the previous record hash (else CHAIN_BROKEN),</li>
 *   <li>each stored hash equals the recomputed content hash (else CONTENT_TAMPERED),</li>
 *   <li>the persisted tail pointer matches the final record (else TRUNCATED_AT_TAIL).</li>
 * </ol>
 * Hashes are recomputed from stored content only; the current masking policy
 * is never consulted, so historical conclusions remain reproducible after a
 * policy change.
 */
@Service
public class ChainIntegrityVerifier {

    public static final String GENESIS = "GENESIS";

    private final HashService hashService;

    public ChainIntegrityVerifier(HashService hashService) {
        this.hashService = hashService;
    }

    public VerificationResult verify(List<StoredRecord> records, ChainAnchor anchor,
                                     List<Integer> corruptLines, long tailSeq, String tailHash) {
        if (corruptLines != null && !corruptLines.isEmpty()) {
            return VerificationResult.failure(FailureReason.CORRUPTED_RECORD, null, null, null,
                    "unparseable log line(s) at " + corruptLines
                            + "; a record was damaged or replaced with malformed data");
        }

        if (records.isEmpty()) {
            if (anchor == null) {
                return VerificationResult.ok(0, GENESIS);
            }
            return VerificationResult.failure(FailureReason.TRUNCATED_AT_TAIL, anchor.seq(),
                    anchor.hash(), null,
                    "log is empty but anchor references seq=" + anchor.seq()
                            + "; all surviving records were removed");
        }

        StoredRecord first = records.get(0);
        long expectedSeq = anchor == null ? 1 : anchor.seq() + 1;
        String expectedPrev = anchor == null ? GENESIS : anchor.hash();

        if (first.seq() != expectedSeq) {
            return VerificationResult.failure(FailureReason.TRUNCATED_AT_HEAD, first.seq(),
                    Long.toString(expectedSeq), Long.toString(first.seq()),
                    "first surviving seq=" + first.seq() + " but chain requires seq="
                            + expectedSeq + "; head records were illegally deleted/truncated");
        }
        if (!safeEquals(expectedPrev, first.prevHash())) {
            return VerificationResult.failure(FailureReason.TRUNCATED_AT_HEAD, first.seq(),
                    expectedPrev, first.prevHash(),
                    "head record prevHash does not match the retained anchor hash; "
                            + "head truncation/rewrite detected");
        }

        String prevHash = expectedPrev;
        long seq = expectedSeq;
        for (StoredRecord r : records) {
            if (r.seq() != seq) {
                return VerificationResult.failure(FailureReason.SEQUENCE_GAP_OR_REORDER, r.seq(),
                        Long.toString(seq), Long.toString(r.seq()),
                        "expected seq=" + seq + " but found seq=" + r.seq()
                                + "; records were deleted, reordered or duplicated");
            }
            if (!safeEquals(prevHash, r.prevHash())) {
                return VerificationResult.failure(FailureReason.CHAIN_BROKEN, r.seq(),
                        prevHash, r.prevHash(),
                        "prevHash of seq=" + r.seq() + " does not match hash of prior record; "
                                + "a record was replaced or reordered");
            }
            String recomputed = contentHash(r);
            if (!safeEquals(recomputed, r.hash())) {
                return VerificationResult.failure(FailureReason.CONTENT_TAMPERED, r.seq(),
                        recomputed, r.hash(),
                        "stored hash of seq=" + r.seq()
                                + " differs from hash recomputed over its fields; "
                                + "record content was modified after write");
            }
            prevHash = r.hash();
            seq++;
        }

        StoredRecord last = records.get(records.size() - 1);
        if (tailSeq != last.seq() || !safeEquals(tailHash, last.hash())) {
            return VerificationResult.failure(FailureReason.TRUNCATED_AT_TAIL, last.seq(),
                    tailSeq + ":" + tailHash, last.seq() + ":" + last.hash(),
                    "persisted tail pointer expects seq=" + tailSeq + " but log ends at seq="
                            + last.seq() + "; tail records were deleted/truncated");
        }

        return VerificationResult.ok(records.size(), last.hash());
    }

    /**
     * Canonical content hash. Fields are sorted by key and escaped with a
     * length-prefix encoding so serialization is unambiguous.
     */
    public String contentHash(StoredRecord r) {
        StringBuilder sb = new StringBuilder(256);
        appendPart(sb, Long.toString(r.seq()));
        appendPart(sb, r.eventId());
        appendPart(sb, Long.toString(r.timestamp()));
        appendPart(sb, r.actor());
        appendPart(sb, r.action());
        appendPart(sb, r.resource());
        appendPart(sb, r.policyVersion());
        appendPart(sb, r.prevHash());
        TreeMap<String, String> sorted = new TreeMap<>();
        if (r.detail() != null) {
            sorted.putAll(r.detail());
        }
        for (Map.Entry<String, String> e : sorted.entrySet()) {
            appendPart(sb, e.getKey());
            appendPart(sb, e.getValue());
        }
        return hashService.sha256Hex(sb.toString());
    }

    private static void appendPart(StringBuilder sb, String part) {
        if (part == null) {
            part = "";
        }
        sb.append(part.length()).append(':').append(part).append('|');
    }

    private static boolean safeEquals(String a, String b) {
        return a == null ? b == null : a.equals(b);
    }
}
