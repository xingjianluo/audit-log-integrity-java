package com.github.xingjianluo.auditlogintegrityjava;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationFailureReason;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 篡改手段与判定原因的对应：改哈希、断链、重排/空洞、删头、去尾、清空、损坏行。
 */
class TamperDetectionTest {

    private static final Logger log = LoggerFactory.getLogger(TamperDetectionTest.class);

    @TempDir
    Path dir;

    private List<AuditEvent> seed4() {
        var h = AuditTestSupport.harness(dir);
        for (int i = 1; i <= 4; i++) {
            h.events().append("user" + i, "ACT" + i, "res" + i, AuditTestSupport.payload("k", "v" + i));
        }
        return h.auditService().readAll();
    }

    private Path eventsFile() {
        return dir.resolve("events.jsonl");
    }

    private List<String> lines() throws Exception {
        return Files.readAllLines(eventsFile());
    }

    private void writeLines(List<String> lines) throws Exception {
        Files.write(eventsFile(), lines);
    }

    private VerificationReport freshVerify() {
        // 用新组件实例模拟“重启后重新加载存储”
        return AuditTestSupport.harness(dir).auditService().verify();
    }

    @Test
    void replacingHashOnlyIsEntryHashMismatch() throws Exception {
        seed4();
        List<String> lines = lines();
        log.info("[输入] 仅把第 1 行的 hash 字段改写为全 f（内容未动）");
        lines.set(0, lines.get(0).replaceFirst("\"hash\":\"[0-9a-f]+\"", "\"hash\":\"" + "f".repeat(64) + "\""));
        writeLines(lines);

        VerificationReport report = freshVerify();
        log.info("[判定依据] reasons={}", reasons(report));
        assertFalse(report.valid());
        assertTrue(report.issues().stream()
                .anyMatch(i -> i.reason() == VerificationFailureReason.ENTRY_HASH_MISMATCH && i.seq() == 1L));
    }

    @Test
    void deletingHeadIsTruncated() throws Exception {
        seed4();
        log.info("[输入] 删除链头第 1 行（模拟删头截断）");
        writeLines(lines().subList(1, 4));

        VerificationReport report = freshVerify();
        log.info("[判定依据] reasons={}, scanned={}", reasons(report), report.scannedEntries());
        assertFalse(report.valid());
        assertTrue(report.issues().stream()
                .anyMatch(i -> i.reason() == VerificationFailureReason.TRUNCATED && i.seq() == 2L));
    }

    @Test
    void droppingTailIsTruncatedAgainstAnchor() throws Exception {
        seed4();
        log.info("[输入] 删除最后 2 行（锚点仍记录 tailSeq=4）");
        writeLines(lines().subList(0, 2));

        VerificationReport report = freshVerify();
        log.info("[判定依据] reasons={}, scanned={}", reasons(report), report.scannedEntries());
        assertFalse(report.valid());
        assertTrue(report.issues().stream()
                .anyMatch(i -> i.reason() == VerificationFailureReason.TRUNCATED && i.seq() == 2L));
    }

    @Test
    void wipingFileIsTruncated() throws Exception {
        seed4();
        log.info("[输入] 清空整个链文件（锚点仍存在）");
        Files.writeString(eventsFile(), "");

        VerificationReport report = freshVerify();
        log.info("[判定依据] reasons={}, scanned={}", reasons(report), report.scannedEntries());
        assertFalse(report.valid());
        assertEquals(VerificationFailureReason.TRUNCATED, report.issues().get(0).reason());
    }

    @Test
    void swappingTwoEntriesIsDetected() throws Exception {
        seed4();
        List<String> lines = lines();
        log.info("[输入] 交换第 2、3 行顺序（重排）");
        String a = lines.get(1);
        lines.set(1, lines.get(2));
        lines.set(2, a);
        writeLines(lines);

        VerificationReport report = freshVerify();
        log.info("[判定依据] reasons={}", reasons(report));
        assertFalse(report.valid());
        assertTrue(report.issues().stream().anyMatch(i -> i.reason() == VerificationFailureReason.SEQUENCE_GAP));
        assertTrue(report.issues().stream().anyMatch(i -> i.reason() == VerificationFailureReason.LINK_MISMATCH));
    }

    @Test
    void deletingMiddleCausesLinkMismatchAndGap() throws Exception {
        seed4();
        log.info("[输入] 删除中间第 3 行（保留头尾）");
        List<String> lines = lines();
        lines.remove(2);
        writeLines(lines);

        VerificationReport report = freshVerify();
        log.info("[判定依据] reasons={}", reasons(report));
        assertFalse(report.valid());
        assertTrue(report.issues().stream().anyMatch(i -> i.reason() == VerificationFailureReason.LINK_MISMATCH));
        assertTrue(report.issues().stream().anyMatch(i -> i.reason() == VerificationFailureReason.SEQUENCE_GAP));
        assertTrue(report.issues().stream().anyMatch(i -> i.reason() == VerificationFailureReason.ANCHOR_MISMATCH
                && i.detail().contains("条目数")));
    }

    @Test
    void corruptLineIsMalformedEntry() throws Exception {
        seed4();
        List<String> lines = lines();
        log.info("[输入] 把第 2 行写成非 JSON 乱码");
        lines.set(1, "{this-is-not-json!!!");
        writeLines(lines);

        VerificationReport report = freshVerify();
        log.info("[判定依据] reasons={}, detail={}", reasons(report),
                report.issues().stream().map(i -> i.detail()).toList());
        assertFalse(report.valid());
        assertEquals(VerificationFailureReason.MALFORMED_ENTRY, report.issues().get(0).reason());
    }

    @Test
    void anchorTamperIsAnchorMismatch() throws Exception {
        seed4();
        Path anchor = dir.resolve("anchor.json");
        log.info("[输入] 仅篡改锚点 tailHash（链文件不动）");
        String content = Files.readString(anchor);
        Files.writeString(anchor, content.replaceFirst("\"tailHash\":\"[0-9a-f]+\"",
                "\"tailHash\":\"" + "a".repeat(64) + "\""));

        VerificationReport report = freshVerify();
        log.info("[判定依据] reasons={}", reasons(report));
        assertFalse(report.valid());
        assertTrue(report.issues().stream()
                .anyMatch(i -> i.reason() == VerificationFailureReason.ANCHOR_MISMATCH));
    }

    private static List<String> reasons(VerificationReport r) {
        return r.issues().stream()
                .map(i -> i.reason() + "@seq" + i.seq())
                .toList();
    }
}
