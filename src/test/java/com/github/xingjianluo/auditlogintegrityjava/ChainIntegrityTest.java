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
 * 正常链路 + 篡改单条字段。
 */
class ChainIntegrityTest {

    private static final Logger log = LoggerFactory.getLogger(ChainIntegrityTest.class);

    @TempDir
    Path dir;

    @Test
    void cleanChainVerifies() {
        var h = AuditTestSupport.harness(dir);
        log.info("[输入] 连续追加 3 条事件, dataDir={}", dir);
        h.events().append("alice", "LOGIN", "host-1", AuditTestSupport.payload("ip", "10.0.0.1"));
        h.events().append("bob", "GRANT", "role-admin", AuditTestSupport.payload());
        h.events().append("alice", "LOGOUT", "host-1", AuditTestSupport.payload("ip", "10.0.0.1"));

        VerificationReport report = h.auditService().verify();
        log.info("[判定依据] valid={}, scanned={}, range=[{},{}], issues={}",
                report.valid(), report.scannedEntries(), report.headSeq(), report.tailSeq(), report.issues());
        assertTrue(report.valid());
        assertEquals(3, report.scannedEntries());
        assertEquals(1, report.headSeq());
        assertEquals(3, report.tailSeq());
    }

    @Test
    void tamperedFieldIsDetectedWithEntryHashMismatch() throws Exception {
        var h = AuditTestSupport.harness(dir);
        h.events().append("alice", "LOGIN", "host-1", AuditTestSupport.payload("ip", "10.0.0.1"));
        h.events().append("bob", "GRANT", "role-admin", AuditTestSupport.payload());
        h.events().append("alice", "LOGOUT", "host-1", AuditTestSupport.payload("ip", "10.0.0.1"));

        Path file = dir.resolve("events.jsonl");
        List<String> lines = Files.readAllLines(file);
        log.info("[输入] 篡改第 2 行 actor: bob -> mallory");
        lines.set(1, lines.get(1).replace("\"actor\":\"bob\"", "\"actor\":\"mallory\""));
        Files.write(file, lines);

        VerificationReport report = h.auditService().verify();
        log.info("[判定依据] valid={}, reasons={}", report.valid(),
                report.issues().stream().map(i -> i.reason() + "@seq" + i.seq()).toList());
        assertFalse(report.valid());
        assertTrue(report.issues().stream().anyMatch(i ->
                i.reason() == VerificationFailureReason.ENTRY_HASH_MISMATCH && i.seq() == 2L));
    }
}
