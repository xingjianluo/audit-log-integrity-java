package com.github.xingjianluo.auditlogintegrityjava;

import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerification;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import com.github.xingjianluo.auditlogintegrityjava.storage.Anchor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规模表现：较大链上导出与离线核验的耗时/内存应在可接受范围（流式实现，核验侧 O(1) 内存）。
 */
class ArchiveScaleTest {

    private static final Logger log = LoggerFactory.getLogger(ArchiveScaleTest.class);
    private static final int N = 5000;
    private static final long TIME_BUDGET_MS = 30_000;

    @TempDir
    Path dir;

    @Test
    void exportAndVerifyScaleLinearly() throws Exception {
        var h = AuditTestSupport.harness(dir, List.of("password"),
                "envA", "key-A", Map.of());

        // 直接构造 N 条合法链（绕开追加路径，专注测量导出/核验）
        long t0 = System.nanoTime();
        String prev = ChainHasher.GENESIS_HASH;
        String headHash = null;
        for (int i = 1; i <= N; i++) {
            AuditEvent candidate = new AuditEvent("evt-" + i, i, 1_700_000_000_000L + i,
                    "actor" + (i % 50), "ACTION" + (i % 10), "res" + (i % 100),
                    Map.of("k" + (i % 7), "v" + i), 1, prev, "");
            String hash = h.hasher().computeHash(candidate);
            AuditEvent e = new AuditEvent(candidate.eventId(), candidate.seq(), candidate.timestamp(),
                    candidate.actor(), candidate.action(), candidate.resource(),
                    candidate.payload(), candidate.policyVersion(), candidate.prevHash(), hash);
            h.store().append(e);
            if (headHash == null) {
                headHash = hash;
            }
            prev = hash;
        }
        h.store().writeAnchor(new Anchor(1, headHash, N, prev, N));
        long buildMs = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(h.auditService().verify().valid());

        long usedBefore = usedMemoryMb();
        long t1 = System.nanoTime();
        ArchiveExportResult exported = h.archiveService().exportRange(1, N);
        long exportMs = (System.nanoTime() - t1) / 1_000_000;
        assertEquals(ArchiveExportOutcome.EXPORTED, exported.outcome());
        assertEquals(N, exported.eventCount());
        long archiveBytes = Files.size(Path.of(exported.archiveFile()));

        long t2 = System.nanoTime();
        ArchiveVerification v = h.archiveService().verify(Path.of(exported.archiveFile()), "envA");
        long verifyMs = (System.nanoTime() - t2) / 1_000_000;
        long usedAfter = usedMemoryMb();

        log.info("[输入] 链规模 N={}, 归档包大小={}KB", N, archiveBytes / 1024);
        log.info("[判定依据] 建链={}ms, 导出={}ms, 核验={}ms, 核验前后堆内存约 {}MB -> {}MB, 结论={}",
                buildMs, exportMs, verifyMs, usedBefore, usedAfter, v.valid());
        assertTrue(v.valid());
        assertEquals(N, v.scannedEntries());
        assertTrue(exportMs < TIME_BUDGET_MS, "导出耗时失控: " + exportMs + "ms");
        assertTrue(verifyMs < TIME_BUDGET_MS, "核验耗时失控: " + verifyMs + "ms");
    }

    private static long usedMemoryMb() {
        System.gc();
        return (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / (1024 * 1024);
    }
}
