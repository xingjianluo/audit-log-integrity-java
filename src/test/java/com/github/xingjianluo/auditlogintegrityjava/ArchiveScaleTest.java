package com.github.xingjianluo.auditlogintegrityjava;

import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveConclusion;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerification;
import com.github.xingjianluo.auditlogintegrityjava.archive.ImportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ImportResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规模表现：2 万条链上导出 1 万条区间、离线核验、导入的耗时与结果。
 * 导出走单趟流式校验（内存 O(1)），耗时应与链规模近似线性。
 */
class ArchiveScaleTest {

    private static final Logger log = LoggerFactory.getLogger(ArchiveScaleTest.class);

    private static final int CHAIN_SIZE = 20_000;
    private static final long RANGE_FROM = 5_000;
    private static final long RANGE_TO = 15_000;

    @TempDir
    Path dir;

    @Test
    void exportAndVerifyAtScale() {
        AuditTestSupport.Harness h = AuditTestSupport.harness(dir.resolve("big"));
        long t0 = System.currentTimeMillis();
        AuditTestSupport.appendChainDirectly(h, CHAIN_SIZE);
        long loadMs = System.currentTimeMillis() - t0;

        t0 = System.currentTimeMillis();
        ArchiveExportResult exported = h.archiveExporter().exportRange(RANGE_FROM, RANGE_TO);
        long exportMs = System.currentTimeMillis() - t0;
        log.info("[规模] 链={} 条(造数 {}ms), 导出区间=[{},{}] 条数={}, 包大小={}KB, 导出耗时={}ms",
                CHAIN_SIZE, loadMs, RANGE_FROM, RANGE_TO, exported.eventCount(),
                exported.packageBytes().length / 1024, exportMs);
        assertEquals(ArchiveExportOutcome.EXPORTED, exported.outcome());
        assertEquals(RANGE_TO - RANGE_FROM + 1, exported.eventCount());

        t0 = System.currentTimeMillis();
        ArchiveVerification v = h.archiveVerifier().verify(
                exported.packageBytes(), h.archiveKeys().publicKeyBytes());
        long verifyMs = System.currentTimeMillis() - t0;
        log.info("[判定依据] 离线核验结论={}, 耗时={}ms", v.conclusion(), verifyMs);
        assertEquals(ArchiveConclusion.VALID, v.conclusion());

        // 宽松上限：防止复杂度失控（正常应为秒级以内）
        assertTrue(exportMs < 60_000, "导出耗时失控: " + exportMs + "ms");
        assertTrue(verifyMs < 60_000, "核验耗时失控: " + verifyMs + "ms");
    }

    @Test
    void importAtScaleIsIdempotent() {
        AuditTestSupport.Harness src = AuditTestSupport.harness(dir.resolve("src"));
        AuditTestSupport.appendChainDirectly(src, CHAIN_SIZE);
        ArchiveExportResult exported = src.archiveExporter().exportRange(1, CHAIN_SIZE);
        assertEquals(ArchiveExportOutcome.EXPORTED, exported.outcome());

        AuditTestSupport.Harness dst = AuditTestSupport.harness(dir.resolve("dst"));
        long t0 = System.currentTimeMillis();
        ImportResult r1 = dst.archiveImporter().importPackage(
                exported.packageBytes(), src.archiveKeys().publicKeyBytes());
        long importMs = System.currentTimeMillis() - t0;
        assertEquals(ImportOutcome.IMPORTED, r1.outcome());
        assertEquals(CHAIN_SIZE, r1.importedCount());

        t0 = System.currentTimeMillis();
        ImportResult r2 = dst.archiveImporter().importPackage(
                exported.packageBytes(), src.archiveKeys().publicKeyBytes());
        long reimportMs = System.currentTimeMillis() - t0;
        log.info("[规模] 导入 {} 条: 首次 {}ms, 重复导入 {}ms, 结论={}/{}, 链规模={}",
                CHAIN_SIZE, importMs, reimportMs, r1.outcome(), r2.outcome(),
                dst.auditService().readAll().size());
        assertEquals(ImportOutcome.ALREADY_IMPORTED, r2.outcome());
        assertEquals(CHAIN_SIZE, dst.auditService().readAll().size());
        assertTrue(dst.auditService().verify().valid());
        assertTrue(importMs < 120_000, "导入耗时失控: " + importMs + "ms");
    }
}
