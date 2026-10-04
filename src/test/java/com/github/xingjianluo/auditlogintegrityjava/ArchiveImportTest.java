package com.github.xingjianluo.auditlogintegrityjava;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 归档导入：幂等、原子（失败零影响）、包问题与存储问题可区分、与本地记录并存。
 */
class ArchiveImportTest {

    private static final Logger log = LoggerFactory.getLogger(ArchiveImportTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path dir;

    private AuditTestSupport.Harness sourceEnv(int events) {
        var a = AuditTestSupport.harness(dir.resolve("a"), List.of("password"),
                "envA", "key-A", Map.of());
        for (int i = 1; i <= events; i++) {
            a.events().append("actor" + i, "A" + i, "r", AuditTestSupport.payload());
        }
        return a;
    }

    private AuditTestSupport.Harness destEnv() {
        return AuditTestSupport.harness(dir.resolve("b"), List.of("password"),
                "envB", "key-B", Map.of("envA", "key-A"));
    }

    private Path exportFrom(AuditTestSupport.Harness src, long from, long to) {
        ArchiveExportResult r = src.archiveService().exportRange(from, to);
        assertEquals(com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportOutcome.EXPORTED,
                r.outcome());
        return Path.of(r.archiveFile());
    }

    private byte[] chainBytes(Path envDir) throws Exception {
        Path f = envDir.resolve("events.jsonl");
        return Files.exists(f) ? Files.readAllBytes(f) : new byte[0];
    }

    @Test
    void importCoexistsWithLocalChainAndStaysVerifiable() throws Exception {
        var a = sourceEnv(5);
        Path archive = exportFrom(a, 2, 5);

        var b = destEnv();
        b.events().append("local1", "L", "r", AuditTestSupport.payload());
        b.events().append("local2", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));

        ArchiveImportResult result = b.archiveService().importArchive(archive);
        log.info("[判定依据] 导入: outcome={}, storedAs={}, 本地链字节不变={}",
                result.outcome(), result.storedAs(),
                Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.IMPORTED, result.outcome());
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))), "导入不得改动本地链");
        assertTrue(b.auditService().verify().valid(), "本地链校验仍须通过");
        assertEquals(List.of(result.storedAs()), b.archiveService().listImports());
        assertTrue(b.archiveService().verifyImported(result.storedAs()).valid(),
                "导入段可独立离线核验");

        // 并存后本地继续追加不受影响
        b.events().append("local3", "L", "r", AuditTestSupport.payload());
        assertTrue(b.auditService().verify().valid());
        assertEquals(3, b.auditService().readAll().size());
    }

    @Test
    void repeatedImportIsIdempotent() throws Exception {
        var a = sourceEnv(4);
        Path archive = exportFrom(a, 1, 4);
        var b = destEnv();
        b.events().append("local", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));

        ArchiveImportResult r1 = b.archiveService().importArchive(archive);
        ArchiveImportResult r2 = b.archiveService().importArchive(archive);
        ArchiveImportResult r3 = b.archiveService().importArchive(archive);
        log.info("[输入] 同一包连续导入 3 次");
        log.info("[判定依据] outcomes=[{},{},{}], 导入段数={}, 本地链字节不变={}",
                r1.outcome(), r2.outcome(), r3.outcome(), b.archiveService().listImports().size(),
                Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.IMPORTED, r1.outcome());
        assertEquals(ArchiveImportOutcome.DUPLICATE_IGNORED, r2.outcome());
        assertEquals(ArchiveImportOutcome.DUPLICATE_IGNORED, r3.outcome());
        assertEquals(1, b.archiveService().listImports().size(), "重复导入不得产生新记录");
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertTrue(b.auditService().verify().valid());
    }

    @Test
    void tamperedPackageIsIntegrityRejectedWithZeroLocalEffect() throws Exception {
        var a = sourceEnv(4);
        Path archive = exportFrom(a, 1, 4);
        // 破坏包内容（改一条事件）
        ObjectNode root = (ObjectNode) MAPPER.readTree(Files.readAllBytes(archive));
        ((ObjectNode) root.withArray("events").get(0)).put("actor", "forged");
        MAPPER.writeValue(archive.toFile(), root);
        log.info("[输入] 导入一个事件内容被篡改的包");

        var b = destEnv();
        b.events().append("local", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));

        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, primaryReason={}, 导入段数={}, 本地链字节不变={}",
                r.outcome(), r.verification().primaryReason(), b.archiveService().listImports().size(),
                Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.INTEGRITY_REJECTED, r.outcome());
        assertTrue(b.archiveService().listImports().isEmpty(), "拒绝导入不得留下任何记录");
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))), "本地记录零改动");
        assertTrue(b.auditService().verify().valid());
    }

    @Test
    void untrustedSourceIsDistinctFromIntegrityFailure() throws Exception {
        var c = AuditTestSupport.harness(dir.resolve("c"), List.of("password"),
                "envC", "key-C", Map.of());
        for (int i = 1; i <= 3; i++) {
            c.events().append("a" + i, "A", "r", AuditTestSupport.payload());
        }
        Path archive = exportFrom(c, 1, 3);

        var b = destEnv(); // 只信任 envA，不信任 envC
        byte[] before = chainBytes(dir.resolve("b"));
        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[输入] 导入来自未信任环境 envC 的包");
        log.info("[判定依据] outcome={}, primaryReason={}", r.outcome(),
                r.verification().primaryReason());
        assertEquals(ArchiveImportOutcome.UNTRUSTED_SOURCE, r.outcome());
        assertTrue(b.archiveService().listImports().isEmpty());
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))));
    }

    @Test
    void storageFailureIsDistinctAndRetryableWithZeroLocalEffect() throws Exception {
        var a = sourceEnv(3);
        Path archive = exportFrom(a, 1, 3);
        var b = destEnv();
        b.events().append("local", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));

        // 制造存储故障：imports 路径被同名普通文件占用，建目录必失败
        Path importsPath = dir.resolve("b").resolve("imports");
        Files.write(importsPath, "blocked".getBytes());
        log.info("[输入] imports 目录被文件占用（模拟存储故障）后导入");

        ArchiveImportResult failed = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, 本地链字节不变={}, 导入段数={}",
                failed.outcome(), Arrays.equals(before, chainBytes(dir.resolve("b"))),
                b.archiveService().listImports().size());
        assertEquals(ArchiveImportOutcome.STORAGE_FAILED, failed.outcome());
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))), "存储失败时本地零改动");
        assertTrue(b.auditService().verify().valid());

        // 故障恢复后重试成功（包本身没问题）
        Files.delete(importsPath);
        ArchiveImportResult retry = b.archiveService().importArchive(archive);
        log.info("[判定依据] 恢复后重试: outcome={}", retry.outcome());
        assertEquals(ArchiveImportOutcome.IMPORTED, retry.outcome());
        assertEquals(1, b.archiveService().listImports().size());
    }

    @Test
    void importIntoEmptyEnvironmentWorks() {
        var a = sourceEnv(3);
        Path archive = exportFrom(a, 1, 3);
        var b = destEnv(); // 全空环境

        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[判定依据] 空环境导入: outcome={}, 本地链仍为空={}",
                r.outcome(), b.auditService().readAll().isEmpty());
        assertEquals(ArchiveImportOutcome.IMPORTED, r.outcome());
        assertTrue(b.auditService().readAll().isEmpty(), "导入段与本地链分离存放");
        assertTrue(b.archiveService().verifyImported(r.storedAs()).valid());
    }
}
