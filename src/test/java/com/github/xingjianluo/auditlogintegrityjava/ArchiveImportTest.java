package com.github.xingjianluo.auditlogintegrityjava;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveFailureReason;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportResult;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 归档导入：记录并入本地链成为本环境自己的记录（可查询、整体校验、可续写）；
 * 幂等、原子（失败零影响）、并发安全；包问题/本地链问题/存储问题/内部错误各自可区分。
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
        assertEquals(ArchiveExportOutcome.EXPORTED, r.outcome());
        return Path.of(r.archiveFile());
    }

    private byte[] chainBytes(Path envDir) throws Exception {
        Path f = envDir.resolve("events.jsonl");
        return Files.exists(f) ? Files.readAllBytes(f) : new byte[0];
    }

    @Test
    void importMergesIntoLocalChainAndStaysAppendable() throws Exception {
        var a = sourceEnv(5);
        Path archive = exportFrom(a, 2, 5);

        var b = destEnv();
        b.events().append("local1", "L", "r", AuditTestSupport.payload());
        b.events().append("local2", "L", "r", AuditTestSupport.payload());
        log.info("[输入] 目标环境已有 2 条本地记录，导入 envA 区间 [2,5] 共 4 条");

        ArchiveImportResult result = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, mergedCount={}, detail={}",
                result.outcome(), result.mergedCount(), result.detail());
        assertEquals(ArchiveImportOutcome.IMPORTED, result.outcome());
        assertEquals(4, result.mergedCount());

        // 导入的记录成为本环境自己的记录：与本地记录一起可查
        List<AuditEvent> all = b.auditService().readAll();
        assertEquals(6, all.size(), "本地 2 条 + 导入 4 条应一起查到");
        List<String> actors = all.stream().map(AuditEvent::actor).toList();
        assertTrue(actors.containsAll(List.of("local1", "local2", "actor2", "actor3", "actor4", "actor5")),
                "导入记录的内容（actor 等）应原样保留: " + actors);
        // 整体校验照样通过
        assertTrue(b.auditService().verify().valid(), "导入后整体校验必须通过");

        // 能接着往后写，序号与链节连续
        b.events().append("local3", "L", "r", AuditTestSupport.payload());
        List<AuditEvent> after = b.auditService().readAll();
        assertEquals(7, after.size());
        assertEquals(7, after.get(after.size() - 1).seq(), "续写应接在导入记录之后");
        assertTrue(b.auditService().verify().valid(), "续写后整体校验仍须通过");
        log.info("[判定依据] 导入后总条数=6, 续写后=7, 整体校验通过");
    }

    @Test
    void importIntoEmptyEnvironmentBecomesOwnChain() {
        var a = sourceEnv(3);
        Path archive = exportFrom(a, 1, 3);
        var b = destEnv(); // 全空环境
        log.info("[输入] 空环境导入 envA 区间 [1,3] 共 3 条");

        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, mergedCount={}", r.outcome(), r.mergedCount());
        assertEquals(ArchiveImportOutcome.IMPORTED, r.outcome());
        assertEquals(3, r.mergedCount());

        List<AuditEvent> all = b.auditService().readAll();
        assertEquals(3, all.size(), "空环境导入后这 3 条就是本环境自己的记录");
        assertEquals(1, all.get(0).seq(), "空环境并入应从 seq=1 重新编号");
        assertTrue(b.auditService().verify().valid());

        // 接着往后写
        b.events().append("local", "L", "r", AuditTestSupport.payload());
        assertEquals(4, b.auditService().readAll().size());
        assertTrue(b.auditService().verify().valid());
        log.info("[判定依据] 空环境导入后可查询、整体校验通过、可续写");
    }

    @Test
    void repeatedImportIsIdempotent() throws Exception {
        var a = sourceEnv(4);
        Path archive = exportFrom(a, 1, 4);
        var b = destEnv();
        b.events().append("local", "L", "r", AuditTestSupport.payload());
        log.info("[输入] 同一包连续导入 3 次");

        ArchiveImportResult r1 = b.archiveService().importArchive(archive);
        byte[] afterFirst = chainBytes(dir.resolve("b"));
        ArchiveImportResult r2 = b.archiveService().importArchive(archive);
        ArchiveImportResult r3 = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcomes=[{},{},{}], merged=[{},{},{}], 链字节在首次后不再变化={}",
                r1.outcome(), r2.outcome(), r3.outcome(),
                r1.mergedCount(), r2.mergedCount(), r3.mergedCount(),
                Arrays.equals(afterFirst, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.IMPORTED, r1.outcome());
        assertEquals(ArchiveImportOutcome.DUPLICATE_IGNORED, r2.outcome());
        assertEquals(ArchiveImportOutcome.DUPLICATE_IGNORED, r3.outcome());
        assertEquals(0, r2.mergedCount());
        assertEquals(0, r3.mergedCount());
        assertEquals(5, b.auditService().readAll().size(), "重复导入不得堆记录");
        assertTrue(Arrays.equals(afterFirst, chainBytes(dir.resolve("b"))),
                "重复导入不得改动链");
        assertTrue(b.auditService().verify().valid());
    }

    @Test
    void overlappingPackagesOnlyMergeNewRecords() throws Exception {
        var a = sourceEnv(8);
        Path first = exportFrom(a, 1, 4);
        Path second = exportFrom(a, 3, 8);
        var b = destEnv();
        log.info("[输入] 先后导入区间 [1,4] 与 [3,8]（重叠 2 条）");

        ArchiveImportResult r1 = b.archiveService().importArchive(first);
        ArchiveImportResult r2 = b.archiveService().importArchive(second);
        log.info("[判定依据] 第一次 merged={}, 第二次 outcome={}, merged={}",
                r1.mergedCount(), r2.outcome(), r2.mergedCount());
        assertEquals(4, r1.mergedCount());
        assertEquals(ArchiveImportOutcome.IMPORTED, r2.outcome());
        assertEquals(4, r2.mergedCount(), "重叠的 2 条应幂等跳过，只并入 4 条新记录");
        assertEquals(8, b.auditService().readAll().size());
        assertTrue(b.auditService().verify().valid());
    }

    @Test
    void importAfterLocalPruneReimportsWithDistinctOutcome() throws Exception {
        var a = sourceEnv(4);
        Path archive = exportFrom(a, 1, 4);
        var b = destEnv(); // 空环境

        ArchiveImportResult r1 = b.archiveService().importArchive(archive);
        assertEquals(ArchiveImportOutcome.IMPORTED, r1.outcome());
        // 保留期清理：只留最新 2 条，导入的头部 2 条被清掉
        int removed = b.auditService().retainByBatch(1, 2);
        assertEquals(2, removed);
        assertEquals(2, b.auditService().readAll().size());
        log.info("[输入] 导入后清理掉其中 2 条，再导入同一个包");

        ArchiveImportResult r2 = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, mergedCount={}, detail={}",
                r2.outcome(), r2.mergedCount(), r2.detail());
        assertEquals(ArchiveImportOutcome.REIMPORTED_AFTER_PRUNE, r2.outcome(),
                "清理后再导入必须给出可区分结论，不能悄悄判成普通成功");
        assertEquals(2, r2.mergedCount(), "被清理的 2 条应重新并入");
        assertEquals(4, b.auditService().readAll().size());
        assertTrue(b.auditService().verify().valid(), "重新并入后整体校验仍须通过");

        // 再导入一次：记录都在了，回到幂等忽略
        ArchiveImportResult r3 = b.archiveService().importArchive(archive);
        assertEquals(ArchiveImportOutcome.DUPLICATE_IGNORED, r3.outcome());
    }

    @Test
    void tamperedPackageIsIntegrityRejectedWithZeroLocalEffect() throws Exception {
        var a = sourceEnv(4);
        Path archive = exportFrom(a, 1, 4);
        ObjectNode root = (ObjectNode) MAPPER.readTree(Files.readAllBytes(archive));
        ((ObjectNode) root.withArray("events").get(0)).put("actor", "forged");
        MAPPER.writeValue(archive.toFile(), root);
        log.info("[输入] 导入一个事件内容被篡改的包");

        var b = destEnv();
        b.events().append("local", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));

        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, primaryReason={}, 本地链字节不变={}",
                r.outcome(), r.verification().primaryReason(),
                Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.INTEGRITY_REJECTED, r.outcome());
        assertEquals(0, r.mergedCount());
        assertEquals(1, b.auditService().readAll().size(), "拒绝导入不得新增任何记录");
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))), "本地记录零改动");
        assertTrue(b.auditService().verify().valid());
    }

    @Test
    void untrustedSourceIsDistinctAndPointsToConfig() throws Exception {
        var c = AuditTestSupport.harness(dir.resolve("c"), List.of("password"),
                "envC", "key-C", Map.of());
        for (int i = 1; i <= 3; i++) {
            c.events().append("a" + i, "A", "r", AuditTestSupport.payload());
        }
        Path archive = exportFrom(c, 1, 3);

        var b = destEnv(); // 只信任 envA，不信任 envC
        byte[] before = chainBytes(dir.resolve("b"));
        log.info("[输入] 导入来自未信任环境 envC 的包");
        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, primaryReason={}, detail={}",
                r.outcome(), r.verification().primaryReason(), r.detail());
        assertEquals(ArchiveImportOutcome.UNTRUSTED_SOURCE, r.outcome());
        assertTrue(r.detail().contains("audit.trusted-archive-keys"),
                "应指明该补哪项配置: " + r.detail());
        assertEquals(0, b.auditService().readAll().size());
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))));
    }

    @Test
    void missingPackageFileIsDistinctFromCorruptPackage() throws Exception {
        var b = destEnv();
        b.events().append("local", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));
        Path missing = dir.resolve("no-such-archive.json");
        log.info("[输入] 导入一个不存在的包文件");

        ArchiveImportResult r = b.archiveService().importArchive(missing);
        log.info("[判定依据] outcome={}, primaryReason={}", r.outcome(),
                r.verification().primaryReason());
        assertEquals(ArchiveImportOutcome.INTEGRITY_REJECTED, r.outcome());
        assertEquals(ArchiveFailureReason.PACKAGE_NOT_FOUND, r.verification().primaryReason(),
                "包未送达/路径错误应与包内容损坏区分开");
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))));
    }

    @Test
    void storageFailureIsDistinctAndRetryableWithZeroLocalEffect() throws Exception {
        var a = sourceEnv(3);
        Path archive = exportFrom(a, 1, 3);
        var b = destEnv();
        b.events().append("local", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));

        // 制造存储故障：merge.intent 路径被非空目录占用，写恢复意图必失败
        Path blocker = dir.resolve("b").resolve("merge.intent");
        Files.createDirectories(blocker.resolve("child"));
        log.info("[输入] merge.intent 被目录占用（模拟存储故障）后导入");

        ArchiveImportResult failed = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, 本地链字节不变={}, 条数={}",
                failed.outcome(), Arrays.equals(before, chainBytes(dir.resolve("b"))),
                b.auditService().readAll().size());
        assertEquals(ArchiveImportOutcome.STORAGE_FAILED, failed.outcome());
        assertEquals(0, failed.mergedCount());
        assertEquals(1, b.auditService().readAll().size(), "存储失败不得新增记录");
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))), "本地原有记录零改动");
        assertTrue(b.auditService().verify().valid());

        // 故障恢复后重试成功（包本身没问题），且失败没留下残渣
        Files.delete(blocker.resolve("child"));
        Files.delete(blocker);
        ArchiveImportResult retry = b.archiveService().importArchive(archive);
        log.info("[判定依据] 恢复后重试: outcome={}, mergedCount={}", retry.outcome(),
                retry.mergedCount());
        assertEquals(ArchiveImportOutcome.IMPORTED, retry.outcome());
        assertEquals(4, b.auditService().readAll().size());
        assertTrue(b.auditService().verify().valid());
        try (var s = Files.list(dir.resolve("b"))) {
            List<String> residue = s.map(p -> p.getFileName().toString())
                    .filter(n -> n.contains(".tmp") || n.equals("merge.intent"))
                    .toList();
            assertTrue(residue.isEmpty(), "失败/成功后不得留下临时文件残渣: " + residue);
        }
    }

    @Test
    void localChainBrokenIsDistinctFromPackageProblem() throws Exception {
        var a = sourceEnv(3);
        Path archive = exportFrom(a, 1, 3);
        var b = destEnv();
        b.events().append("local1", "L", "r", AuditTestSupport.payload());
        b.events().append("local2", "L", "r", AuditTestSupport.payload());

        // 破坏本地链（篡改一条记录的 actor）
        Path eventsFile = dir.resolve("b").resolve("events.jsonl");
        List<String> lines = Files.readAllLines(eventsFile);
        ObjectNode first = (ObjectNode) MAPPER.readTree(lines.get(0));
        first.put("actor", "tampered");
        lines.set(0, MAPPER.writeValueAsString(first));
        Files.write(eventsFile, lines);
        byte[] broken = chainBytes(dir.resolve("b"));
        log.info("[输入] 本地链被篡改后导入一个本身有效的包");

        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, detail={}", r.outcome(), r.detail());
        assertEquals(ArchiveImportOutcome.LOCAL_CHAIN_INVALID, r.outcome(),
                "本地链破损应与包本身有问题严格区分");
        assertEquals(0, r.mergedCount());
        assertTrue(Arrays.equals(broken, chainBytes(dir.resolve("b"))),
                "拒绝合并且本地记录（即使是破损状态）不被改动");
    }

    @Test
    void concurrentImportOfSamePackageMergesExactlyOnce() throws Exception {
        var a = sourceEnv(6);
        Path archive = exportFrom(a, 1, 6);
        var b = destEnv();
        b.events().append("local", "L", "r", AuditTestSupport.payload());
        int threads = 8;
        log.info("[输入] {} 个线程同时导入同一个包", threads);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        ConcurrentLinkedQueue<ArchiveImportResult> results = new ConcurrentLinkedQueue<>();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                results.add(b.archiveService().importArchive(archive));
                return null;
            }));
        }
        ready.await();
        go.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        long imported = results.stream()
                .filter(r -> r.outcome() == ArchiveImportOutcome.IMPORTED).count();
        long duplicates = results.stream()
                .filter(r -> r.outcome() == ArchiveImportOutcome.DUPLICATE_IGNORED).count();
        long mergedTotal = results.stream().mapToLong(ArchiveImportResult::mergedCount).sum();
        log.info("[判定依据] IMPORTED={}, DUPLICATE_IGNORED={}, 总并入条数={}, 链大小={}",
                imported, duplicates, mergedTotal, b.auditService().readAll().size());
        assertEquals(1, imported, "并发下同一包只能被真正并入一次");
        assertEquals(threads - 1, duplicates);
        assertEquals(6, mergedTotal, "并发导入不得重复堆记录");
        assertEquals(7, b.auditService().readAll().size());
        assertTrue(b.auditService().verify().valid(), "并发导入后链必须完好");
    }
}
