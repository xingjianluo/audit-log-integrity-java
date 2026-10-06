package com.github.xingjianluo.auditlogintegrityjava;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveFailureReason;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveKeyProvider;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveSigner;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerifier;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingService;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.storage.FileAuditStore;
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
 * 归档导入：包内记录并入本地链成为本环境自己的记录（可查询、整体校验通过、可续写）；
 * 重复导入幂等；并发导入不重复堆记录；各类失败（包问题/本地状态/存储故障/配置缺失/
 * 内部错误）各有可区分结论且本地零改动。
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
    void importMergesIntoLocalChainAndStaysQueryableVerifiableAndAppendable() throws Exception {
        var a = sourceEnv(5);
        Path archive = exportFrom(a, 2, 5);

        var b = destEnv();
        b.events().appendWithId("local-1", "local1", "L", "r", AuditTestSupport.payload());
        b.events().appendWithId("local-2", "local2", "L", "r", AuditTestSupport.payload());
        log.info("[输入] 目标环境已有 2 条本地记录，导入 envA 区间 [2,5] 共 4 条的包");

        ArchiveImportResult result = b.archiveService().importArchive(archive);
        List<AuditEvent> all = b.auditService().readAll();
        log.info("[判定依据] outcome={}, mergedCount={}, totalEvents={}, 实际链大小={}, 校验={}",
                result.outcome(), result.mergedCount(), result.totalEvents(), all.size(),
                b.auditService().verify().valid());
        assertEquals(ArchiveImportOutcome.IMPORTED, result.outcome());
        assertEquals(4, result.mergedCount());
        assertEquals(6, result.totalEvents());
        assertEquals(6, all.size(), "导入的记录必须能在本环境查到");
        assertTrue(b.auditService().verify().valid(), "并入后整体校验仍须通过");

        // 导入的记录成为本环境自己的记录：业务字段原样、事件 ID 带来源前缀、序号接在本地链尾
        AuditEvent first = all.get(2);
        assertEquals("envA:evt-2", first.eventId());
        assertEquals("actor2", first.actor());
        assertEquals(3, first.seq());
        assertEquals(all.get(1).hash(), first.prevHash(), "并入记录必须接在本地链尾之后");

        // 能接着往后写
        b.events().appendWithId("local-3", "local3", "L", "r", AuditTestSupport.payload());
        assertEquals(7, b.auditService().readAll().size());
        assertEquals(7, b.auditService().readAll().get(6).seq());
        assertTrue(b.auditService().verify().valid(), "导入后继续追加，整体校验仍须通过");
    }

    @Test
    void importIntoEmptyEnvironmentWorks() {
        var a = sourceEnv(3);
        Path archive = exportFrom(a, 1, 3);
        var b = destEnv(); // 全空环境
        log.info("[输入] 把 3 条记录的包导入全空环境");

        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, mergedCount={}, totalEvents={}, 校验={}",
                r.outcome(), r.mergedCount(), r.totalEvents(), b.auditService().verify().valid());
        assertEquals(ArchiveImportOutcome.IMPORTED, r.outcome());
        assertEquals(3, r.mergedCount());
        assertEquals(3, b.auditService().readAll().size());
        assertEquals(1, b.auditService().readAll().get(0).seq(), "空环境并入后从 seq=1 开始");
        assertTrue(b.auditService().verify().valid());

        b.events().appendWithId("after-import", "x", "L", "r", AuditTestSupport.payload());
        assertEquals(4, b.auditService().readAll().size());
        assertTrue(b.auditService().verify().valid(), "空环境导入后可继续追加且校验通过");
    }

    @Test
    void repeatedImportIsIdempotent() throws Exception {
        var a = sourceEnv(4);
        Path archive = exportFrom(a, 1, 4);
        var b = destEnv();
        b.events().appendWithId("local-1", "local", "L", "r", AuditTestSupport.payload());

        ArchiveImportResult r1 = b.archiveService().importArchive(archive);
        byte[] afterFirst = chainBytes(dir.resolve("b"));
        ArchiveImportResult r2 = b.archiveService().importArchive(archive);
        ArchiveImportResult r3 = b.archiveService().importArchive(archive);
        log.info("[输入] 同一包连续导入 3 次");
        log.info("[判定依据] outcomes=[{},{},{}], 链大小={}, 首次后链字节不变={}",
                r1.outcome(), r2.outcome(), r3.outcome(), b.auditService().readAll().size(),
                Arrays.equals(afterFirst, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.IMPORTED, r1.outcome());
        assertEquals(ArchiveImportOutcome.DUPLICATE_IGNORED, r2.outcome());
        assertEquals(ArchiveImportOutcome.DUPLICATE_IGNORED, r3.outcome());
        assertEquals(0, r2.mergedCount(), "重复导入不得新增记录");
        assertEquals(5, b.auditService().readAll().size(), "重复导入不得重复堆记录");
        assertTrue(Arrays.equals(afterFirst, chainBytes(dir.resolve("b"))), "重复导入不得改动链");
        assertTrue(b.auditService().verify().valid());
    }

    @Test
    void concurrentImportOfSamePackageMergesExactlyOnce() throws Exception {
        var a = sourceEnv(4);
        Path archive = exportFrom(a, 1, 4);
        var b = destEnv();
        b.events().appendWithId("local-1", "local", "L", "r", AuditTestSupport.payload());

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch go = new CountDownLatch(1);
        ConcurrentLinkedQueue<ArchiveImportResult> results = new ConcurrentLinkedQueue<>();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                try {
                    go.await();
                    results.add(b.archiveService().importArchive(archive));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        ready.await();
        go.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        long imported = results.stream().filter(r -> r.outcome() == ArchiveImportOutcome.IMPORTED).count();
        long duplicates = results.stream()
                .filter(r -> r.outcome() == ArchiveImportOutcome.DUPLICATE_IGNORED).count();
        log.info("[输入] {} 个线程同时导入同一个包", threads);
        log.info("[判定依据] IMPORTED={}, DUPLICATE_IGNORED={}, 链大小={}, 校验={}",
                imported, duplicates, b.auditService().readAll().size(),
                b.auditService().verify().valid());
        assertEquals(threads, results.size());
        assertEquals(1, imported, "并发导入同一个包只能有一个真正并入");
        assertEquals(threads - 1, duplicates, "其余并发导入必须幂等忽略");
        assertEquals(5, b.auditService().readAll().size(), "并发导入不得重复堆记录");
        assertTrue(b.auditService().verify().valid(), "并发导入后链必须完好");
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
        b.events().appendWithId("local-1", "local", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));

        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, primaryReason={}, 链字节不变={}",
                r.outcome(), r.verification().primaryReason(),
                Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.INTEGRITY_REJECTED, r.outcome());
        assertEquals(1, b.auditService().readAll().size(), "拒绝导入本地零改动");
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))));
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
        assertEquals(ArchiveFailureReason.UNTRUSTED_ENVIRONMENT, r.verification().primaryReason());
        assertEquals(0, b.auditService().readAll().size(), "未信任来源本地零改动");
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))));
    }

    @Test
    void missingPackageFileIsStorageFailedAndRetryable() throws Exception {
        var b = destEnv();
        b.events().appendWithId("local-1", "local", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));
        Path missing = dir.resolve("no-such-archive.json");
        log.info("[输入] 导入一个根本不存在的包文件");

        ArchiveImportResult r = b.archiveService().importArchive(missing);
        log.info("[判定依据] outcome={}, primaryReason={}, 链字节不变={}",
                r.outcome(), r.verification().primaryReason(),
                Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.STORAGE_FAILED, r.outcome(),
                "文件不存在属于接收侧问题，应可重试而非判成包损坏");
        assertEquals(ArchiveFailureReason.PACKAGE_UNREADABLE, r.verification().primaryReason());
        assertEquals(1, b.auditService().readAll().size());
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))));
    }

    @Test
    void storageFailureIsDistinctAndRetryableWithZeroLocalEffect() throws Exception {
        var a = sourceEnv(3);
        Path archive = exportFrom(a, 1, 3);
        var b = destEnv();
        b.events().appendWithId("local-1", "local", "L", "r", AuditTestSupport.payload());
        byte[] before = chainBytes(dir.resolve("b"));

        // 制造存储故障：链文件重写所需的临时路径被同名目录占用，写入必失败
        Path blockedTmp = dir.resolve("b").resolve("events.jsonl.tmp");
        Files.createDirectories(blockedTmp);
        log.info("[输入] 链文件临时路径被占用（模拟存储故障）后导入");

        ArchiveImportResult failed = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, 链字节不变={}, 链大小={}",
                failed.outcome(), Arrays.equals(before, chainBytes(dir.resolve("b"))),
                b.auditService().readAll().size());
        assertEquals(ArchiveImportOutcome.STORAGE_FAILED, failed.outcome());
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))), "存储失败时本地零改动");
        assertEquals(1, b.auditService().readAll().size());
        assertTrue(b.auditService().verify().valid());

        // 故障恢复后重试成功（包本身没问题）
        Files.delete(blockedTmp);
        ArchiveImportResult retry = b.archiveService().importArchive(archive);
        log.info("[判定依据] 恢复后重试: outcome={}, mergedCount={}, 校验={}",
                retry.outcome(), retry.mergedCount(), b.auditService().verify().valid());
        assertEquals(ArchiveImportOutcome.IMPORTED, retry.outcome());
        assertEquals(4, b.auditService().readAll().size());
        assertTrue(b.auditService().verify().valid());
    }

    @Test
    void prunedRangeReimportIsRejectedWithDistinctOutcome() throws Exception {
        var a = sourceEnv(10);
        Path archive = exportFrom(a, 1, 5);
        int removed = a.auditService().retainByBatch(1, 5); // 清理掉 [1,5]，链头变为 seq=6
        assertEquals(5, removed);
        byte[] before = chainBytes(dir.resolve("a"));
        log.info("[输入] 本环境导出的 [1,5] 区间已被保留期清理，再把该包导回本环境");

        ArchiveImportResult r = a.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, detail={}, 链字节不变={}",
                r.outcome(), r.detail(), Arrays.equals(before, chainBytes(dir.resolve("a"))));
        assertEquals(ArchiveImportOutcome.PRUNED_RANGE, r.outcome(),
                "已清理区间不得借导入复活，且必须有独立结论");
        assertEquals(5, a.auditService().readAll().size());
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("a"))), "本地零改动");
        assertTrue(a.auditService().verify().valid());
    }

    @Test
    void sameEnvironmentReimportWhileRecordsPresentIsDuplicate() throws Exception {
        var a = sourceEnv(5);
        Path archive = exportFrom(a, 1, 5);
        byte[] before = chainBytes(dir.resolve("a"));
        log.info("[输入] 把本环境导出的包导回本环境（记录仍在本地链上）");

        ArchiveImportResult r = a.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, mergedCount={}, 链字节不变={}",
                r.outcome(), r.mergedCount(), Arrays.equals(before, chainBytes(dir.resolve("a"))));
        assertEquals(ArchiveImportOutcome.DUPLICATE_IGNORED, r.outcome(),
                "本环境记录仍在链上时导回必须幂等忽略，不得复制出自己的副本");
        assertEquals(5, a.auditService().readAll().size());
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("a"))));
        assertTrue(a.auditService().verify().valid());
    }

    @Test
    void foreignEventIdCollisionDoesNotConflict() {
        var a = sourceEnv(4); // 包内事件 id 为 evt-1..evt-4
        Path archive = exportFrom(a, 1, 4);
        var b = destEnv();
        // 目标环境本地也有 evt-1..evt-3（不同环境各自编号，id 撞车很常见）
        b.events().append("localActor1", "L", "r", AuditTestSupport.payload());
        b.events().append("localActor2", "L", "r", AuditTestSupport.payload());
        b.events().append("localActor3", "L", "r", AuditTestSupport.payload());
        log.info("[输入] 目标环境本地事件 ID 与包内事件 ID 撞车（evt-1..evt-3）");

        ArchiveImportResult r = b.archiveService().importArchive(archive);
        List<AuditEvent> all = b.auditService().readAll();
        log.info("[判定依据] outcome={}, totalEvents={}, 链大小={}, 校验={}",
                r.outcome(), r.totalEvents(), all.size(), b.auditService().verify().valid());
        assertEquals(ArchiveImportOutcome.IMPORTED, r.outcome(),
                "跨环境的 ID 撞车不得误判为冲突");
        assertEquals(7, all.size());
        assertEquals("evt-1", all.get(0).eventId(), "本地原有记录保持原样");
        assertEquals("envA:evt-1", all.get(3).eventId(), "并入记录带来源前缀，与本地记录区分");
        assertTrue(b.auditService().verify().valid());
    }

    @Test
    void brokenLocalChainIsLocalChainInvalidWithZeroEffect() throws Exception {
        var a = sourceEnv(3);
        Path archive = exportFrom(a, 1, 3);
        var b = destEnv();
        b.events().appendWithId("local-1", "local", "L", "r", AuditTestSupport.payload());
        // 破坏本地链：改写链文件中唯一一条记录的 actor
        Path chainFile = dir.resolve("b").resolve("events.jsonl");
        String content = Files.readString(chainFile).replace("local", "hacked");
        Files.writeString(chainFile, content);
        byte[] before = chainBytes(dir.resolve("b"));
        log.info("[输入] 本地链已被篡改（校验不通过）时导入");

        ArchiveImportResult r = b.archiveService().importArchive(archive);
        log.info("[判定依据] outcome={}, detail={}, 链字节不变={}",
                r.outcome(), r.detail(), Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.LOCAL_CHAIN_INVALID, r.outcome(),
                "本地链破损必须是独立结论，不得并入也不得误报包问题");
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))), "本地零改动");
    }

    @Test
    void conflictingPackageIsEventConflictWithZeroLocalEffect() throws Exception {
        var a = sourceEnv(3);
        Path archive1 = exportFrom(a, 1, 3);
        var b = destEnv();
        assertEquals(ArchiveImportOutcome.IMPORTED, b.archiveService().importArchive(archive1).outcome());
        byte[] before = chainBytes(dir.resolve("b"));

        // 另一个同样来自 envA（同密钥签发、核验有效）但 evt-1 内容不同的包
        var a2 = AuditTestSupport.harness(dir.resolve("a2"), List.of("password"),
                "envA", "key-A", Map.of());
        a2.events().appendWithId("evt-1", "DIFFERENT", "A1", "r", AuditTestSupport.payload());
        a2.events().appendWithId("evt-2", "actor2", "A2", "r", AuditTestSupport.payload());
        Path archive2 = exportFrom(a2, 1, 2);
        log.info("[输入] 导入同环境另一份包，其中 evt-1 内容与已并入记录矛盾");

        ArchiveImportResult r = b.archiveService().importArchive(archive2);
        log.info("[判定依据] outcome={}, detail={}, 链字节不变={}",
                r.outcome(), r.detail(), Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertEquals(ArchiveImportOutcome.EVENT_CONFLICT, r.outcome(),
                "同一事件 ID 内容矛盾必须是独立结论");
        assertEquals(3, b.auditService().readAll().size(), "冲突拒绝本地零改动");
        assertTrue(Arrays.equals(before, chainBytes(dir.resolve("b"))));
        assertTrue(b.auditService().verify().valid());
    }

    @Test
    void exportWithoutArchiveKeyIsConfigurationMissing() {
        var noKey = AuditTestSupport.harness(dir.resolve("nokey"), List.of("password"),
                "envX", "", Map.of());
        noKey.events().appendWithId("e1", "actor", "A", "r", AuditTestSupport.payload());
        log.info("[输入] 未配置 audit.archive-key 的环境发起归档导出");

        ArchiveExportResult r = noKey.archiveService().exportRange(1, 1);
        log.info("[判定依据] outcome={}, detail={}", r.outcome(), r.detail());
        assertEquals(ArchiveExportOutcome.CONFIGURATION_MISSING, r.outcome(),
                "缺配置必须是可区分结论，不得抛出未归类异常");
    }

    @Test
    void unexpectedInternalErrorIsClassified() {
        var a = sourceEnv(3);
        Path archive = exportFrom(a, 1, 3);

        // 手工装配一个 rewriteAll 会抛出未预料运行时异常的存储
        AuditProperties props = new AuditProperties();
        props.setDataDir(dir.resolve("broken").toString());
        props.setEnvironmentId("envB");
        props.setArchiveKey("key-B");
        props.setTrustedArchiveKeys(Map.of("envA", "key-A"));
        ObjectMapper mapper = new ObjectMapper();
        FileAuditStore store = new FileAuditStore(props, mapper) {
            @Override
            public synchronized void rewriteAll(List<AuditEvent> events) {
                throw new IllegalStateException("模拟未预料的内部错误");
            }
        };
        ChainHasher hasher = new ChainHasher();
        AuditService audit = new AuditService(store, hasher, new MaskingService(props, mapper));
        ArchiveKeyProvider keys = new ArchiveKeyProvider(props);
        ArchiveService archiveService = new ArchiveService(audit, keys, new ArchiveSigner(),
                new ArchiveVerifier(hasher, new ArchiveSigner(), keys, mapper), props, mapper);
        log.info("[输入] 存储层抛出未预料运行时异常时导入有效包");

        ArchiveImportResult r = archiveService.importArchive(archive);
        log.info("[判定依据] outcome={}, detail={}", r.outcome(), r.detail());
        assertEquals(ArchiveImportOutcome.INTERNAL_ERROR, r.outcome(),
                "未预料的内部错误必须归类为 INTERNAL_ERROR，不得冒出未归类异常");
        assertEquals(0, audit.readAll().size(), "内部错误发生在写入前，本地零改动");
    }
}
