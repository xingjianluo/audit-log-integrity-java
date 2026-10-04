package com.github.xingjianluo.auditlogintegrityjava;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveKeyService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerifier;
import com.github.xingjianluo.auditlogintegrityjava.archive.ImportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ImportResult;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingService;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import com.github.xingjianluo.auditlogintegrityjava.storage.FileAuditStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 归档导入：幂等、原子、与本地记录并存、失败结论可区分。
 */
class ArchiveImportTest {

    private static final Logger log = LoggerFactory.getLogger(ArchiveImportTest.class);
    private final ObjectMapper mapper = new ObjectMapper();

    @TempDir
    Path dir;

    private AuditTestSupport.Harness sourceEnv(int events) {
        AuditTestSupport.Harness h = AuditTestSupport.harness(dir.resolve("src-" + System.nanoTime()));
        for (int i = 1; i <= events; i++) {
            h.events().append("actor" + i, "ACTION" + i, "res" + i,
                    AuditTestSupport.payload("password", "secret" + i));
        }
        return h;
    }

    private byte[] export(AuditTestSupport.Harness h, long from, long to) {
        ArchiveExportResult r = h.archiveExporter().exportRange(from, to);
        assertEquals(com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportOutcome.EXPORTED,
                r.outcome());
        return r.packageBytes();
    }

    @Test
    void importIntoEmptyEnvironmentCoexistsAndVerifies() {
        AuditTestSupport.Harness src = sourceEnv(5);
        byte[] pkg = export(src, 2, 4);
        byte[] srcKey = src.archiveKeys().publicKeyBytes();

        AuditTestSupport.Harness dst = AuditTestSupport.harness(dir.resolve("dst"));
        ImportResult r1 = dst.archiveImporter().importPackage(pkg, srcKey);
        log.info("[输入] 空环境导入区间[2,4] -> 结论={}, 新增={}", r1.outcome(), r1.importedCount());
        assertEquals(ImportOutcome.IMPORTED, r1.outcome());
        assertEquals(3, r1.importedCount());
        assertTrue(dst.auditService().verify().valid());

        List<AuditEvent> all = dst.auditService().readAll();
        assertEquals(3, all.size());
        assertEquals("imp-", all.get(0).eventId().substring(0, 4));
        assertTrue(all.get(0).payload().get("_importOriginalEvent").contains("actor2"));
        assertEquals(src.archiveKeys().environmentId(), all.get(0).payload().get("_importSourceEnv"));
        log.info("[判定依据] 导入后本地链 {} 条，校验={}, 首条payload含原始事件={}",
                all.size(), dst.auditService().verify().valid(),
                all.get(0).payload().get("_importOriginalEvent").contains("actor2"));
    }

    @Test
    void repeatedImportIsIdempotent() {
        AuditTestSupport.Harness src = sourceEnv(5);
        byte[] pkg = export(src, 1, 5);
        byte[] srcKey = src.archiveKeys().publicKeyBytes();
        AuditTestSupport.Harness dst = AuditTestSupport.harness(dir.resolve("dst"));

        ImportResult r1 = dst.archiveImporter().importPackage(pkg, srcKey);
        ImportResult r2 = dst.archiveImporter().importPackage(pkg, srcKey);
        ImportResult r3 = dst.archiveImporter().importPackage(pkg, srcKey);
        log.info("[输入] 同一包连续导入 3 次 -> 结论依次为 {}, {}, {}; 链规模={}",
                r1.outcome(), r2.outcome(), r3.outcome(), dst.auditService().readAll().size());
        assertEquals(ImportOutcome.IMPORTED, r1.outcome());
        assertEquals(ImportOutcome.ALREADY_IMPORTED, r2.outcome());
        assertEquals(ImportOutcome.ALREADY_IMPORTED, r3.outcome());
        assertEquals(5, dst.auditService().readAll().size());
        assertTrue(dst.auditService().verify().valid());
    }

    @Test
    void importCoexistsWithExistingLocalRecords() {
        AuditTestSupport.Harness src = sourceEnv(4);
        byte[] pkg = export(src, 1, 4);
        byte[] srcKey = src.archiveKeys().publicKeyBytes();

        AuditTestSupport.Harness dst = AuditTestSupport.harness(dir.resolve("dst"));
        dst.events().append("local1", "ACT", "r", AuditTestSupport.payload("k", "v"));
        dst.events().append("local2", "ACT", "r", AuditTestSupport.payload("k", "v"));
        List<String> beforeIds = dst.auditService().readAll().stream().map(AuditEvent::eventId).toList();

        ImportResult r = dst.archiveImporter().importPackage(pkg, srcKey);
        List<AuditEvent> after = dst.auditService().readAll();
        log.info("[输入] 已有 {} 条本地记录的环境导入 4 条 -> 结论={}, 总量={}",
                beforeIds.size(), r.outcome(), after.size());
        assertEquals(ImportOutcome.IMPORTED, r.outcome());
        assertEquals(6, after.size());
        assertEquals(beforeIds, after.subList(0, 2).stream().map(AuditEvent::eventId).toList());
        assertTrue(dst.auditService().verify().valid());
    }

    @Test
    void tamperedPackageIsPackageInvalidWithZeroLocalChange() {
        AuditTestSupport.Harness src = sourceEnv(4);
        byte[] pkg = export(src, 1, 4);
        byte[] broken;
        try {
            ObjectNode root = (ObjectNode) mapper.readTree(pkg);
            ((ObjectNode) ((ArrayNode) root.get("events")).get(0)).put("actor", "forged");
            broken = mapper.writeValueAsBytes(root);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        AuditTestSupport.Harness dst = AuditTestSupport.harness(dir.resolve("dst"));
        dst.events().append("local", "ACT", "r", AuditTestSupport.payload("k", "v"));
        ImportResult r = dst.archiveImporter().importPackage(broken, src.archiveKeys().publicKeyBytes());
        log.info("[输入] 内容被篡改的包导入 -> 结论={}, 包核验结论={}",
                r.outcome(), r.verification().conclusion());
        assertEquals(ImportOutcome.PACKAGE_INVALID, r.outcome());
        assertEquals(1, dst.auditService().readAll().size());
        assertTrue(dst.auditService().verify().valid());
    }

    /** 追加到第 failAfter 条之后抛存储异常的存储。 */
    static class FailingStore extends FileAuditStore {
        volatile int failAfter = Integer.MAX_VALUE;
        int appended;

        FailingStore(AuditProperties props, ObjectMapper mapper) {
            super(props, mapper);
        }

        @Override
        public synchronized void append(AuditEvent event) {
            if (++appended > failAfter) {
                throw new AuditStoreException("模拟存储故障: seq=" + event.seq());
            }
            super.append(event);
        }
    }

    @Test
    void storageFailureMidImportRollsBackAndIsRetryable() {
        AuditTestSupport.Harness src = sourceEnv(5);
        byte[] pkg = export(src, 1, 5);
        byte[] srcKey = src.archiveKeys().publicKeyBytes();

        // 手工装配一个“第 2 条后必失败”的接收环境
        Path dstDir = dir.resolve("dst-failing");
        AuditProperties props = new AuditProperties();
        props.setDataDir(dstDir.toString());
        ObjectMapper om = new ObjectMapper();
        ChainHasher hasher = new ChainHasher();
        FailingStore store = new FailingStore(props, om);
        MaskingService masking = new MaskingService(props, om);
        AuditService audit = new AuditService(store, hasher, masking);
        ArchiveImportService importer = new ArchiveImportService(
                new ArchiveVerifier(hasher), audit, om);

        store.failAfter = 2;
        ImportResult r1 = importer.importPackage(pkg, srcKey);
        log.info("[输入] 导入 5 条但存储在第 2 条后故障 -> 结论={}, 依据={}", r1.outcome(), r1.detail());
        assertEquals(ImportOutcome.IMPORT_STORAGE_FAILED, r1.outcome());
        assertEquals(0, audit.readAll().size());
        assertTrue(audit.verify().valid());
        log.info("[判定依据] 回滚后本地条数={}, 链校验={}", audit.readAll().size(), audit.verify().valid());

        // 存储恢复后重试：整体成功
        store.failAfter = Integer.MAX_VALUE;
        ImportResult r2 = importer.importPackage(pkg, srcKey);
        log.info("[输入] 存储恢复后重试导入 -> 结论={}, 新增={}", r2.outcome(), r2.importedCount());
        assertEquals(ImportOutcome.IMPORTED, r2.outcome());
        assertEquals(5, audit.readAll().size());
        assertTrue(audit.verify().valid());
    }

    @Test
    void storageFailureWithExistingRecordsLeavesThemUntouched() {
        AuditTestSupport.Harness src = sourceEnv(4);
        byte[] pkg = export(src, 1, 4);
        byte[] srcKey = src.archiveKeys().publicKeyBytes();

        Path dstDir = dir.resolve("dst-failing2");
        AuditProperties props = new AuditProperties();
        props.setDataDir(dstDir.toString());
        ObjectMapper om = new ObjectMapper();
        ChainHasher hasher = new ChainHasher();
        FailingStore store = new FailingStore(props, om);
        MaskingService masking = new MaskingService(props, om);
        AuditService audit = new AuditService(store, hasher, masking);
        ArchiveImportService importer = new ArchiveImportService(
                new ArchiveVerifier(hasher), audit, om);

        audit.append(new com.github.xingjianluo.auditlogintegrityjava.service.EventInput(
                "local-1", "a", "ACT", "r", AuditTestSupport.payload("k", "v")));
        audit.append(new com.github.xingjianluo.auditlogintegrityjava.service.EventInput(
                "local-2", "a", "ACT", "r", AuditTestSupport.payload("k", "v")));
        List<AuditEvent> before = audit.readAll();

        store.failAfter = 3; // 2 条本地 + 1 条导入后故障
        ImportResult r = importer.importPackage(pkg, srcKey);
        log.info("[输入] 已有 2 条本地记录，导入第 1 条后存储故障 -> 结论={}", r.outcome());
        assertEquals(ImportOutcome.IMPORT_STORAGE_FAILED, r.outcome());
        assertEquals(before, audit.readAll());
        assertTrue(audit.verify().valid());
        log.info("[判定依据] 回滚后本地记录与导入前完全一致: {}", before.equals(audit.readAll()));
    }

    @Test
    void brokenLocalChainRefusesImport() throws Exception {
        AuditTestSupport.Harness src = sourceEnv(3);
        byte[] pkg = export(src, 1, 3);
        byte[] srcKey = src.archiveKeys().publicKeyBytes();

        AuditTestSupport.Harness dst = AuditTestSupport.harness(dir.resolve("dst"));
        dst.events().append("local", "ACT", "r", AuditTestSupport.payload("k", "v"));
        // 篡改本地链
        Path eventsFile = dst.dir().resolve("events.jsonl");
        List<String> lines = Files.readAllLines(eventsFile);
        ObjectNode node = (ObjectNode) mapper.readTree(lines.get(0));
        node.put("actor", "intruder");
        Files.write(eventsFile, List.of(mapper.writeValueAsString(node)));

        ImportResult r = dst.archiveImporter().importPackage(pkg, srcKey);
        log.info("[输入] 本地链被篡改后导入 -> 结论={}, 依据={}", r.outcome(), r.detail());
        assertEquals(ImportOutcome.LOCAL_CHAIN_INVALID, r.outcome());
        assertEquals(1, dst.auditService().readAll().size());
    }
}
