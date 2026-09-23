package com.github.xingjianluo.auditlogintegrityjava;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import com.github.xingjianluo.auditlogintegrityjava.service.EventInput;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 存储异常语义与崩溃恢复：
 * 1) 存储目录不可用时，追加以 AuditStoreException 显式失败；
 * 2) 链文件末尾出现未落盘完成的半截行，重启时截断并保持校验通过；
 * 3) “事件已追加但锚点未刷新”的崩溃窗口，重启时自动对账前滚；
 * 4) 按批次清理中途制造半截事件行，重启恢复后清理结论一致。
 */
class StorageFailureAndRecoveryTest {

    private static final Logger log = LoggerFactory.getLogger(StorageFailureAndRecoveryTest.class);

    @TempDir
    Path dir;

    @Test
    void unwritableStorageRaisesAuditStoreException() {
        Path blocked = dir.resolve("blocked");
        try {
            Files.createFile(blocked); // 占用同名路径，使其无法作为目录
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        log.info("[输入] 以普通文件路径作为 dataDir: {}", blocked);
        assertThrows(AuditStoreException.class, () -> AuditTestSupport.harness(blocked));
        log.info("[判定依据] 构造存储时抛出 AuditStoreException，失败原因可解释");
    }

    @Test
    void partialLastLineIsTruncatedOnRestart() throws Exception {
        var h = AuditTestSupport.harness(dir);
        h.events().append("a", "A", "r", AuditTestSupport.payload());
        h.events().append("b", "B", "r", AuditTestSupport.payload());

        Path file = dir.resolve("events.jsonl");
        Files.writeString(file, Files.readString(file) + "{\"eventId\":\"ghost\",incomplete");
        log.info("[输入] 在链文件末尾追加一条无换行符的半截 JSON（模拟写入中途崩溃）");

        var reopened = AuditTestSupport.harness(dir);
        List<AuditEvent> events = reopened.auditService().readAll();
        VerificationReport report = reopened.auditService().verify();
        log.info("[判定依据] 恢复后条数={}, eventIds={}, 校验={}",
                events.size(), events.stream().map(AuditEvent::eventId).toList(), report.valid());
        assertEquals(2, events.size());
        assertTrue(report.valid());
    }

    @Test
    void anchorLaggingBehindFileIsReconciledOnRestart() throws Exception {
        var h = AuditTestSupport.harness(dir);
        h.events().append("a", "A", "r", AuditTestSupport.payload());
        h.events().append("b", "B", "r", AuditTestSupport.payload());

        // 直接再追加一条到链文件却不更新锚点，模拟 append 成功、锚点写前崩溃
        AuditEvent tail = h.auditService().readAll().get(1);
        AuditEvent ghost = new AuditEvent("ghost", tail.seq() + 1, System.currentTimeMillis(),
                "c", "C", "r", AuditTestSupport.payload(), 1, tail.hash(),
                h.hasher().computeHash(new AuditEvent("ghost", tail.seq() + 1,
                        System.currentTimeMillis(), "c", "C", "r",
                        AuditTestSupport.payload(), 1, tail.hash(), "")));
        h.store().append(ghost);
        log.info("[输入] 链文件有 3 条但锚点停在 tailSeq=2（模拟追加后崩溃）");

        var reopened = AuditTestSupport.harness(dir);
        VerificationReport report = reopened.auditService().verify();
        log.info("[判定依据] 重开校验={} tailSeq={} scanned={}（锚点自动前滚）",
                report.valid(), report.tailSeq(), report.scannedEntries());
        assertTrue(report.valid());
        assertEquals(3, report.scannedEntries());
        assertEquals(3, report.tailSeq());

        // 对账后继续写入，序号与链节正确
        reopened.events().appendWithId("after", "d", "D", "r", AuditTestSupport.payload());
        VerificationReport after = reopened.auditService().verify();
        log.info("[判定依据] 对账后续写一条, 校验={} tailSeq={}", after.valid(), after.tailSeq());
        assertTrue(after.valid());
        assertEquals(4, after.tailSeq());
    }

    @Test
    void partialLineAfterPruningRecoversConsistently() throws Exception {
        var h = AuditTestSupport.harness(dir);
        for (int i = 1; i <= 4; i++) {
            h.events().appendWithId("p" + i, "u", "A", "r", AuditTestSupport.payload());
        }
        int removed = h.auditService().retainByBatch(1, 2); // 保留 p3,p4
        Path file = dir.resolve("events.jsonl");
        Files.writeString(file, Files.readString(file) + "{\"partial\":");
        log.info("[输入] 清理后链末尾再制造半截行, 已删除 {} 条", removed);

        var reopened = AuditTestSupport.harness(dir);
        List<AuditEvent> events = reopened.auditService().readAll();
        VerificationReport report = reopened.auditService().verify();
        log.info("[判定依据] 恢复后 eventIds={}, 校验={}",
                events.stream().map(AuditEvent::eventId).toList(), report.valid());
        assertEquals(List.of("p3", "p4"), events.stream().map(AuditEvent::eventId).toList());
        assertTrue(report.valid());
    }
}
