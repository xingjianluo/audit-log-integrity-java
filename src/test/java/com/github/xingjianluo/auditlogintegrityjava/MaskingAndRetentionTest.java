package com.github.xingjianluo.auditlogintegrityjava;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 落盘脱敏不可逆、策略版本化与历史可复现、按批次保留后完整性。
 */
class MaskingAndRetentionTest {

    private static final Logger log = LoggerFactory.getLogger(MaskingAndRetentionTest.class);

    @TempDir
    Path dir;

    @Test
    void sensitiveFieldsAreMaskedOnDiskIrreversibly() throws Exception {
        var h = AuditTestSupport.harness(dir);
        String secret = "p@ssw0rd-123";
        log.info("[输入] 追加含敏感字段事件, password={}, idCard={}", secret, "110101199001011234");
        h.events().appendWithId("s1", "alice", "LOGIN", "host",
                AuditTestSupport.payload("password", secret, "idCard", "110101199001011234",
                        "ip", "10.0.0.1"));

        String raw = Files.readString(dir.resolve("events.jsonl"));
        AuditEvent stored = h.auditService().readAll().get(0);
        log.info("[判定依据] 落盘原文是否含明文={}, 脱敏字段值={}, 非敏感字段保留={}",
                raw.contains(secret), stored.payload().get("password"), stored.payload().get("ip"));
        assertFalse(raw.contains(secret), "明文密码不得出现在磁盘文件中");
        assertFalse(raw.contains("110101199001011234"));
        assertEquals("***REDACTED***", stored.payload().get("password"));
        assertEquals("***REDACTED***", stored.payload().get("idCard"));
        assertEquals("10.0.0.1", stored.payload().get("ip"));
        assertEquals(1, stored.policyVersion());
        assertTrue(h.auditService().verify().valid());
    }

    @Test
    void policyUpdateOnlyAffectsLaterEventsAndHistoryStaysReproducible() {
        var h = AuditTestSupport.harness(dir);
        h.events().appendWithId("old-1", "alice", "A", "r",
                AuditTestSupport.payload("email", "a@example.com", "password", "x"));
        AuditEvent before = h.auditService().readAll().get(0);

        log.info("[输入] 策略变更: 新增敏感字段 email，版本 1 -> 2");
        MaskingPolicy v2 = h.maskingService().updatePolicy(
                Set.of("password", "idCard", "phone", "token", "email"), "***REDACTED***");
        assertEquals(2, v2.version());

        h.events().appendWithId("new-1", "bob", "B", "r",
                AuditTestSupport.payload("email", "b@example.com", "password", "y"));
        List<AuditEvent> all = h.auditService().readAll();
        AuditEvent old = all.get(0);
        AuditEvent fresh = all.get(1);

        log.info("[判定依据] 旧事件 email 明文仍在={} policyVersion={}; 新事件 email 被掩码={} policyVersion={}",
                old.payload().get("email"), old.policyVersion(),
                fresh.payload().get("email"), fresh.policyVersion());
        assertEquals("a@example.com", old.payload().get("email"));
        assertEquals(1, old.policyVersion());
        assertEquals("***REDACTED***", fresh.payload().get("email"));
        assertEquals(2, fresh.policyVersion());
        assertEquals(before, old, "历史事件记录在策略变更后必须保持字节级不变");
        assertTrue(h.auditService().verify().valid());
    }

    @Test
    void batchRetentionRemovesOldBatchesAndKeepsIntegrity() {
        var h = AuditTestSupport.harness(dir);
        int n = 5;
        for (int i = 1; i <= n; i++) {
            h.events().appendWithId("e" + i, "u", "ACT", "r", AuditTestSupport.payload("i", String.valueOf(i)));
        }
        log.info("[输入] 共 {} 条；按批次保留 keepBatches=1, batchSize=2（保留最新 2 条）", n);
        int removed = h.auditService().retainByBatch(1, 2);

        List<AuditEvent> remaining = h.auditService().readAll();
        VerificationReport report = h.auditService().verify();
        log.info("[判定依据] 删除={}, 剩余 eventIds={}, 剩余 seq={}, 校验={}, 锚点 head/tail={}/{}",
                removed, remaining.stream().map(AuditEvent::eventId).toList(),
                remaining.stream().map(AuditEvent::seq).toList(), report.valid(),
                report.headSeq(), report.tailSeq());
        assertEquals(3, removed);
        assertEquals(List.of("e4", "e5"), remaining.stream().map(AuditEvent::eventId).toList());
        assertEquals(4L, report.headSeq());
        assertEquals(5L, report.tailSeq());
        assertTrue(report.valid());
    }

    @Test
    void retentionSurvivesRestartAndLaterAppendsStillVerify() {
        var h1 = AuditTestSupport.harness(dir);
        for (int i = 1; i <= 6; i++) {
            h1.events().appendWithId("r" + i, "u", "ACT", "x", AuditTestSupport.payload());
        }
        h1.auditService().retainByBatch(2, 2); // 保留最新 4 条: r3..r6
        log.info("[输入] 清理后模拟进程重启，重新打开同一目录并继续追加 r7");

        var h2 = AuditTestSupport.harness(dir);
        VerificationReport reopen = h2.auditService().verify();
        h2.events().appendWithId("r7", "u", "ACT", "x", AuditTestSupport.payload());
        VerificationReport afterAppend = h2.auditService().verify();
        log.info("[判定依据] 重开校验={} 区间=[{},{}]; 追加后校验={} tailSeq={}",
                reopen.valid(), reopen.headSeq(), reopen.tailSeq(),
                afterAppend.valid(), afterAppend.tailSeq());
        assertTrue(reopen.valid());
        assertTrue(afterAppend.valid());
        assertEquals(7L, afterAppend.tailSeq());
        assertEquals(3L, afterAppend.headSeq());
    }

    @Test
    void keepMoreThanExistIsNoOp() {
        var h = AuditTestSupport.harness(dir);
        for (int i = 1; i <= 3; i++) {
            h.events().appendWithId("k" + i, "u", "A", "r", AuditTestSupport.payload());
        }
        int removed = h.auditService().retainByBatch(10, 10);
        log.info("[判定依据] 保留窗口大于现有量时删除条数={}, 校验={}", removed,
                h.auditService().verify().valid());
        assertEquals(0, removed);
        assertEquals(3, h.auditService().readAll().size());
        assertTrue(h.auditService().verify().valid());
    }
}
