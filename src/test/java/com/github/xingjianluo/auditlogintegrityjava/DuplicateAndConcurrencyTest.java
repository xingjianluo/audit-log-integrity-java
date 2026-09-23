package com.github.xingjianluo.auditlogintegrityjava;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import com.github.xingjianluo.auditlogintegrityjava.service.DuplicateEventException;
import com.github.xingjianluo.auditlogintegrityjava.service.EventInput;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 幂等重复提交（串行/并发）与高并发写入下的链连续性。
 */
class DuplicateAndConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(DuplicateAndConcurrencyTest.class);

    @TempDir
    Path dir;

    @Test
    void sameEventSubmittedTwiceCreatesOneRecord() {
        var h = AuditTestSupport.harness(dir);
        EventInput first = new EventInput("dup-1", "alice", "LOGIN", "host-1",
                AuditTestSupport.payload("password", "p@ss"));
        log.info("[输入] 同一 EventInput 连续提交两次: eventId=dup-1");
        AuditEvent e1 = h.auditService().append(first);
        AuditEvent e2 = h.auditService().append(first);

        List<AuditEvent> all = h.auditService().readAll();
        log.info("[判定依据] 返回事件同一对象值={}, 链上记录数={}", e1.equals(e2), all.size());
        assertEquals(1, all.size());
        assertEquals(e1, e2);
        assertTrue(h.auditService().verify().valid());
    }

    @Test
    void sameEventWithDifferentIdentityIsRejected() {
        var h = AuditTestSupport.harness(dir);
        h.auditService().append(new EventInput("dup-2", "alice", "LOGIN", "host-1",
                AuditTestSupport.payload()));
        log.info("[输入] 相同 eventId=dup-2 但 actor 改为 bob 再次提交");
        assertThrows(DuplicateEventException.class, () -> h.auditService()
                .append(new EventInput("dup-2", "bob", "LOGIN", "host-1", AuditTestSupport.payload())));
        assertEquals(1, h.auditService().readAll().size());
        log.info("[判定依据] 抛出 DuplicateEventException，链仍为 1 条且校验通过: {}",
                h.auditService().verify().valid());
    }

    @Test
    void concurrentSubmissionsOfSameEventIdAreIdempotent() throws Exception {
        var h = AuditTestSupport.harness(dir);
        int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        Set<Long> seqs = ConcurrentHashMap.newKeySet();
        log.info("[输入] {} 个线程并发提交同一 eventId=same", threads);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                start.await();
                AuditEvent e = h.auditService().append(new EventInput("same", "alice", "PING",
                        "svc", AuditTestSupport.payload()));
                seqs.add(e.seq());
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        List<AuditEvent> all = h.auditService().readAll();
        VerificationReport report = h.auditService().verify();
        log.info("[判定依据] 落盘条数={}, 返回过的 seq 集合={}, 校验={}", all.size(), seqs, report.valid());
        assertEquals(1, all.size());
        assertEquals(Set.of(1L), seqs);
        assertTrue(report.valid());
    }

    @Test
    void manyConcurrentDistinctEventsProduceContinuousChain() throws Exception {
        var h = AuditTestSupport.harness(dir);
        int threads = 16;
        int perThread = 25;
        int total = threads * perThread;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        log.info("[输入] {} 线程 x {} 条不同 eventId，共 {} 条并发追加", threads, perThread, total);
        for (int t = 0; t < threads; t++) {
            final int worker = t;
            pool.submit(() -> {
                start.await();
                for (int i = 0; i < perThread; i++) {
                    h.auditService().append(new EventInput(
                            "w" + worker + "-" + i, "user" + worker, "ACT", "res",
                            AuditTestSupport.payload("i", String.valueOf(i))));
                }
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        List<AuditEvent> all = h.auditService().readAll();
        VerificationReport report = h.auditService().verify();
        long distinctIds = all.stream().map(AuditEvent::eventId).distinct().count();
        List<Long> seqs = all.stream().map(AuditEvent::seq).sorted().toList();
        boolean contiguous = IntStream.range(0, seqs.size()).allMatch(i -> seqs.get(i) == i + 1L);
        log.info("[判定依据] 落盘条数={}, 去重 eventId 数={}, seq 1..N 连续={}, 校验={}",
                all.size(), distinctIds, contiguous, report.valid());
        assertEquals(total, all.size());
        assertEquals(total, distinctIds);
        assertTrue(contiguous);
        assertTrue(report.valid());
    }
}
