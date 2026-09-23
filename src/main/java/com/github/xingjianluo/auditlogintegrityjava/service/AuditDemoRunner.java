package com.github.xingjianluo.auditlogintegrityjava.service;

import com.github.xingjianluo.auditlogintegrityjava.export.AuditExporter;
import com.github.xingjianluo.auditlogintegrityjava.export.InMemoryAuditEventReceiver;
import com.github.xingjianluo.auditlogintegrityjava.model.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.model.ExportResult;
import com.github.xingjianluo.auditlogintegrityjava.model.VerificationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Local, self-contained demonstration of the audit chain, enabled with
 * {@code --audit.demo}. It uses an isolated demo directory and walks through:
 * append -> verify -> export -> receiver failure vs integrity failure ->
 * tamper detection -> batched cleanup -> final verification.
 */
@Component
@Profile("demo")
public class AuditDemoRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AuditDemoRunner.class);

    private final AuditService auditService;
    private final AuditExporter exporter;
    private final InMemoryAuditEventReceiver receiver;
    private final AuditProperties properties;

    public AuditDemoRunner(AuditService auditService, AuditExporter exporter,
                           InMemoryAuditEventReceiver receiver, AuditProperties properties) {
        this.auditService = auditService;
        this.exporter = exporter;
        this.receiver = receiver;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        long t = System.currentTimeMillis();
        // The store is already initialized against this directory, so the demo
        // appends on top of whatever is there; use a fresh tmp dir per run via
        // -Daudit.storage-dir=... if a pristine demo is required.
        log.info("=== AUDIT CHAIN DEMO START ===");

        for (int i = 1; i <= 5; i++) {
            auditService.record(new AuditEvent("demo-" + i, t + i, "alice", "LOGIN",
                    "/account/" + i, Map.of(
                            "password", "secret-" + i, "token", "tok-" + i, "ok", "yes")));
        }
        auditService.record(new AuditEvent("demo-1", t, "alice", "LOGIN", "/x",
                Map.of("password", "again"))); // duplicate, ignored
        log.info("[demo] records after 6 submissions (1 duplicate): {}",
                auditService.allRecords().size());
        printVerify("[demo] intact chain", auditService.verify());

        ExportResult ok = exporter.exportToReceiver();
        log.info("[demo] export #1 status={} delivered={}", ok.status(), ok.deliveredCount());

        receiver.setFailing(true);
        auditService.record(new AuditEvent("demo-6", t + 6, "bob", "GRANT", "/role",
                Map.of("password", "p6")));
        ExportResult recvFail = exporter.exportToReceiver();
        log.info("[demo] export with receiver outage status={} (distinct from integrity failure)",
                recvFail.status());
        receiver.setFailing(false);

        Path logFile = Path.of(properties.getStorageDir()).resolve("audit.log");
        List<String> lines = Files.readAllLines(logFile, StandardCharsets.UTF_8);
        String tampered = lines.get(2).replace("\"action\":\"LOGIN\"", "\"action\":\"BACKDOOR\"");
        Files.write(logFile, List.of(lines.get(0), lines.get(1), tampered),
                StandardCharsets.UTF_8); // also truncates tail
        VerificationResult tamperedResult = auditService.verify();
        printVerify("[demo] after on-disk tamper + tail truncation", tamperedResult);

        ExportResult blocked = exporter.exportToReceiver();
        log.info("[demo] export blocked status={} reason={}", blocked.status(),
                blocked.verification() == null ? null : blocked.verification().reason());

        log.info("=== AUDIT CHAIN DEMO END (reason={}) ===",
                tamperedResult.reason());
    }

    private void printVerify(String label, VerificationResult r) {
        log.info("{} -> valid={} reason={} count={} basis={}",
                label, r.valid(), r.reason(), r.recordCount(), r.detail());
    }
}
