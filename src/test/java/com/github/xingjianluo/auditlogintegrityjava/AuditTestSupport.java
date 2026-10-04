package com.github.xingjianluo.auditlogintegrityjava;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveKeyService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerifier;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import com.github.xingjianluo.auditlogintegrityjava.export.ExportService;
import com.github.xingjianluo.auditlogintegrityjava.export.LocalReceiverClient;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingService;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.service.EventInput;
import com.github.xingjianluo.auditlogintegrityjava.storage.Anchor;
import com.github.xingjianluo.auditlogintegrityjava.storage.FileAuditStore;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 以临时目录装配一整套组件（不走 Spring 上下文，测试更快、互相隔离）。
 */
public final class AuditTestSupport {

    public static final class Harness {
        private final Path dir;
        private final ObjectMapper mapper;
        private final ChainHasher hasher;
        private final FileAuditStore store;
        private final MaskingService maskingService;
        private final AuditService auditService;
        private final LocalReceiverClient receiver;
        private final ExportService exportService;
        private final ArchiveKeyService archiveKeyService;
        private final ArchiveVerifier archiveVerifier;
        private final ArchiveExportService archiveExportService;
        private final ArchiveImportService archiveImportService;
        private AuditEventBuilder builder;

        Harness(Path dir, ObjectMapper mapper, ChainHasher hasher, FileAuditStore store,
                MaskingService maskingService, AuditService auditService,
                LocalReceiverClient receiver, ExportService exportService,
                ArchiveKeyService archiveKeyService, ArchiveVerifier archiveVerifier,
                ArchiveExportService archiveExportService, ArchiveImportService archiveImportService) {
            this.dir = dir;
            this.mapper = mapper;
            this.hasher = hasher;
            this.store = store;
            this.maskingService = maskingService;
            this.auditService = auditService;
            this.receiver = receiver;
            this.exportService = exportService;
            this.archiveKeyService = archiveKeyService;
            this.archiveVerifier = archiveVerifier;
            this.archiveExportService = archiveExportService;
            this.archiveImportService = archiveImportService;
        }

        public Path dir() { return dir; }
        public ObjectMapper mapper() { return mapper; }
        public ChainHasher hasher() { return hasher; }
        public FileAuditStore store() { return store; }
        public MaskingService maskingService() { return maskingService; }
        public AuditService auditService() { return auditService; }
        public LocalReceiverClient receiver() { return receiver; }
        public ExportService exportService() { return exportService; }
        public ArchiveKeyService archiveKeys() { return archiveKeyService; }
        public ArchiveVerifier archiveVerifier() { return archiveVerifier; }
        public ArchiveExportService archiveExporter() { return archiveExportService; }
        public ArchiveImportService archiveImporter() { return archiveImportService; }

        public AuditEventBuilder events() {
            if (builder == null) {
                builder = new AuditEventBuilder(auditService);
            }
            return builder;
        }
    }

    public static final class AuditEventBuilder {
        private final AuditService service;
        private int counter;

        AuditEventBuilder(AuditService service) {
            this.service = service;
        }

        public AuditEventRef append(String actor, String action, String resource,
                                    Map<String, String> payload) {
            counter++;
            String eventId = "evt-" + counter;
            service.append(new EventInput(eventId, actor, action, resource, payload));
            return new AuditEventRef(eventId);
        }

        public AuditEventRef appendWithId(String eventId, String actor, String action,
                                          String resource, Map<String, String> payload) {
            service.append(new EventInput(eventId, actor, action, resource, payload));
            return new AuditEventRef(eventId);
        }
    }

    public record AuditEventRef(String eventId) {
    }

    private AuditTestSupport() {
    }

    public static Harness harness(Path dir) {
        return harness(dir, List.of("password", "idCard", "phone", "token"));
    }

    public static Harness harness(Path dir, List<String> sensitiveFields) {
        AuditProperties props = new AuditProperties();
        props.setDataDir(dir.toString());
        props.setSensitiveFields(new ArrayList<>(sensitiveFields));
        ObjectMapper mapper = new ObjectMapper();
        ChainHasher hasher = new ChainHasher();
        FileAuditStore store = new FileAuditStore(props, mapper);
        MaskingService masking = new MaskingService(props, mapper);
        AuditService audit = new AuditService(store, hasher, masking);
        LocalReceiverClient receiver = new LocalReceiverClient();
        ExportService exporter = new ExportService(audit, receiver);
        ArchiveKeyService keyService = new ArchiveKeyService(props);
        ArchiveVerifier verifier = new ArchiveVerifier(hasher);
        ArchiveExportService archiveExporter = new ArchiveExportService(store, hasher, keyService, mapper);
        ArchiveImportService archiveImporter = new ArchiveImportService(verifier, audit, mapper);
        return new Harness(dir, mapper, hasher, store, masking, audit, receiver, exporter,
                keyService, verifier, archiveExporter, archiveImporter);
    }

    /**
     * 绕过 AuditService.append 直接构造一条完整合法链（O(n)，供大规模测试快速造数）。
     * 事件内容不经脱敏（payload 均非敏感字段），链节与锚点与正常写入一致。
     */
    public static void appendChainDirectly(Harness h, int count) {
        String prevHash = ChainHasher.GENESIS_HASH;
        String headHash = null;
        AuditEvent last = null;
        for (int i = 1; i <= count; i++) {
            AuditEvent candidate = new AuditEvent("bulk-" + i, i, 1700000000000L + i,
                    "loader", "LOAD", "bulk",
                    payload("index", String.valueOf(i)), 1, prevHash, "");
            String hash = h.hasher().computeHash(candidate);
            last = new AuditEvent(candidate.eventId(), candidate.seq(), candidate.timestamp(),
                    candidate.actor(), candidate.action(), candidate.resource(),
                    candidate.payload(), candidate.policyVersion(), candidate.prevHash(), hash);
            h.store().append(last);
            if (headHash == null) {
                headHash = hash;
            }
            prevHash = hash;
        }
        if (last != null) {
            h.store().writeAnchor(new Anchor(1, headHash, last.seq(), last.hash(), count));
        }
    }

    public static Map<String, String> payload(String... kv) {
        Map<String, String> m = new java.util.LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }
}
