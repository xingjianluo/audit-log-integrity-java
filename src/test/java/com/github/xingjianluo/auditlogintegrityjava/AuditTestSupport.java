package com.github.xingjianluo.auditlogintegrityjava;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveKeyProvider;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveSigner;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerifier;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import com.github.xingjianluo.auditlogintegrityjava.export.ExportService;
import com.github.xingjianluo.auditlogintegrityjava.export.LocalReceiverClient;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingService;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.service.EventInput;
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
        private final ArchiveService archiveService;
        private AuditEventBuilder builder;

        Harness(Path dir, ObjectMapper mapper, ChainHasher hasher, FileAuditStore store,
                MaskingService maskingService, AuditService auditService,
                LocalReceiverClient receiver, ExportService exportService,
                ArchiveService archiveService) {
            this.dir = dir;
            this.mapper = mapper;
            this.hasher = hasher;
            this.store = store;
            this.maskingService = maskingService;
            this.auditService = auditService;
            this.receiver = receiver;
            this.exportService = exportService;
            this.archiveService = archiveService;
        }

        public Path dir() { return dir; }
        public ObjectMapper mapper() { return mapper; }
        public ChainHasher hasher() { return hasher; }
        public FileAuditStore store() { return store; }
        public MaskingService maskingService() { return maskingService; }
        public AuditService auditService() { return auditService; }
        public LocalReceiverClient receiver() { return receiver; }
        public ExportService exportService() { return exportService; }
        public ArchiveService archiveService() { return archiveService; }

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
        return harness(dir, sensitiveFields, "local", "local-test-key", Map.of());
    }

    /**
     * 带归档环境身份与密钥的装配：envId 标识环境，archiveKey 为本环境签名密钥，
     * trustedKeys 为可核验/导入的其他环境密钥。
     */
    public static Harness harness(Path dir, List<String> sensitiveFields, String envId,
                                  String archiveKey, Map<String, String> trustedKeys) {
        AuditProperties props = new AuditProperties();
        props.setDataDir(dir.toString());
        props.setSensitiveFields(new ArrayList<>(sensitiveFields));
        props.setEnvironmentId(envId);
        props.setArchiveKey(archiveKey);
        props.setTrustedArchiveKeys(trustedKeys);
        ObjectMapper mapper = new ObjectMapper();
        ChainHasher hasher = new ChainHasher();
        FileAuditStore store = new FileAuditStore(props, mapper);
        MaskingService masking = new MaskingService(props, mapper);
        AuditService audit = new AuditService(store, hasher, masking);
        LocalReceiverClient receiver = new LocalReceiverClient();
        ExportService exporter = new ExportService(audit, receiver);
        ArchiveKeyProvider keys = new ArchiveKeyProvider(props);
        ArchiveSigner signer = new ArchiveSigner();
        ArchiveVerifier verifier = new ArchiveVerifier(hasher, signer, keys, mapper);
        ArchiveService archive = new ArchiveService(audit, keys, signer, verifier, props, mapper);
        return new Harness(dir, mapper, hasher, store, masking, audit, receiver, exporter, archive);
    }

    public static Map<String, String> payload(String... kv) {
        Map<String, String> m = new java.util.LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }
}
