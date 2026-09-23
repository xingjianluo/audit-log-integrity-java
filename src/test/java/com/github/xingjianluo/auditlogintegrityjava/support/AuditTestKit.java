package com.github.xingjianluo.auditlogintegrityjava.support;

import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.crypto.HashService;
import com.github.xingjianluo.auditlogintegrityjava.crypto.Sha256HashService;
import com.github.xingjianluo.auditlogintegrityjava.export.AuditEventReceiver;
import com.github.xingjianluo.auditlogintegrityjava.export.AuditExporter;
import com.github.xingjianluo.auditlogintegrityjava.export.InMemoryAuditEventReceiver;
import com.github.xingjianluo.auditlogintegrityjava.masking.ConfigurableFieldMaskingPolicy;
import com.github.xingjianluo.auditlogintegrityjava.masking.FixedRetentionPolicy;
import com.github.xingjianluo.auditlogintegrityjava.masking.HashMaskingStrategy;
import com.github.xingjianluo.auditlogintegrityjava.masking.RetentionPolicy;
import com.github.xingjianluo.auditlogintegrityjava.model.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.service.ChainIntegrityVerifier;
import com.github.xingjianluo.auditlogintegrityjava.store.FileAuditLogStore;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** Wires the real components (no Spring) against a fresh temp directory. */
public final class AuditTestKit {

    public final AuditProperties props;
    public final HashService hashService;
    public final HashMaskingStrategy strategy;
    public final ConfigurableFieldMaskingPolicy policy;
    public final FileAuditLogStore store;
    public final ChainIntegrityVerifier verifier;
    public final RetentionPolicy retention;
    public final AuditService service;
    public final InMemoryAuditEventReceiver receiver;
    public final AuditExporter exporter;

    private AuditTestKit(AuditProperties props, HashService hashService,
                         HashMaskingStrategy strategy,
                         ConfigurableFieldMaskingPolicy policy,
                         FileAuditLogStore store, ChainIntegrityVerifier verifier,
                         RetentionPolicy retention, AuditService service,
                         InMemoryAuditEventReceiver receiver, AuditExporter exporter) {
        this.props = props;
        this.hashService = hashService;
        this.strategy = strategy;
        this.policy = policy;
        this.store = store;
        this.verifier = verifier;
        this.retention = retention;
        this.service = service;
        this.receiver = receiver;
        this.exporter = exporter;
    }

    public static AuditTestKit create(Path dir, long retentionDays, int batchSize) {
        AuditProperties props = new AuditProperties();
        props.setStorageDir(dir.toString());
        props.setMaskingSalt("unit-salt");
        props.setSensitiveFields(java.util.List.of("password", "token", "idCard"));
        props.setRetentionDays(retentionDays);
        props.setCleanupBatchSize(batchSize);

        HashService hashService = new Sha256HashService();
        HashMaskingStrategy strategy = new HashMaskingStrategy(hashService, "unit-salt", "v1");
        ConfigurableFieldMaskingPolicy policy =
                new ConfigurableFieldMaskingPolicy(strategy, hashService,
                        Set.of("password", "token", "idCard"));
        FileAuditLogStore store = new FileAuditLogStore(props, hashService);
        store.init();
        ChainIntegrityVerifier verifier = new ChainIntegrityVerifier(hashService);
        RetentionPolicy retention = new FixedRetentionPolicy(props);
        AuditService service = new AuditService(store, hashService, policy, retention, verifier);
        InMemoryAuditEventReceiver receiver = new InMemoryAuditEventReceiver();
        AuditExporter exporter = new AuditExporter(store, service, verifier, receiver);
        return new AuditTestKit(props, hashService, strategy, policy, store, verifier,
                retention, service, receiver, exporter);
    }

    /** Create a fresh store/service over the same directory (simulated restart). */
    public AuditTestKit reopen() {
        FileAuditLogStore newStore = new FileAuditLogStore(props, hashService);
        newStore.init();
        AuditService newService = new AuditService(newStore, hashService, policy, retention, verifier);
        AuditExporter newExporter = new AuditExporter(newStore, newService, verifier, receiver);
        return new AuditTestKit(props, hashService, strategy, policy, newStore, verifier,
                retention, newService, receiver, newExporter);
    }

    public static AuditEvent event(String id, long timestamp, String action) {
        Map<String, String> detail = new HashMap<>();
        detail.put("password", "p@ssw0rd-" + id);
        detail.put("token", "bearer-" + id);
        detail.put("note", "ordinary-note-" + id);
        return new AuditEvent(id, timestamp, "alice", action, "/resource/" + id, detail);
    }

    public static AuditEvent plain(String id, long timestamp) {
        return event(id, timestamp, "LOGIN");
    }
}
