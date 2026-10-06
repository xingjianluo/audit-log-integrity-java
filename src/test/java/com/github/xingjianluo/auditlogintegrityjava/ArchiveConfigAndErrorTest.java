package com.github.xingjianluo.auditlogintegrityjava;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveFailureReason;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportOutcome;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveKeyProvider;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveSigner;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerification;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerifier;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingService;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.storage.FileAuditStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 配置缺失与未预料内部错误的归类：导出/核验/导入不允许抛出笼统异常，
 * 必须给出可区分、可操作的结论（补配置 / 可重试 / 找对方）。
 */
class ArchiveConfigAndErrorTest {

    private static final Logger log = LoggerFactory.getLogger(ArchiveConfigAndErrorTest.class);

    @TempDir
    Path dir;

    private AuditProperties props(Path dataDir, String envId, String archiveKey,
                                  Map<String, String> trusted) {
        AuditProperties props = new AuditProperties();
        props.setDataDir(dataDir.toString());
        props.setSensitiveFields(List.of("password"));
        props.setEnvironmentId(envId);
        props.setArchiveKey(archiveKey);
        props.setTrustedArchiveKeys(trusted);
        return props;
    }

    private ArchiveService archiveService(AuditProperties props, AuditService audit,
                                          ObjectMapper mapper) {
        ChainHasher hasher = new ChainHasher();
        ArchiveKeyProvider keys = new ArchiveKeyProvider(props);
        return new ArchiveService(audit, keys, new ArchiveSigner(),
                new ArchiveVerifier(hasher, new ArchiveSigner(), keys, mapper), props, mapper);
    }

    @Test
    void exportWithoutArchiveKeyIsConfigMissingNotException() {
        AuditProperties props = props(dir.resolve("a"), "envA", "", Map.of()); // 未配密钥
        ObjectMapper mapper = new ObjectMapper();
        FileAuditStore store = new FileAuditStore(props, mapper);
        AuditService audit = new AuditService(store, new ChainHasher(),
                new MaskingService(props, mapper));
        ArchiveService archive = archiveService(props, audit, mapper);
        audit.append(new com.github.xingjianluo.auditlogintegrityjava.service.EventInput(
                "e1", "actor", "A", "r", AuditTestSupport.payload()));
        log.info("[输入] 未配置 audit.archive-key 时导出");

        ArchiveExportResult r = archive.exportRange(1, 1);
        log.info("[判定依据] outcome={}, detail={}", r.outcome(), r.detail());
        assertEquals(ArchiveExportOutcome.CONFIG_MISSING, r.outcome());
        assertTrue(r.detail().contains("audit.archive-key"), "应指明该补哪项配置: " + r.detail());
    }

    @Test
    void exportWithoutEnvironmentIdIsConfigMissing() {
        AuditProperties props = props(dir.resolve("a"), "", "key-A", Map.of()); // 未配环境标识
        ObjectMapper mapper = new ObjectMapper();
        FileAuditStore store = new FileAuditStore(props, mapper);
        AuditService audit = new AuditService(store, new ChainHasher(),
                new MaskingService(props, mapper));
        ArchiveService archive = archiveService(props, audit, mapper);
        audit.append(new com.github.xingjianluo.auditlogintegrityjava.service.EventInput(
                "e1", "actor", "A", "r", AuditTestSupport.payload()));
        log.info("[输入] 未配置 audit.environment-id 时导出");

        ArchiveExportResult r = archive.exportRange(1, 1);
        log.info("[判定依据] outcome={}, detail={}", r.outcome(), r.detail());
        assertEquals(ArchiveExportOutcome.CONFIG_MISSING, r.outcome());
        assertTrue(r.detail().contains("audit.environment-id"), "应指明该补哪项配置: " + r.detail());
    }

    @Test
    void exportInternalErrorIsClassifiedNotThrown() {
        AuditProperties props = props(dir.resolve("a"), "envA", "key-A", Map.of());
        ObjectMapper mapper = new ObjectMapper();
        FileAuditStore store = new FileAuditStore(props, mapper);
        // 注入一个会抛未预料运行时异常的 AuditService
        AuditService audit = new AuditService(store, new ChainHasher(),
                new MaskingService(props, mapper)) {
            @Override
            public VerificationReport verify() {
                throw new IllegalStateException("模拟未预料的内部错误");
            }
        };
        ArchiveService archive = archiveService(props, audit, mapper);
        log.info("[输入] 导出过程中校验组件抛出未预料异常");

        ArchiveExportResult r = archive.exportRange(1, 1);
        log.info("[判定依据] outcome={}, detail={}", r.outcome(), r.detail());
        assertEquals(ArchiveExportOutcome.INTERNAL_ERROR, r.outcome(),
                "未预料内部错误必须归类为可区分结论，而不是笼统失败");
    }

    @Test
    void importInternalErrorIsClassifiedNotThrown() {
        // 先用正常环境导出一个有效包
        var src = AuditTestSupport.harness(dir.resolve("src"), List.of("password"),
                "envA", "key-A", Map.of());
        src.events().append("a1", "A", "r", AuditTestSupport.payload());
        Path archiveFile = Path.of(src.archiveService().exportRange(1, 1).archiveFile());

        AuditProperties props = props(dir.resolve("dst"), "envB", "key-B", Map.of("envA", "key-A"));
        ObjectMapper mapper = new ObjectMapper();
        FileAuditStore store = new FileAuditStore(props, mapper);
        // 合并阶段抛未预料运行时异常
        AuditService audit = new AuditService(store, new ChainHasher(),
                new MaskingService(props, mapper)) {
            @Override
            public MergeResult mergeImported(List<AuditEvent> sourceEvents, String eventIdPrefix) {
                throw new IllegalStateException("模拟未预料的内部错误");
            }
        };
        ArchiveService archive = archiveService(props, audit, mapper);
        log.info("[输入] 导入过程中合并组件抛出未预料异常");

        ArchiveImportResult r = archive.importArchive(archiveFile);
        log.info("[判定依据] outcome={}, detail={}", r.outcome(), r.detail());
        assertEquals(ArchiveImportOutcome.INTERNAL_ERROR, r.outcome());
        assertEquals(0, r.mergedCount());
        assertEquals(0, audit.readAll().size(), "内部错误时本地零改动");
    }

    @Test
    void verifyMissingPackageFileIsPackageNotFound() {
        var h = AuditTestSupport.harness(dir.resolve("h"), List.of("password"),
                "envA", "key-A", Map.of());
        log.info("[输入] 核验一个不存在的包文件");
        ArchiveVerification v = h.archiveService().verify(dir.resolve("nope.json"), null);
        log.info("[判定依据] valid={}, primaryReason={}", v.valid(), v.primaryReason());
        assertEquals(ArchiveFailureReason.PACKAGE_NOT_FOUND, v.primaryReason());
        assertEquals(1, v.issues().size(), "包未送达不应叠加格式/元数据等衍生判定");
    }
}
