package com.github.xingjianluo.auditlogintegrityjava.web;

import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportResult;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveExportService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveImportService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveKeyService;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerification;
import com.github.xingjianluo.auditlogintegrityjava.archive.ArchiveVerifier;
import com.github.xingjianluo.auditlogintegrityjava.archive.ImportResult;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import com.github.xingjianluo.auditlogintegrityjava.export.ExportResult;
import com.github.xingjianluo.auditlogintegrityjava.export.LocalReceiverClient;
import com.github.xingjianluo.auditlogintegrityjava.export.ExportService;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingPolicy;
import com.github.xingjianluo.auditlogintegrityjava.policy.MaskingService;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.service.EventInput;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * 便于本地手工验证的 HTTP 入口。
 */
@RestController
@RequestMapping("/audit")
public class AuditController {

    private final AuditService auditService;
    private final ExportService exportService;
    private final MaskingService maskingService;
    private final LocalReceiverClient receiver;
    private final ArchiveExportService archiveExportService;
    private final ArchiveImportService archiveImportService;
    private final ArchiveVerifier archiveVerifier;
    private final ArchiveKeyService archiveKeyService;

    public AuditController(AuditService auditService, ExportService exportService,
                           MaskingService maskingService, LocalReceiverClient receiver,
                           ArchiveExportService archiveExportService,
                           ArchiveImportService archiveImportService,
                           ArchiveVerifier archiveVerifier,
                           ArchiveKeyService archiveKeyService) {
        this.auditService = auditService;
        this.exportService = exportService;
        this.maskingService = maskingService;
        this.receiver = receiver;
        this.archiveExportService = archiveExportService;
        this.archiveImportService = archiveImportService;
        this.archiveVerifier = archiveVerifier;
        this.archiveKeyService = archiveKeyService;
    }

    @PostMapping("/events")
    public AuditEvent append(@RequestBody EventInput input) {
        return auditService.append(input);
    }

    @GetMapping("/events")
    public List<AuditEvent> events() {
        return auditService.readAll();
    }

    @GetMapping("/verify")
    public VerificationReport verify() {
        return auditService.verify();
    }

    @PostMapping("/retain")
    public Map<String, Object> retain(@RequestParam int keepBatches,
                                      @RequestParam(defaultValue = "100") int batchSize) {
        int removed = auditService.retainByBatch(keepBatches, batchSize);
        return Map.of("removed", removed, "report", auditService.verify());
    }

    @PostMapping("/export")
    public ExportResult export() {
        return exportService.exportAll();
    }

    @PostMapping("/export/order")
    public ExportResult exportOrdered(@RequestBody List<String> orderedEventIds) {
        return exportService.exportInOrder(orderedEventIds);
    }

    /** 测试用：模拟接收端故障开关 */
    @PostMapping("/receiver/failing")
    public Map<String, Object> receiverFailing(@RequestParam boolean failing) {
        receiver.setFailing(failing);
        return Map.of("receiverFailing", failing);
    }

    /** 测试用：重置内存接收端的幂等记录 */
    @PostMapping("/receiver/reset")
    public Map<String, Object> receiverReset() {
        receiver.reset();
        return Map.of("receiver", "reset");
    }

    @PostMapping("/policy")
    public MaskingPolicy updatePolicy(@RequestBody Map<String, Object> body) {
        @SuppressWarnings("unchecked")
        List<String> fields = (List<String>) body.getOrDefault("sensitiveFields", List.of());
        String token = (String) body.get("maskToken");
        return maskingService.updatePolicy(new TreeSet<>(fields), token);
    }

    @GetMapping("/policy")
    public MaskingPolicy policy() {
        return maskingService.current();
    }

    // ---- 归档包：导出 / 离线核验 / 导入 ----

    /**
     * 导出 [fromSeq, toSeq] 为签名归档包。给定 out 时把包写到该文件路径，
     * 否则在响应里以 Base64 返回包字节。
     */
    @PostMapping("/archive/export")
    public Map<String, Object> exportArchive(@RequestParam long fromSeq,
                                             @RequestParam long toSeq,
                                             @RequestParam(required = false) String out)
            throws IOException {
        ArchiveExportResult result = archiveExportService.exportRange(fromSeq, toSeq);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("outcome", result.outcome().name());
        body.put("archiveId", result.archiveId());
        body.put("fromSeq", result.fromSeq());
        body.put("toSeq", result.toSeq());
        body.put("eventCount", result.eventCount());
        body.put("detail", result.detail());
        body.put("integrityIssues", result.integrityIssues());
        if (result.packageBytes() != null) {
            if (out != null && !out.isBlank()) {
                Files.write(Path.of(out), result.packageBytes());
                body.put("packagePath", out);
            } else {
                body.put("packageBase64", Base64.getEncoder().encodeToString(result.packageBytes()));
            }
            body.put("packageSize", result.packageBytes().length);
        }
        return body;
    }

    /** 本环境标识与公钥（带外交付给核验方/导入方）。 */
    @GetMapping("/archive/public-key")
    public Map<String, Object> archivePublicKey() {
        return Map.of(
                "environmentId", archiveKeyService.environmentId(),
                "publicKeyBase64", Base64.getEncoder().encodeToString(archiveKeyService.publicKeyBytes()));
    }

    /** 离线核验一个归档包文件（path=包文件, keyPath=来源环境公钥文件，Base64）。 */
    @PostMapping("/archive/verify")
    public ArchiveVerification verifyArchive(@RequestParam String path,
                                             @RequestParam String keyPath) throws IOException {
        byte[] packageBytes = Files.readAllBytes(Path.of(path));
        byte[] publicKey = Base64.getDecoder().decode(
                Files.readString(Path.of(keyPath)).trim());
        return archiveVerifier.verify(packageBytes, publicKey);
    }

    /** 把归档包文件导入本地链（幂等、原子）。 */
    @PostMapping("/archive/import")
    public ImportResult importArchive(@RequestParam String path,
                                      @RequestParam String keyPath) throws IOException {
        byte[] packageBytes = Files.readAllBytes(Path.of(path));
        byte[] publicKey = Base64.getDecoder().decode(
                Files.readString(Path.of(keyPath)).trim());
        return archiveImportService.importPackage(packageBytes, publicKey);
    }
}
