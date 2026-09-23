package com.github.xingjianluo.auditlogintegrityjava.web;

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

    public AuditController(AuditService auditService, ExportService exportService,
                           MaskingService maskingService, LocalReceiverClient receiver) {
        this.auditService = auditService;
        this.exportService = exportService;
        this.maskingService = maskingService;
        this.receiver = receiver;
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
}
