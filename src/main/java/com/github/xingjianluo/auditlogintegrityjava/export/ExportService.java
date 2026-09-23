package com.github.xingjianluo.auditlogintegrityjava.export;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationIssue;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 导出服务。
 *
 * <p>结论分类（两类失败严格可区分）：
 * <ul>
 *   <li>{@link ExportOutcome#INTEGRITY_FAILED}：本地链完整性校验未通过，一条都不投递；</li>
 *   <li>{@link ExportOutcome#RECEIVER_FAILED}：链完好但接收端抛错；本地记录不受影响，可重试；</li>
 *   <li>{@link ExportOutcome#DUPLICATE_IGNORED}：全部为接收端已收过的重复投递；</li>
 *   <li>{@link ExportOutcome#DELIVERED}：至少一条新投递成功，且无失败。</li>
 * </ul>
 * 乱序/重复投递由接收端以 eventId 幂等吸收，导出过程不写本地存储。
 */
@Service
public class ExportService {

    private static final Logger log = LoggerFactory.getLogger(ExportService.class);

    private final AuditService auditService;
    private final AuditReceiverClient receiver;

    public ExportService(AuditService auditService, AuditReceiverClient receiver) {
        this.auditService = auditService;
        this.receiver = receiver;
    }

    public ExportResult exportAll() {
        return doExport(auditService.readAll(), null);
    }

    /**
     * 按给定 eventId 顺序投递（可故意乱序/重复）；orderedEventIds 为 null 表示按链顺序导出全部。
     */
    public ExportResult exportInOrder(List<String> orderedEventIds) {
        return doExport(auditService.readAll(), orderedEventIds);
    }

    private ExportResult doExport(List<AuditEvent> chain, List<String> orderedEventIds) {
        VerificationReport report = auditService.verify();
        if (!report.valid()) {
            log.warn("导出中止: 本地完整性校验失败, 问题={}", report.issues());
            return new ExportResult(ExportOutcome.INTEGRITY_FAILED, 0, 0, 0,
                    List.of(), List.copyOf(report.issues()),
                    "本地审计链完整性校验失败，未进行任何投递");
        }

        Map<String, AuditEvent> byId = new LinkedHashMap<>();
        chain.forEach(e -> byId.put(e.eventId(), e));

        List<AuditEvent> toDeliver;
        if (orderedEventIds == null) {
            toDeliver = chain;
        } else {
            toDeliver = new ArrayList<>();
            for (String id : orderedEventIds) {
                AuditEvent e = byId.get(id);
                if (e != null) {
                    toDeliver.add(e);
                } else {
                    log.warn("导出列表中的 eventId 在本地链不存在，跳过: {}", id);
                }
            }
        }

        int delivered = 0;
        int duplicate = 0;
        List<String> failed = new ArrayList<>();
        for (AuditEvent e : toDeliver) {
            try {
                AuditReceiverClient.Ack ack = receiver.deliver(e);
                if (ack == AuditReceiverClient.Ack.DUPLICATE) {
                    duplicate++;
                } else {
                    delivered++;
                }
            } catch (ReceiverException ex) {
                failed.add(e.eventId());
                log.error("接收端投递失败: eventId={}, 原因={}", e.eventId(), ex.getMessage());
            }
        }

        ExportOutcome outcome;
        String detail;
        if (!failed.isEmpty()) {
            outcome = ExportOutcome.RECEIVER_FAILED;
            detail = "接收端故障导致 " + failed.size() + " 条投递失败（本地审计记录未改动），可重试";
        } else if (delivered > 0) {
            outcome = ExportOutcome.DELIVERED;
            detail = "成功投递 " + delivered + " 条";
        } else if (duplicate > 0) {
            outcome = ExportOutcome.DUPLICATE_IGNORED;
            detail = "全部 " + duplicate + " 条均为接收端已接收的重复投递，幂等忽略";
        } else {
            outcome = ExportOutcome.DELIVERED;
            detail = "链为空，无待导出事件";
        }
        log.info("导出结论: outcome={}, attempted={}, delivered={}, duplicateIgnored={}, receiverFailed={}",
                outcome, toDeliver.size(), delivered, duplicate, failed.size());
        return new ExportResult(outcome, toDeliver.size(), delivered, duplicate,
                List.copyOf(failed), List.<VerificationIssue>of(), detail);
    }
}
