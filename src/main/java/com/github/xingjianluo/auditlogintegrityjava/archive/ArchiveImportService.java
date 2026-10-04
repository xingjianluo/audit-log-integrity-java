package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.service.EventInput;
import com.github.xingjianluo.auditlogintegrityjava.service.IntegrityException;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 归档导入服务：把核验通过的归档包幂等、原子地并入本地链。
 *
 * <p>每条源事件包装为一条本地事件追加到链尾（与本地已有记录并存于同一条链），
 * 原始事件 JSON 逐字节保留在 payload 的 {@code _importOriginalEvent} 字段中，
 * 本地事件 id 为确定性的 {@code imp-<archiveId>-<原eventId>}，因此：
 * <ul>
 *   <li>同一个包反复导入结果相同（已存在的 id 被幂等跳过）；</li>
 *   <li>包本身核验不过 → {@link ImportOutcome#PACKAGE_INVALID}，本地零改动；</li>
 *   <li>本地链当前不完整 → {@link ImportOutcome#LOCAL_CHAIN_INVALID}，本地零改动；</li>
 *   <li>接收/存储中途出错 → 回滚到导入前状态，
 *       {@link ImportOutcome#IMPORT_STORAGE_FAILED}，可安全重试。</li>
 * </ul>
 */
@Service
public class ArchiveImportService {

    private static final Logger log = LoggerFactory.getLogger(ArchiveImportService.class);

    public static final String IMPORT_ACTOR = "_archive-import";
    public static final String IMPORT_ACTION = "ARCHIVE_IMPORT";

    private final ArchiveVerifier verifier;
    private final AuditService auditService;
    private final ObjectMapper mapper;

    public ArchiveImportService(ArchiveVerifier verifier, AuditService auditService,
                                ObjectMapper mapper) {
        this.verifier = verifier;
        this.auditService = auditService;
        this.mapper = mapper;
    }

    /**
     * 导入归档包。
     *
     * @param packageBytes     包字节
     * @param sourcePublicKey  来源环境公钥（带外获得）
     */
    public ImportResult importPackage(byte[] packageBytes, byte[] sourcePublicKey) {
        ArchiveVerification verification = verifier.verify(packageBytes, sourcePublicKey);
        if (!verification.valid()) {
            log.warn("归档导入结论: outcome={}, 依据=包核验未通过 {}",
                    ImportOutcome.PACKAGE_INVALID, verification.details());
            return new ImportResult(ImportOutcome.PACKAGE_INVALID,
                    verification.archiveId(), 0, 0, verification,
                    "归档包完整性核验未通过（" + verification.conclusion() + "），本地零改动");
        }

        ArchivePackage pkg;
        try {
            pkg = mapper.readValue(packageBytes, ArchivePackage.class);
        } catch (IOException e) {
            // 核验已通过却解析失败，理论上不可达；按包无效处理，本地零改动
            log.error("归档导入结论: outcome={}, 依据=核验通过后解析失败 {}", ImportOutcome.PACKAGE_INVALID, e.getMessage());
            return new ImportResult(ImportOutcome.PACKAGE_INVALID,
                    verification.archiveId(), 0, 0, verification, "包解析失败，本地零改动");
        }

        List<EventInput> batch = new ArrayList<>(pkg.events().size());
        for (AuditEvent source : pkg.events()) {
            batch.add(toImportInput(pkg.manifest(), source));
        }

        final List<com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent> appended;
        try {
            appended = auditService.appendExternalBatch(batch);
        } catch (IntegrityException integrity) {
            log.warn("归档导入结论: outcome={}, 依据=本地链校验未通过 {}",
                    ImportOutcome.LOCAL_CHAIN_INVALID, integrity.getReport().issues());
            return new ImportResult(ImportOutcome.LOCAL_CHAIN_INVALID,
                    verification.archiveId(), 0, 0, verification,
                    "本地链当前不完整，拒绝在其上导入，本地零改动");
        } catch (AuditStoreException storage) {
            log.error("归档导入结论: outcome={}, 依据=接收/存储失败（已回滚）: {}",
                    ImportOutcome.IMPORT_STORAGE_FAILED, storage.getMessage());
            return new ImportResult(ImportOutcome.IMPORT_STORAGE_FAILED,
                    verification.archiveId(), 0, 0, verification,
                    "导入过程中本地存储出错，已回滚到导入前状态，可重试: " + storage.getMessage());
        }

        ImportOutcome outcome = appended.isEmpty() ? ImportOutcome.ALREADY_IMPORTED : ImportOutcome.IMPORTED;
        log.info("归档导入结论: outcome={}, archiveId={}, 新增={}, 幂等跳过={}",
                outcome, verification.archiveId(), appended.size(), batch.size() - appended.size());
        return new ImportResult(outcome, verification.archiveId(),
                appended.size(), batch.size() - appended.size(), verification,
                appended.isEmpty() ? "包中记录此前已全部导入，幂等零改动"
                        : "成功导入 " + appended.size() + " 条记录");
    }

    /** 把一条源事件包装为确定性的本地导入事件（原始事件 JSON 逐字节保留在 payload）。 */
    private EventInput toImportInput(ArchiveManifest manifest, AuditEvent source) {
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put("_importArchiveId", manifest.archiveId());
        payload.put("_importSourceEnv", manifest.environmentId());
        payload.put("_importOriginalSeq", Long.toString(source.seq()));
        payload.put("_importOriginalHash", source.hash());
        try {
            payload.put("_importOriginalEvent", mapper.writeValueAsString(source));
        } catch (IOException e) {
            throw new AuditStoreException("序列化源事件失败: seq=" + source.seq(), e);
        }
        return new EventInput(
                "imp-" + manifest.archiveId() + "-" + source.eventId(),
                IMPORT_ACTOR, IMPORT_ACTION,
                "archive://" + manifest.environmentId() + "/" + manifest.archiveId(),
                payload);
    }
}
