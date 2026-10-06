package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.service.IntegrityException;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * 归档包服务。
 *
 * <p>导出：把指定 seq 区间的事件连同当时证据（每条事件自身的哈希链节、区间头尾哈希、
 * 区间前驱哈希）打包成单个自包含 JSON 文件，并用本环境密钥对清单签名。
 * 事件落盘时已按当时策略脱敏并记录 policyVersion，归档只是原样复制，
 * 因此之后调整脱敏策略或来源环境做保留期清理，都不会改变本包的可核验性。
 */
@Service
public class ArchiveService {

    private static final Logger log = LoggerFactory.getLogger(ArchiveService.class);

    private final AuditService auditService;
    private final ArchiveKeyProvider keys;
    private final ArchiveSigner signer;
    private final ArchiveVerifier verifier;
    private final ObjectMapper mapper;
    private final Path archiveDir;
    private final Path importDir;

    public ArchiveService(AuditService auditService, ArchiveKeyProvider keys, ArchiveSigner signer,
                          ArchiveVerifier verifier, AuditProperties properties, ObjectMapper mapper) {
        this.auditService = auditService;
        this.keys = keys;
        this.signer = signer;
        this.verifier = verifier;
        this.mapper = mapper;
        Path dataDir = Path.of(properties.getDataDir());
        this.archiveDir = dataDir.resolve("archives");
        this.importDir = dataDir.resolve("imports");
    }

    /**
     * 导出 [fromSeq, toSeq] 区间为自包含归档包。
     * 下界严格（起点已被清理则拒绝），上界裁剪到当前链尾。
     * 配置缺失与未预料内部错误都归类为可区分结论，不抛笼统异常。
     */
    public ArchiveExportResult exportRange(long fromSeq, long toSeq) {
        if (fromSeq <= 0 || toSeq < fromSeq) {
            throw new IllegalArgumentException("要求 1 <= fromSeq <= toSeq");
        }
        List<String> missingConfig = keys.missingLocalConfig();
        if (!missingConfig.isEmpty()) {
            log.warn("归档导出中止: 配置缺失 {}", missingConfig);
            return new ArchiveExportResult(ArchiveExportOutcome.CONFIG_MISSING,
                    fromSeq, toSeq, 0, null,
                    "归档所需配置缺失: " + String.join(", ", missingConfig) + "，请补齐后重试");
        }
        try {
            return doExport(fromSeq, toSeq);
        } catch (RuntimeException e) {
            log.error("归档导出: 未预料的内部错误", e);
            return new ArchiveExportResult(ArchiveExportOutcome.INTERNAL_ERROR,
                    fromSeq, toSeq, 0, null,
                    "导出过程出现未预料的内部错误（本地记录未受影响），可重试；反复出现请排查环境: "
                            + e.getMessage());
        }
    }

    private ArchiveExportResult doExport(long fromSeq, long toSeq) {
        VerificationReport report = auditService.verify();
        if (!report.valid()) {
            log.warn("归档导出中止: 本地完整性校验失败, 问题={}", report.issues());
            return new ArchiveExportResult(ArchiveExportOutcome.INTEGRITY_FAILED,
                    fromSeq, toSeq, 0, null, "本地审计链完整性校验失败，未生成归档包");
        }
        List<AuditEvent> chain = auditService.readAll();
        if (chain.isEmpty()) {
            log.info("归档导出: 空链, 无可归档记录");
            return new ArchiveExportResult(ArchiveExportOutcome.EMPTY_CHAIN,
                    fromSeq, toSeq, 0, null, "本地链为空，没有可归档的记录");
        }
        long headSeq = chain.get(0).seq();
        long tailSeq = chain.get(chain.size() - 1).seq();
        if (fromSeq < headSeq || fromSeq > tailSeq) {
            log.info("归档导出: 区间起点 {} 不在留存范围 [{},{}]（已被清理或尚未到达）", fromSeq, headSeq, tailSeq);
            return new ArchiveExportResult(ArchiveExportOutcome.RANGE_UNAVAILABLE,
                    fromSeq, toSeq, 0, null,
                    "区间起点 seq=" + fromSeq + " 不在本地留存范围 [" + headSeq + "," + tailSeq + "]，"
                            + "可能已被保留期清理");
        }
        long effectiveTo = Math.min(toSeq, tailSeq);
        List<AuditEvent> segment = new ArrayList<>();
        for (AuditEvent e : chain) {
            if (e.seq() >= fromSeq && e.seq() <= effectiveTo) {
                segment.add(e);
            }
        }

        long exportedAt = System.currentTimeMillis();
        String envId = keys.localEnvironmentId();
        AuditEvent first = segment.get(0);
        AuditEvent last = segment.get(segment.size() - 1);
        String fileName = "archive-" + envId + "-" + fromSeq + "-" + effectiveTo + "-" + exportedAt + ".json";
        Path target = archiveDir.resolve(fileName);
        Path tmp = archiveDir.resolve(fileName + ".tmp");

        try {
            Files.createDirectories(archiveDir);
            writeArchive(tmp, envId, exportedAt, fromSeq, effectiveTo, segment,
                    first.prevHash(), first.hash(), last.hash());
            moveAtomically(tmp, target);
        } catch (IOException e) {
            deleteQuietly(tmp);
            log.error("归档导出: 写归档文件失败, 原因={}", e.toString());
            return new ArchiveExportResult(ArchiveExportOutcome.STORAGE_FAILED,
                    fromSeq, effectiveTo, 0, null, "写归档文件失败（本地记录未受影响），可重试: " + e.getMessage());
        }
        log.info("归档导出完成: file={}, env={}, range=[{},{}], count={}", target, envId,
                fromSeq, effectiveTo, segment.size());
        return new ArchiveExportResult(ArchiveExportOutcome.EXPORTED,
                fromSeq, effectiveTo, segment.size(), target.toString(),
                "归档包已生成: " + target);
    }

    /**
     * 流式写出归档包：事件逐条写入并滚动累计清单哈希，内存占用与区间大小无关的部分为 O(1)。
     */
    private void writeArchive(Path target, String envId, long exportedAt,
                              long fromSeq, long toSeq, List<AuditEvent> segment,
                              String prevHash, String headHash, String tailHash) throws IOException {
        String canonical = signer.canonicalMetadata(envId, exportedAt, fromSeq, toSeq,
                segment.size(), prevHash, headHash, tailHash);
        ArchiveSigner.ManifestDigest digest = signer.newDigest(canonical);

        JsonFactory factory = mapper.getFactory();
        try (OutputStream out = new BufferedOutputStream(Files.newOutputStream(target,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING));
             JsonGenerator g = factory.createGenerator(out)) {
            g.writeStartObject();
            g.writeStringField("format", ArchiveSigner.FORMAT);
            g.writeNumberField("formatVersion", ArchiveSigner.FORMAT_VERSION);
            g.writeStringField("environmentId", envId);
            g.writeNumberField("exportedAt", exportedAt);
            g.writeNumberField("fromSeq", fromSeq);
            g.writeNumberField("toSeq", toSeq);
            g.writeNumberField("count", segment.size());
            g.writeStringField("prevHash", prevHash);
            g.writeStringField("headHash", headHash);
            g.writeStringField("tailHash", tailHash);
            g.writeArrayFieldStart("events");
            for (AuditEvent e : segment) {
                digest.addEventHash(e.hash());
                g.writeObject(e);
            }
            g.writeEndArray();
            String manifestHash = digest.hex();
            g.writeStringField("manifestHash", manifestHash);
            g.writeStringField("signature", signer.hmacSha256Hex(keys.localKey(), manifestHash));
            g.writeEndObject();
        }
    }

    /**
     * 离线核验归档包：只依赖包文件与（按环境查表的）核验密钥，
     * 不触碰本地链与脱敏策略，因此历史结论永远可按包内证据复现。
     */
    public ArchiveVerification verify(Path archiveFile, String expectedEnvironmentId) {
        return verifier.verify(archiveFile, expectedEnvironmentId);
    }

    /**
     * 导入归档包到本环境：包内记录并入本地链，成为本环境自己的记录。
     *
     * <p>规则：
     * <ul>
     *   <li>先离线核验，包本身有问题 → INTEGRITY_REJECTED / UNTRUSTED_SOURCE，本地零改动；</li>
     *   <li>并入：事件内容原样保留，seq/链节/哈希按本地链尾重排，导入后即可与本地记录
     *       一起查询、整体校验，并继续往后追加；</li>
     *   <li>幂等：同一包（或区间重叠的包）重复/并发导入，已存在的记录按 eventId+内容
     *       幂等跳过 → DUPLICATE_IGNORED，不堆重复记录、不动链；</li>
     *   <li>清理后再导入：该包此前导入过但记录已被保留期清理 → 重新并入并明确给出
     *       REIMPORTED_AFTER_PRUNE，不悄悄判成普通成功；</li>
     *   <li>原子：合并是单步可恢复操作，接收/存储失败 → STORAGE_FAILED，
     *       本地原有记录零改动，可重试；本地链本身破损 → LOCAL_CHAIN_INVALID；</li>
     *   <li>包副本留存 imports/ 下作为证据，可随时独立离线核验。</li>
     * </ul>
     */
    public ArchiveImportResult importArchive(Path archiveFile) {
        ArchiveVerification verification;
        try {
            verification = verifier.verify(archiveFile, null);
        } catch (RuntimeException e) {
            log.error("归档导入: 核验过程出现未预料的内部错误", e);
            return new ArchiveImportResult(ArchiveImportOutcome.INTERNAL_ERROR, null, null, 0,
                    "核验过程出现未预料的内部错误（本地记录零改动），可重试；反复出现请排查环境: "
                            + e.getMessage());
        }
        if (!verification.valid()) {
            boolean untrusted =
                    verification.primaryReason() == ArchiveFailureReason.UNTRUSTED_ENVIRONMENT;
            ArchiveImportOutcome outcome = untrusted
                    ? ArchiveImportOutcome.UNTRUSTED_SOURCE
                    : ArchiveImportOutcome.INTEGRITY_REJECTED;
            String detail = untrusted
                    ? "没有来源环境 " + verification.environmentId() + " 的核验密钥，无法确认包来源；"
                            + "请把对方密钥配置到 audit.trusted-archive-keys." + verification.environmentId()
                            + " 或与对方确认来源，本地记录零改动"
                    : "归档包核验未通过（" + verification.primaryReason() + "），本地记录零改动；"
                            + "应与提供方核对而非简单重试";
            log.warn("归档导入拒绝: outcome={}, 主因={}, 问题数={}",
                    outcome, verification.primaryReason(), verification.issues().size());
            return new ArchiveImportResult(outcome, verification, null, 0, detail);
        }

        List<AuditEvent> events;
        try {
            events = readArchiveEvents(archiveFile);
        } catch (Exception e) {
            // 核验已通过却读不出事件：未预料的内部状态，归类为内部错误而非包问题
            log.error("归档导入: 读取已核验包失败", e);
            return new ArchiveImportResult(ArchiveImportOutcome.INTERNAL_ERROR, verification,
                    null, 0, "包核验通过但读取事件失败（本地记录零改动），可重试: " + e.getMessage());
        }

        String fileName = "imported-" + verification.environmentId()
                + "-" + verification.fromSeq() + "-" + verification.toSeq() + ".json";
        boolean previouslyImported = Files.exists(importDir.resolve(fileName));

        AuditService.MergeResult merge;
        try {
            // 跨环境导入：eventId 加 "来源环境/" 前缀做命名空间隔离；
            // 同环境回导（如清理后恢复）保持原 eventId
            String prefix = verification.environmentId().equals(keys.localEnvironmentId())
                    ? "" : verification.environmentId() + "/";
            merge = auditService.mergeImported(events, prefix);
        } catch (IntegrityException e) {
            log.warn("归档导入拒绝: 本地链完整性校验未通过, 问题={}", e.getReport().issues());
            return new ArchiveImportResult(ArchiveImportOutcome.LOCAL_CHAIN_INVALID,
                    verification, null, 0,
                    "包本身有效，但本地链完整性校验未通过，拒绝在破损链上合并（本地记录零改动）；"
                            + "请先处理本地链问题再导入");
        } catch (AuditStoreException e) {
            log.error("归档导入: 本地接收/存储失败, 原因={}", e.toString());
            return new ArchiveImportResult(ArchiveImportOutcome.STORAGE_FAILED,
                    verification, null, 0,
                    "包本身有效，但本地接收/存储失败（本地记录零改动），可重试: " + e.getMessage());
        } catch (RuntimeException e) {
            log.error("归档导入: 未预料的内部错误", e);
            return new ArchiveImportResult(ArchiveImportOutcome.INTERNAL_ERROR, verification,
                    null, 0, "导入过程出现未预料的内部错误（本地记录零改动），可重试；反复出现请排查环境: "
                            + e.getMessage());
        }

        if (merge.appended() == 0) {
            log.info("归档导入幂等忽略: 包内 {} 条记录均已在本地链中", merge.skipped());
            return new ArchiveImportResult(ArchiveImportOutcome.DUPLICATE_IGNORED,
                    verification, previouslyImported ? fileName : null, 0,
                    "包内记录已全部存在于本地链，幂等忽略，未新增记录");
        }

        // 留存包副本作为证据（可独立离线核验）；副本写失败不影响已完成的合并，但要写日志说明
        String storedAs = null;
        String copyNote = "";
        try {
            Files.createDirectories(importDir);
            Path tmp = importDir.resolve(fileName + ".tmp");
            try {
                Files.copy(archiveFile, tmp,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                moveAtomically(tmp, importDir.resolve(fileName));
            } catch (IOException e) {
                deleteQuietly(tmp);
                throw e;
            }
            storedAs = fileName;
        } catch (IOException e) {
            copyNote = "；注意：包副本留存失败（" + e.getMessage() + "），记录已正常并入本地链";
            log.warn("归档导入: 包副本留存失败, 原因={}", e.toString());
        }

        ArchiveImportOutcome outcome = previouslyImported
                ? ArchiveImportOutcome.REIMPORTED_AFTER_PRUNE
                : ArchiveImportOutcome.IMPORTED;
        String detail = previouslyImported
                ? "该包此前导入过、记录已被保留期清理，本次已重新并入本地链 " + merge.appended() + " 条"
                        + "（幂等跳过 " + merge.skipped() + " 条）" + copyNote
                : "已把 " + merge.appended() + " 条记录并入本地链（幂等跳过 " + merge.skipped()
                        + " 条），可与本地记录一起查询、整体校验并继续追加" + copyNote;
        log.info("归档导入完成: outcome={}, env={}, 区间=[{},{}], 新并入={}, 跳过={}, 副本={}",
                outcome, verification.environmentId(), verification.fromSeq(),
                verification.toSeq(), merge.appended(), merge.skipped(), storedAs);
        return new ArchiveImportResult(outcome, verification, storedAs, merge.appended(), detail);
    }

    /**
     * 流式读出包内全部事件（导入用）。调用前包须已通过离线核验。
     */
    private List<AuditEvent> readArchiveEvents(Path archiveFile) throws IOException {
        List<AuditEvent> events = new ArrayList<>();
        try (var in = Files.newInputStream(archiveFile);
             var p = mapper.getFactory().createParser(in)) {
            while (p.nextToken() != null) {
                if ("events".equals(p.currentName())) {
                    p.nextToken(); // START_ARRAY
                    while (p.nextToken() == com.fasterxml.jackson.core.JsonToken.START_OBJECT) {
                        events.add(mapper.readValue(p, AuditEvent.class));
                    }
                    break;
                }
            }
        }
        return events;
    }

    /**
     * 已留存的归档包副本文件名列表（imports/ 下，作为导入证据，可逐个独立离线核验）。
     */
    public List<String> listImports() {
        if (!Files.isDirectory(importDir)) {
            return List.of();
        }
        try (var stream = Files.list(importDir)) {
            return stream.map(p -> p.getFileName().toString())
                    .filter(n -> n.endsWith(".json"))
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new IllegalStateException("读取导入目录失败: " + importDir, e);
        }
    }

    /**
     * 核验某个已导入的归档段。
     */
    public ArchiveVerification verifyImported(String storedAs) {
        return verifier.verify(importDir.resolve(storedAs), null);
    }

    static void moveAtomically(Path src, Path dst) throws IOException {
        try {
            Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException atomicFailed) {
            Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    static void deleteQuietly(Path p) {
        try {
            Files.deleteIfExists(p);
        } catch (IOException ignored) {
            // 清理临时文件失败不影响结论
        }
    }
}
