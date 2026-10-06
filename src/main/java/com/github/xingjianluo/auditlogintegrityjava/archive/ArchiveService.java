package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonStreamContext;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.chain.VerificationReport;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.service.AuditService;
import com.github.xingjianluo.auditlogintegrityjava.service.ImportMergeResult;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
 *
 * <p>导入：先离线核验，再把包内事件<b>并入本地链</b>——并入的记录按本地链规则重链
 * （新 seq、新链节、本地复算哈希，业务字段原样保留），成为本环境自己的记录，
 * 可与原有记录一起查询、整体校验、并继续往后追加。导入幂等且原子：
 * 同一包重复导入结果与首次一致；接收/存储失败时本地原有记录一字节不变。
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

    public ArchiveService(AuditService auditService, ArchiveKeyProvider keys, ArchiveSigner signer,
                          ArchiveVerifier verifier, AuditProperties properties, ObjectMapper mapper) {
        this.auditService = auditService;
        this.keys = keys;
        this.signer = signer;
        this.verifier = verifier;
        this.mapper = mapper;
        Path dataDir = Path.of(properties.getDataDir());
        this.archiveDir = dataDir.resolve("archives");
    }

    /**
     * 导出 [fromSeq, toSeq] 区间为自包含归档包。
     * 下界严格（起点已被清理则拒绝），上界裁剪到当前链尾。
     */
    public ArchiveExportResult exportRange(long fromSeq, long toSeq) {
        if (fromSeq <= 0 || toSeq < fromSeq) {
            throw new IllegalArgumentException("要求 1 <= fromSeq <= toSeq");
        }
        final String localKey;
        try {
            localKey = keys.localKey();
        } catch (IllegalStateException e) {
            log.warn("归档导出中止: {}", e.getMessage());
            return new ArchiveExportResult(ArchiveExportOutcome.CONFIGURATION_MISSING,
                    fromSeq, toSeq, 0, null,
                    e.getMessage() + "；请补充配置 audit.archive-key 后重试");
        }
        try {
            return doExport(fromSeq, toSeq, localKey);
        } catch (RuntimeException e) {
            log.error("归档导出: 未预料的内部错误", e);
            return new ArchiveExportResult(ArchiveExportOutcome.INTERNAL_ERROR,
                    fromSeq, toSeq, 0, null, "导出过程出现未预料的内部错误: " + e);
        }
    }

    private ArchiveExportResult doExport(long fromSeq, long toSeq, String localKey) {
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
                    first.prevHash(), first.hash(), last.hash(), localKey);
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
                              String prevHash, String headHash, String tailHash,
                              String localKey) throws IOException {
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
            g.writeStringField("signature", signer.hmacSha256Hex(localKey, manifestHash));
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
     * 导入归档包：核验通过后把包内事件<b>并入本地链</b>，成为本环境自己的记录。
     *
     * <p>规则：
     * <ul>
     *   <li>先离线核验，包本身有问题 → INTEGRITY_REJECTED / UNTRUSTED_SOURCE，本地零改动；</li>
     *   <li>幂等：同一包重复导入 → DUPLICATE_IGNORED，结果与首次一致，不重复堆记录；
     *       并发导入同一个包由写锁串行化，效果同串行；</li>
     *   <li>本环境自己导出且已被保留期清理的区间 → PRUNED_RANGE，不让已清理记录复活；</li>
     *   <li>原子：并入采用“整体重写链文件 + 刷新锚点”，接收/存储中途失败 → STORAGE_FAILED，
     *       本地原有记录一字节不变，可重试；</li>
     *   <li>配置缺失、未预料的内部错误各有独立结论，不会冒出未归类异常。</li>
     * </ul>
     */
    public ArchiveImportResult importArchive(Path archiveFile) {
        final ArchiveVerification verification;
        try {
            verification = verifier.verify(archiveFile, null);
        } catch (RuntimeException e) {
            log.error("归档导入: 核验过程出现未预料的内部错误", e);
            return new ArchiveImportResult(ArchiveImportOutcome.INTERNAL_ERROR, null, 0, 0,
                    "核验过程出现未预料的内部错误（本地记录零改动）: " + e);
        }
        if (!verification.valid()) {
            ArchiveImportOutcome outcome = switch (verification.primaryReason()) {
                case UNTRUSTED_ENVIRONMENT, ENVIRONMENT_MISMATCH -> ArchiveImportOutcome.UNTRUSTED_SOURCE;
                case PACKAGE_UNREADABLE -> ArchiveImportOutcome.STORAGE_FAILED;
                case INTERNAL_ERROR -> ArchiveImportOutcome.INTERNAL_ERROR;
                default -> ArchiveImportOutcome.INTEGRITY_REJECTED;
            };
            String advice = switch (outcome) {
                case UNTRUSTED_SOURCE -> "没有该来源环境的核验密钥；若确实信任对方，请把其密钥配置到 "
                        + "audit.trusted-archive-keys.<env>（本环境的包则配置 audit.archive-key），否则应找对方核对";
                case STORAGE_FAILED -> "包文件不存在或无法读取（本地记录零改动），检查路径后可重试";
                case INTERNAL_ERROR -> "核验过程出现未预料的内部错误（本地记录零改动），需排查";
                default -> "归档包核验未通过，本地记录零改动；应与提供方核对而非简单重试";
            };
            log.warn("归档导入拒绝: outcome={}, 主因={}, 问题数={}",
                    outcome, verification.primaryReason(), verification.issues().size());
            return new ArchiveImportResult(outcome, verification, 0, 0,
                    advice + "（主因: " + verification.primaryReason() + "）");
        }

        final List<AuditEvent> events;
        try {
            events = readPackageEvents(archiveFile);
        } catch (IOException e) {
            log.error("归档导入: 读取包文件失败, 原因={}", e.toString());
            return new ArchiveImportResult(ArchiveImportOutcome.STORAGE_FAILED, verification, 0, 0,
                    "包本身有效，但读取包文件失败（本地记录零改动），可重试: " + e.getMessage());
        }

        boolean sameEnvironment = verification.environmentId().equals(keys.localEnvironmentId());
        final ImportMergeResult merge;
        try {
            merge = auditService.mergeImported(verification.environmentId(), sameEnvironment, events);
        } catch (AuditStoreException e) {
            log.error("归档导入: 本地接收/存储失败, 原因={}", e.toString());
            return new ArchiveImportResult(ArchiveImportOutcome.STORAGE_FAILED, verification, 0, 0,
                    "包本身有效，但本地接收/存储失败（本地记录零改动），可重试: " + e.getMessage());
        } catch (RuntimeException e) {
            log.error("归档导入: 未预料的内部错误", e);
            return new ArchiveImportResult(ArchiveImportOutcome.INTERNAL_ERROR, verification, 0, 0,
                    "导入过程出现未预料的内部错误: " + e);
        }

        ArchiveImportOutcome outcome = switch (merge.outcome()) {
            case MERGED -> ArchiveImportOutcome.IMPORTED;
            case DUPLICATE_IGNORED -> ArchiveImportOutcome.DUPLICATE_IGNORED;
            case PRUNED_RANGE -> ArchiveImportOutcome.PRUNED_RANGE;
            case EVENT_CONFLICT -> ArchiveImportOutcome.EVENT_CONFLICT;
            case CHAIN_INVALID -> ArchiveImportOutcome.LOCAL_CHAIN_INVALID;
        };
        log.info("归档导入结论: outcome={}, env={}, 区间=[{},{}], 新并入={}, 本地链总数={}",
                outcome, verification.environmentId(), verification.fromSeq(), verification.toSeq(),
                merge.mergedCount(), merge.totalEvents());
        return new ArchiveImportResult(outcome, verification, merge.mergedCount(),
                merge.totalEvents(), merge.detail());
    }

    /**
     * 流式读出包内事件（导入用）。调用前包已通过离线核验，结构与清单一致。
     */
    private List<AuditEvent> readPackageEvents(Path archiveFile) throws IOException {
        List<AuditEvent> events = new ArrayList<>();
        try (InputStream in = Files.newInputStream(archiveFile);
             JsonParser p = mapper.getFactory().createParser(in)) {
            while (p.nextToken() != null) {
                JsonStreamContext ctx = p.getParsingContext();
                if (p.currentToken() == JsonToken.FIELD_NAME
                        && "events".equals(p.currentName())
                        && ctx.getParent() != null && ctx.getParent().inRoot()) {
                    p.nextToken(); // 定位到 START_ARRAY
                    while (p.nextToken() == JsonToken.START_OBJECT) {
                        events.add(mapper.readValue(p, AuditEvent.class));
                    }
                }
            }
        }
        return events;
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
