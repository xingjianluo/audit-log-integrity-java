package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import com.github.xingjianluo.auditlogintegrityjava.crypto.ChainHasher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeSet;

/**
 * 归档包离线核验器：不依赖运行中的服务与任何运行时数据，只读包文件本身。
 *
 * <p>流式解析（Jackson Streaming），逐条复算事件哈希、检查序号连续性与链节，
 * 滚动复算清单哈希并验签；内存占用与包大小无关。结论按类别区分：
 * 内容被改（ENTRY_HASH_MISMATCH）、记录被删（SEQUENCE_GAP）、尾部被截（TRUNCATED）、
 * 顺序被打乱（ORDER_VIOLATION）、链节断裂（LINK_MISMATCH）、伪造/掉包（SIGNATURE_MISMATCH）、
 * 跨环境顶替（UNTRUSTED_ENVIRONMENT / ENVIRONMENT_MISMATCH）等。
 */
@Component
public class ArchiveVerifier {

    private static final Logger log = LoggerFactory.getLogger(ArchiveVerifier.class);
    private static final int MAX_ISSUES = 100;
    private static final int MAX_TRACKED_GAP = 100_000;

    private final ChainHasher hasher;
    private final ArchiveSigner signer;
    private final ArchiveKeyProvider keys;
    private final ObjectMapper mapper;

    public ArchiveVerifier(ChainHasher hasher, ArchiveSigner signer,
                           ArchiveKeyProvider keys, ObjectMapper mapper) {
        this.hasher = hasher;
        this.signer = signer;
        this.keys = keys;
        this.mapper = mapper;
    }

    /**
     * 核验归档包。
     *
     * @param expectedEnvironmentId 期望的来源环境；为 null 时不做环境一致性断言
     */
    public ArchiveVerification verify(Path archiveFile, String expectedEnvironmentId) {
        State s = new State();
        try (InputStream in = Files.newInputStream(archiveFile);
             JsonParser p = mapper.getFactory().createParser(in)) {
            if (p.nextToken() != JsonToken.START_OBJECT) {
                return finish(s.withIssue(ArchiveFailureReason.MALFORMED_PACKAGE, null, null,
                        "包文件不是 JSON 对象"), expectedEnvironmentId);
            }
            while (p.nextToken() != JsonToken.END_OBJECT) {
                String field = p.currentName();
                p.nextToken();
                switch (field) {
                    case "format" -> s.format = p.getValueAsString();
                    case "formatVersion" -> s.formatVersion = p.getIntValue();
                    case "environmentId" -> s.environmentId = p.getValueAsString();
                    case "exportedAt" -> s.exportedAt = p.getLongValue();
                    case "fromSeq" -> s.fromSeq = p.getLongValue();
                    case "toSeq" -> s.toSeq = p.getLongValue();
                    case "count" -> s.declaredCount = p.getLongValue();
                    case "prevHash" -> s.prevHash = p.getValueAsString();
                    case "headHash" -> s.headHash = p.getValueAsString();
                    case "tailHash" -> s.tailHash = p.getValueAsString();
                    case "manifestHash" -> s.manifestHash = p.getValueAsString();
                    case "signature" -> s.signature = p.getValueAsString();
                    case "events" -> readEvents(p, s);
                    default -> p.skipChildren();
                }
            }
        } catch (JsonProcessingException e) {
            // 物理截断（JSON 未写完）与其余结构损坏区分开；
            // 解析中途失败时，后续字段“缺失”只是截断的后果，不再叠加 MALFORMED 判定
            s.parseFailed = true;
            boolean truncated = e.getMessage() != null && e.getMessage().contains("end-of-input");
            return finish(s.withIssue(
                    truncated ? ArchiveFailureReason.TRUNCATED : ArchiveFailureReason.MALFORMED_PACKAGE,
                    null, null, "包文件解析失败: " + e.getMessage()), expectedEnvironmentId);
        } catch (IOException e) {
            // 文件不存在/不可读：接收侧问题，与包内容无关，不判成“包损坏”；
            // 直接给出唯一结论，不再叠加格式/元数据等基于内容的判定
            return single(ArchiveFailureReason.PACKAGE_UNREADABLE,
                    "包文件不存在或无法读取: " + e.getMessage());
        } catch (Exception e) {
            // 未预料的内部错误：明确归类，不混为“包损坏”，也不向上抛未归类异常
            log.error("归档包核验出现未预料的内部错误", e);
            return single(ArchiveFailureReason.INTERNAL_ERROR,
                    "核验过程出现未预料的内部错误: " + e);
        }
        return finish(s, expectedEnvironmentId);
    }

    private void readEvents(JsonParser p, State s) throws IOException {
        if (s.fromSeq == null || s.toSeq == null || s.declaredCount == null) {
            s.withIssue(ArchiveFailureReason.MALFORMED_PACKAGE, null, null,
                    "events 出现在完整元数据之前，无法定位区间");
            p.skipChildren();
            return;
        }
        if (p.currentToken() != JsonToken.START_ARRAY) {
            s.withIssue(ArchiveFailureReason.MALFORMED_PACKAGE, null, null, "events 不是数组");
            p.skipChildren();
            return;
        }
        String canonical = signer.canonicalMetadata(s.environmentId, s.exportedAt,
                s.fromSeq, s.toSeq, s.declaredCount, s.prevHash, s.headHash, s.tailHash);
        s.digest = signer.newDigest(canonical);

        long expectedSeq = s.fromSeq;
        String expectedPrev = s.prevHash;
        while (p.nextToken() == JsonToken.START_OBJECT) {
            AuditEvent e = mapper.readValue(p, AuditEvent.class);
            s.scanned++;
            if (e.eventId() == null || e.hash() == null) {
                s.withIssue(ArchiveFailureReason.MALFORMED_PACKAGE, null, null,
                        "第 " + s.scanned + " 条事件缺少必要字段");
                continue;
            }
            String recomputed = hasher.computeHash(e);
            if (!recomputed.equals(e.hash())) {
                s.withIssue(ArchiveFailureReason.ENTRY_HASH_MISMATCH, e.seq(), e.eventId(),
                        "事件内容被改动: 存储 hash 与复算 hash 不一致");
            }
            // 序号：先记“疑似空洞”，若之后该序号出现则改判为重排；
            // 流结束时仍未补上的空洞才判定为记录被删除。
            if (e.seq() > expectedSeq) {
                if (e.seq() - expectedSeq > MAX_TRACKED_GAP) {
                    // 空洞过大不可能是乱序，直接判定删除，避免恶意包撑爆内存
                    s.withIssue(ArchiveFailureReason.SEQUENCE_GAP, expectedSeq, null,
                            "序号从 " + expectedSeq + " 直接跳到 " + e.seq() + "，大量记录被删除");
                } else {
                    for (long missing = expectedSeq; missing < e.seq(); missing++) {
                        s.pendingGaps.add(missing);
                    }
                }
            } else if (e.seq() < expectedSeq) {
                s.pendingGaps.remove(e.seq());
                s.withIssue(ArchiveFailureReason.ORDER_VIOLATION, e.seq(), e.eventId(),
                        "期望 seq=" + expectedSeq + " 实际 seq=" + e.seq() + "，顺序被打乱");
            }
            if (!Objects.equals(e.prevHash(), expectedPrev)) {
                s.withIssue(ArchiveFailureReason.LINK_MISMATCH, e.seq(), e.eventId(),
                        "prevHash 与预期链节不一致");
            }
            s.digest.addEventHash(e.hash());
            expectedPrev = e.hash();
            expectedSeq = Math.max(expectedSeq, e.seq() + 1);
            s.lastSeq = e.seq();
        }
        if (!s.pendingGaps.isEmpty()) {
            s.withIssue(ArchiveFailureReason.SEQUENCE_GAP, s.pendingGaps.first(), null,
                    "序号 " + s.pendingGaps.first() + " 起共 " + s.pendingGaps.size()
                            + " 条记录缺失，中间记录被删除");
        }
    }

    private ArchiveVerification single(ArchiveFailureReason reason, String detail) {
        ArchiveVerification result = ArchiveVerification.invalid(null, 0, 0, 0,
                List.of(new ArchiveIssue(reason, null, null, detail)));
        log.info("归档包离线核验: 结论=无效, 主因={}, 判定依据={}", reason, detail);
        return result;
    }

    private ArchiveVerification finish(State s, String expectedEnvironmentId) {
        // 格式与版本
        if (!ArchiveSigner.FORMAT.equals(s.format)) {
            s.withIssue(ArchiveFailureReason.UNSUPPORTED_FORMAT, null, null,
                    "不认识的包格式: " + s.format);
        } else if (s.formatVersion != ArchiveSigner.FORMAT_VERSION) {
            s.withIssue(ArchiveFailureReason.UNSUPPORTED_FORMAT, null, null,
                    "不支持的格式版本: " + s.formatVersion);
        }
        boolean metadataMissing = s.environmentId == null || s.fromSeq == null || s.toSeq == null
                || s.declaredCount == null || s.prevHash == null || s.headHash == null
                || s.tailHash == null || s.manifestHash == null || s.signature == null
                || s.digest == null;
        if (metadataMissing && !s.parseFailed) {
            s.withIssue(ArchiveFailureReason.MALFORMED_PACKAGE, null, null,
                    "包缺少必要字段（元数据/事件/清单哈希/签名不完整）");
        }

        // 环境身份
        if (s.environmentId != null && expectedEnvironmentId != null
                && !s.environmentId.equals(expectedEnvironmentId)) {
            s.withIssue(ArchiveFailureReason.ENVIRONMENT_MISMATCH, null, null,
                    "包来源环境=" + s.environmentId + " 与期望环境=" + expectedEnvironmentId + " 不符");
        }
        Optional<String> key = s.environmentId == null
                ? Optional.empty() : keys.keyFor(s.environmentId);
        if (s.environmentId != null && key.isEmpty()) {
            s.withIssue(ArchiveFailureReason.UNTRUSTED_ENVIRONMENT, null, null,
                    "没有环境 " + s.environmentId + " 的核验密钥，无法确认包来源");
        }

        // 结构结论
        if (s.digest != null && s.scanned == 0 && !s.hasStructuralIssue()) {
            s.withIssue(ArchiveFailureReason.EMPTY_ARCHIVE, null, null,
                    "包内没有任何事件，空包不能作为完整性证据");
        }
        if (s.declaredCount != null && s.digest != null && s.scanned != s.declaredCount) {
            s.withIssue(ArchiveFailureReason.TRUNCATED, s.lastSeq, null,
                    "实际事件数=" + s.scanned + " 与清单声明 count=" + s.declaredCount + " 不一致");
        }
        if (s.toSeq != null && s.digest != null && s.scanned > 0
                && s.lastSeq != null && s.lastSeq.longValue() != s.toSeq.longValue()) {
            s.withIssue(ArchiveFailureReason.TRUNCATED, s.lastSeq, null,
                    "实际尾部 seq=" + s.lastSeq + " 与清单声明 toSeq=" + s.toSeq + " 不一致，尾部被截断");
        }

        // 清单与签名（有密钥才验签）
        if (s.digest != null && s.manifestHash != null
                && !s.digest.hex().equals(s.manifestHash)) {
            s.withIssue(ArchiveFailureReason.MANIFEST_MISMATCH, null, null,
                    "清单哈希与包内容不符，内容被改动后未重签");
        }
        if (s.manifestHash != null && s.signature != null && key.isPresent()) {
            String expected = signer.hmacSha256Hex(key.get(), s.manifestHash);
            if (!expected.equals(s.signature)) {
                s.withIssue(ArchiveFailureReason.SIGNATURE_MISMATCH, null, null,
                        "签名不符：包被伪造、掉包，或非本信任域密钥签发");
            }
        }

        boolean valid = s.issues.isEmpty();
        long from = s.fromSeq == null ? 0 : s.fromSeq;
        long to = s.toSeq == null ? 0 : s.toSeq;
        ArchiveVerification result = valid
                ? ArchiveVerification.ok(s.environmentId, from, to, s.scanned)
                : ArchiveVerification.invalid(s.environmentId, from, to, s.scanned, s.issues);
        log.info("归档包离线核验: 结论={}, 主因={}, env={}, 区间=[{},{}], 扫描条目={}, 问题数={}",
                valid ? "有效" : "无效", result.primaryReason(), s.environmentId, from, to,
                s.scanned, s.issues.size());
        s.issues.forEach(i -> log.warn("  判定依据: reason={}, seq={}, eventId={}, detail={}",
                i.reason(), i.seq(), i.eventId(), i.detail()));
        return result;
    }

    private static final class State {
        String format;
        int formatVersion = -1;
        String environmentId;
        long exportedAt;
        Long fromSeq;
        Long toSeq;
        Long declaredCount;
        String prevHash;
        String headHash;
        String tailHash;
        String manifestHash;
        String signature;
        ArchiveSigner.ManifestDigest digest;
        long scanned;
        Long lastSeq;
        boolean parseFailed;
        final TreeSet<Long> pendingGaps = new TreeSet<>();
        final List<ArchiveIssue> issues = new ArrayList<>();

        State withIssue(ArchiveFailureReason reason, Long seq, String eventId, String detail) {
            if (issues.size() < MAX_ISSUES) {
                issues.add(new ArchiveIssue(reason, seq, eventId, detail));
            }
            return this;
        }

        boolean hasStructuralIssue() {
            return issues.stream().anyMatch(i -> i.reason() == ArchiveFailureReason.ENTRY_HASH_MISMATCH
                    || i.reason() == ArchiveFailureReason.SEQUENCE_GAP
                    || i.reason() == ArchiveFailureReason.ORDER_VIOLATION
                    || i.reason() == ArchiveFailureReason.LINK_MISMATCH);
        }
    }
}
