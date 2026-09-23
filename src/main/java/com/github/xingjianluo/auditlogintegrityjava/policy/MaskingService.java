package com.github.xingjianluo.auditlogintegrityjava.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import org.springframework.stereotype.Service;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * 敏感字段脱敏服务。
 *
 * <p>要点：
 * <ul>
 *   <li>落盘前把敏感字段值整体替换为固定掩码 token，不可逆，且不同明文产生相同 token
 *       （不保留任何可反推特征，如长度）；</li>
 *   <li>每条策略带单调递增版本号，事件记录写入时的版本号；</li>
 *   <li>策略变更只影响之后写入的事件，历史事件中的脱敏值与版本号不变，
 *       因而历史校验结论始终可复现。</li>
 * </ul>
 */
@Service
public class MaskingService {

    private final ObjectMapper mapper;
    private final Path policyFile;
    private volatile MaskingPolicy current;

    public MaskingService(AuditProperties properties, ObjectMapper mapper) {
        this.mapper = mapper;
        this.policyFile = Path.of(properties.getDataDir()).resolve("policy.json");
        this.current = loadOrInit(properties);
    }

    public MaskingPolicy current() {
        return current;
    }

    /**
     * 按给定策略返回脱敏后的新 payload（不修改入参）。
     */
    public Map<String, String> mask(Map<String, String> payload, MaskingPolicy policy) {
        Map<String, String> result = new LinkedHashMap<>();
        if (payload != null) {
            for (Map.Entry<String, String> e : payload.entrySet()) {
                boolean sensitive = e.getKey() != null && policy.sensitiveFields().contains(e.getKey());
                if (sensitive) {
                    result.put(e.getKey(), policy.maskToken());
                } else {
                    result.put(e.getKey(), e.getValue());
                }
            }
        }
        return result;
    }

    /**
     * 变更策略：版本号 +1 并持久化。敏感字段集合内容未变时不产生新版本。
     */
    public synchronized MaskingPolicy updatePolicy(Set<String> sensitiveFields, String maskToken) {
        Set<String> normalized = new TreeSet<>();
        if (sensitiveFields != null) {
            sensitiveFields.stream().filter(f -> f != null && !f.isBlank()).forEach(normalized::add);
        }
        String token = (maskToken == null || maskToken.isBlank()) ? current.maskToken() : maskToken;

        if (normalized.equals(new TreeSet<>(current.sensitiveFields())) && token.equals(current.maskToken())) {
            return current;
        }
        MaskingPolicy next = new MaskingPolicy(current.version() + 1, normalized, token);
        persist(next);
        this.current = next;
        return next;
    }

    private MaskingPolicy loadOrInit(AuditProperties properties) {
        try {
            if (Files.exists(policyFile)) {
                MaskingPolicy loaded = mapper.readValue(Files.readAllBytes(policyFile), MaskingPolicy.class);
                return new MaskingPolicy(loaded.version(),
                        new TreeSet<>(loaded.sensitiveFields()), loaded.maskToken());
            }
        } catch (IOException e) {
            throw new AuditStoreException("读取脱敏策略文件失败", e);
        }
        MaskingPolicy initial = new MaskingPolicy(1,
                new TreeSet<>(properties.getSensitiveFields()), properties.getMaskToken());
        persist(initial);
        return initial;
    }

    private void persist(MaskingPolicy policy) {
        Path tmp = policyFile.resolveSibling("policy.json.tmp");
        try {
            Files.createDirectories(policyFile.getParent());
            try (BufferedWriter w = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                w.write(mapper.writeValueAsString(policy));
                w.flush();
            }
            try {
                Files.move(tmp, policyFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicFailed) {
                Files.move(tmp, policyFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new AuditStoreException("持久化脱敏策略失败", e);
        }
    }
}
