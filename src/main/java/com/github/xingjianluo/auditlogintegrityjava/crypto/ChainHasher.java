package com.github.xingjianluo.auditlogintegrityjava.crypto;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.TreeMap;

/**
 * 链式哈希：entryHash = SHA-256(prevHash || 规范化事件内容)。
 *
 * <p>规范化串（UTF-8）为，字段顺序固定：
 * <pre>
 * seq \n timestamp \n eventId \n actor \n action \n resource \n policyVersion \n prevHash \n
 * k1=v1&amp;k2=v2...   (payload 按 key 字典序排序；null 值记为空串)
 * </pre>
 * 事件自身的 hash 字段不参与计算，因此可在落盘/读盘后独立复算比对。
 */
@Component
public class ChainHasher {

    public static final String GENESIS_HASH = "0".repeat(64);

    /**
     * payload 的规范化表示：key 按字典序排列，保证同一 Map 无论迭代顺序如何结果一致。
     */
    public String canonicalPayload(Map<String, String> payload) {
        if (payload == null || payload.isEmpty()) {
            return "";
        }
        TreeMap<String, String> sorted = new TreeMap<>(payload);
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> e : sorted.entrySet()) {
            if (!first) {
                sb.append('&');
            }
            first = false;
            sb.append(e.getKey()).append('=').append(e.getValue() == null ? "" : e.getValue());
        }
        return sb.toString();
    }

    /**
     * 计算一条事件的入口哈希（不依赖 event.hash() 字段）。
     */
    public String computeHash(AuditEvent event) {
        String canonical = String.join("\n",
                Long.toString(event.seq()),
                Long.toString(event.timestamp()),
                nullToEmpty(event.eventId()),
                nullToEmpty(event.actor()),
                nullToEmpty(event.action()),
                nullToEmpty(event.resource()),
                Integer.toString(event.policyVersion()),
                nullToEmpty(event.prevHash()),
                canonicalPayload(event.payload()));
        return sha256Hex(canonical);
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
