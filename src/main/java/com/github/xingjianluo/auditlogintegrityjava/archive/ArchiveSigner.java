package com.github.xingjianluo.auditlogintegrityjava.archive;

import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 归档清单哈希与签名。
 *
 * <p>manifestHash = SHA-256( 规范化元数据 || 每条事件 hash 按序连接 )，可流式滚动计算，
 * 核验侧无需把全部事件载入内存。signature = HMAC-SHA256(环境密钥, manifestHash)。
 * 没有环境密钥的人无法为伪造/掉包的包算出合法签名。
 */
@Component
public class ArchiveSigner {

    public static final String FORMAT = "audit-archive";
    public static final int FORMAT_VERSION = 1;

    /**
     * 元数据规范化串（字段顺序固定，UTF-8）。
     */
    public String canonicalMetadata(String environmentId, long exportedAt,
                                    long fromSeq, long toSeq, long count,
                                    String prevHash, String headHash, String tailHash) {
        return String.join("\n",
                FORMAT,
                Integer.toString(FORMAT_VERSION),
                nullToEmpty(environmentId),
                Long.toString(exportedAt),
                Long.toString(fromSeq),
                Long.toString(toSeq),
                Long.toString(count),
                nullToEmpty(prevHash),
                nullToEmpty(headHash),
                nullToEmpty(tailHash)) + "\n";
    }

    /**
     * 滚动清单哈希：先喂元数据，再按包内顺序逐条喂事件 hash。
     */
    public ManifestDigest newDigest(String canonicalMetadata) {
        return new ManifestDigest(canonicalMetadata);
    }

    public String hmacSha256Hex(String key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return toHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    public static final class ManifestDigest {
        private final MessageDigest digest;

        ManifestDigest(String canonicalMetadata) {
            try {
                this.digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 unavailable", e);
            }
            digest.update(canonicalMetadata.getBytes(StandardCharsets.UTF_8));
        }

        public void addEventHash(String eventHash) {
            digest.update(nullToEmpty(eventHash).getBytes(StandardCharsets.UTF_8));
            digest.update((byte) '\n');
        }

        public String hex() {
            return toHex(digest.digest());
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(Character.forDigit((b >> 4) & 0xF, 16));
            hex.append(Character.forDigit(b & 0xF, 16));
        }
        return hex.toString();
    }
}
