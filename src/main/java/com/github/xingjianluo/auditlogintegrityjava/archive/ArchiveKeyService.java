package com.github.xingjianluo.auditlogintegrityjava.archive;

import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import com.github.xingjianluo.auditlogintegrityjava.storage.AuditStoreException;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 环境签名密钥服务：每个环境一对 Ed25519 密钥，首次使用时生成并持久化在数据目录
 * （{@code archive-signing.key} / {@code archive-signing.pub}）。
 *
 * <p>环境标识 environmentId = "env-" + SHA-256(公钥) 前 16 位十六进制，
 * 完全由公钥派生：核验方用同一把公钥可独立算出同一标识，
 * 不同环境的包因此无法互相顶替。私钥永不出环境。
 */
@Service
public class ArchiveKeyService {

    private static final String KEY_ALGORITHM = "Ed25519";
    private static final String PRIVATE_KEY_FILE = "archive-signing.key";
    private static final String PUBLIC_KEY_FILE = "archive-signing.pub";

    private final Path privateKeyFile;
    private final Path publicKeyFile;

    private volatile PrivateKey privateKey;
    private volatile byte[] publicKeyBytes;
    private volatile String environmentId;

    public ArchiveKeyService(AuditProperties properties) {
        Path dir = Path.of(properties.getDataDir());
        this.privateKeyFile = dir.resolve(PRIVATE_KEY_FILE);
        this.publicKeyFile = dir.resolve(PUBLIC_KEY_FILE);
        loadOrGenerate();
    }

    /** 本环境标识（由公钥派生）。 */
    public String environmentId() {
        return environmentId;
    }

    /** 本环境公钥（X.509 编码字节），带外交付给核验方。 */
    public byte[] publicKeyBytes() {
        return publicKeyBytes.clone();
    }

    /** 用本环境私钥签名，返回 Base64 签名。 */
    public synchronized String sign(byte[] data) {
        try {
            Signature signer = Signature.getInstance(KEY_ALGORITHM);
            signer.initSign(privateKey);
            signer.update(data);
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("归档签名失败", e);
        }
    }

    /** 由公钥派生环境标识（核验方用同一算法独立复算）。 */
    public static String environmentIdOf(byte[] publicKeyBytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(publicKeyBytes);
            StringBuilder hex = new StringBuilder(16);
            for (int i = 0; i < 8; i++) {
                hex.append(Character.forDigit((digest[i] >> 4) & 0xF, 16));
                hex.append(Character.forDigit(digest[i] & 0xF, 16));
            }
            return "env-" + hex;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** 用给定公钥核验签名（离线核验路径，不依赖本环境密钥）。 */
    public static boolean verifySignature(byte[] publicKeyBytes, byte[] data, String signatureBase64) {
        try {
            KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
            PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            Signature verifier = Signature.getInstance(KEY_ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    // ---- 密钥的加载/生成/持久化 ----

    private synchronized void loadOrGenerate() {
        try {
            if (Files.exists(privateKeyFile) && Files.exists(publicKeyFile)) {
                byte[] privBytes = Base64.getDecoder().decode(
                        Files.readString(privateKeyFile, StandardCharsets.UTF_8).trim());
                byte[] pubBytes = Base64.getDecoder().decode(
                        Files.readString(publicKeyFile, StandardCharsets.UTF_8).trim());
                KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
                this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
                this.publicKeyBytes = pubBytes;
            } else {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
                KeyPair pair = generator.generateKeyPair();
                this.privateKey = pair.getPrivate();
                this.publicKeyBytes = pair.getPublic().getEncoded();
                Files.createDirectories(privateKeyFile.getParent());
                writeAtomically(privateKeyFile,
                        Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
                writeAtomically(publicKeyFile,
                        Base64.getEncoder().encodeToString(publicKeyBytes));
            }
            this.environmentId = environmentIdOf(publicKeyBytes);
        } catch (GeneralSecurityException | IOException | IllegalArgumentException e) {
            throw new AuditStoreException("加载/生成归档签名密钥失败: " + privateKeyFile.getParent(), e);
        }
    }

    private static void writeAtomically(Path target, String content) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        try {
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException atomicFailed) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
