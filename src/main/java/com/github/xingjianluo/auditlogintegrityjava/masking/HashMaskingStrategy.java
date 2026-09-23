package com.github.xingjianluo.auditlogintegrityjava.masking;

import com.github.xingjianluo.auditlogintegrityjava.crypto.HashService;

/**
 * Masks a value as {@code mask:<version>:<8 hex chars of salted SHA-256>}.
 * The digest is truncated and salted, so the plaintext is not recoverable
 * and identical values across records still correlate for audit analysis.
 */
public class HashMaskingStrategy implements MaskingStrategy {

    private final HashService hashService;
    private final String salt;
    private final String version;

    public HashMaskingStrategy(HashService hashService, String salt, String version) {
        this.hashService = hashService;
        this.salt = salt;
        this.version = version;
    }

    @Override
    public String version() {
        return version;
    }

    @Override
    public String mask(String plain) {
        if (plain == null) {
            return null;
        }
        String digest = hashService.sha256Hex("mask|" + version + "|" + salt + "|" + plain);
        return "mask:" + version + ":" + digest.substring(0, 8);
    }
}
