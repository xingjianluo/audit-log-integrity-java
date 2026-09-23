package com.github.xingjianluo.auditlogintegrityjava.crypto;

/**
 * Deterministic one-way hashing used for chain links and field fingerprints.
 */
public interface HashService {
    String sha256Hex(String input);
}
