package com.github.xingjianluo.auditlogintegrityjava.masking;

/**
 * One-way masking of a single sensitive value. Implementations must be
 * deterministic per strategy version so historical records stay reproducible,
 * and irreversible: the plaintext must not be recoverable from the output.
 */
public interface MaskingStrategy {
    String version();
    String mask(String plain);
}
