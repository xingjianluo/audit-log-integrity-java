package com.github.xingjianluo.auditlogintegrityjava.model;

/**
 * Immutable head anchor after a retention cleanup batch: the first surviving
 * record must link back to this anchor, so authorized batch pruning stays
 * verifiable and arbitrary head truncation is detectable.
 */
public record ChainAnchor(long seq, String hash, long updatedAt) {
}
