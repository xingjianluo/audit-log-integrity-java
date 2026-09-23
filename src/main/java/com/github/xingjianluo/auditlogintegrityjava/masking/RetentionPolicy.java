package com.github.xingjianluo.auditlogintegrityjava.masking;

/**
 * Retention policy: records older than {@link #maxAgeMillis()} may be pruned,
 * but pruning must happen in bounded batches.
 */
public interface RetentionPolicy {
    long maxAgeMillis();
    int batchSize();
}
