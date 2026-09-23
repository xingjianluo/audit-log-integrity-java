package com.github.xingjianluo.auditlogintegrityjava.store;

import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;

import java.util.List;

/**
 * Consistent snapshot of one log read: successfully parsed records, the
 * 1-based line numbers of unparseable lines, and the persisted tail
 * pointer (lastSeq/lastHash) used to detect tail truncation.
 */
public record LogSnapshot(
        List<StoredRecord> records,
        List<Integer> corruptLineNumbers,
        long tailSeq,
        String tailHash) {
}
