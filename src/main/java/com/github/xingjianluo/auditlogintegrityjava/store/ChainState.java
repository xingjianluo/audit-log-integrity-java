package com.github.xingjianluo.auditlogintegrityjava.store;

import com.github.xingjianluo.auditlogintegrityjava.model.ChainAnchor;
import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;

import java.util.List;

/**
 * Immutable, self-consistent view of the chain: records together with the
 * anchor and tail pointer that describe them. Mutations replace the whole
 * state atomically under the store lock, so readers never observe a mixture
 * of, e.g., post-prune records with a pre-prune tail pointer.
 */
record ChainState(List<StoredRecord> records, ChainAnchor anchor,
                  long tailSeq, String tailHash) {

    static ChainState genesis() {
        return new ChainState(List.of(), null, 0L,
                com.github.xingjianluo.auditlogintegrityjava.service.ChainIntegrityVerifier.GENESIS);
    }
}
