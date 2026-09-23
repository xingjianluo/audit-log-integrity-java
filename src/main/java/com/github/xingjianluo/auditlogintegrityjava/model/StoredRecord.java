package com.github.xingjianluo.auditlogintegrityjava.model;

import java.util.Map;

/**
 * One immutable, append-only record in the integrity chain.
 * {@code seq} is gap-less starting after the chain anchor; {@code prevHash}
 * links to the previous record hash (or the anchor hash at the head).
 */
public record StoredRecord(
        long seq,
        String eventId,
        long timestamp,
        String actor,
        String action,
        String resource,
        Map<String, String> detail,
        String policyVersion,
        String prevHash,
        String hash) {
}
