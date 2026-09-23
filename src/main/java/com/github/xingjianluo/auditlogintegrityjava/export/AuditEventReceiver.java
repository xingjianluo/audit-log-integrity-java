package com.github.xingjianluo.auditlogintegrityjava.export;

import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;

/**
 * Simulated remote receiver. Implementations must be idempotent per seq:
 * duplicate or out-of-order redelivery of the same record must not create
 * duplicates. They may reject/throw to simulate receiver failure.
 */
public interface AuditEventReceiver {

    /**
     * @throws ReceiverException when the receiver is unavailable or rejects
     */
    void deliver(StoredRecord record) throws ReceiverException;
}
