package com.github.xingjianluo.auditlogintegrityjava.export;

import com.github.xingjianluo.auditlogintegrityjava.model.StoredRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Local in-memory simulation of a remote receiver. Keyed by seq, so
 * duplicate or out-of-order redelivery is a no-op (idempotent). A failing
 * switch simulates receiver outage; out-of-order acceptance is also allowed,
 * matching an at-least-once channel.
 */
@Component
public class InMemoryAuditEventReceiver implements AuditEventReceiver {

    private static final Logger log = LoggerFactory.getLogger(InMemoryAuditEventReceiver.class);

    private final Map<Long, StoredRecord> received = new ConcurrentHashMap<>();
    private volatile boolean failing;

    public void setFailing(boolean failing) {
        this.failing = failing;
    }

    public boolean isFailing() {
        return failing;
    }

    public Map<Long, StoredRecord> received() {
        return received;
    }

    public void reset() {
        received.clear();
        failing = false;
    }

    @Override
    public void deliver(StoredRecord record) throws ReceiverException {
        if (failing) {
            log.warn("receiver SIMULATED FAILURE rejecting seq={} eventId={}",
                    record.seq(), record.eventId());
            throw new ReceiverException("simulated receiver outage for seq=" + record.seq());
        }
        StoredRecord previous = received.putIfAbsent(record.seq(), record);
        if (previous != null) {
            log.info("receiver accepted DUPLICATE idempotently seq={} eventId={}",
                    record.seq(), record.eventId());
        } else {
            log.info("receiver accepted seq={} eventId={}", record.seq(), record.eventId());
        }
    }
}
