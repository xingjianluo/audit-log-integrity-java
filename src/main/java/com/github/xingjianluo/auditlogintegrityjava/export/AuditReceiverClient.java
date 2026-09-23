package com.github.xingjianluo.auditlogintegrityjava.export;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;

/**
 * 本地模拟接收端：以 eventId 幂等；可模拟异常/乱序。
 */
public interface AuditReceiverClient {

    enum Ack { ACCEPTED, DUPLICATE }

    Ack deliver(AuditEvent event) throws ReceiverException;
}
