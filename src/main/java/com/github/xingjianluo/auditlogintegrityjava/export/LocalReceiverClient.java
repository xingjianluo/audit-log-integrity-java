package com.github.xingjianluo.auditlogintegrityjava.export;

import com.github.xingjianluo.auditlogintegrityjava.chain.AuditEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地内存模拟接收端：
 * <ul>
 *   <li>以 eventId 幂等：重复投递返回 {@link Ack#DUPLICATE}，不产生副作用；</li>
 *   <li>{@code failing=true} 时所有投递抛 {@link ReceiverException}，模拟接收端故障；</li>
 *   <li>投递动作本身与事件顺序无关，调用方可乱序投递以验证幂等。</li>
 * </ul>
 */
@Component
public class LocalReceiverClient implements AuditReceiverClient {

    private static final Logger log = LoggerFactory.getLogger(LocalReceiverClient.class);

    private final Set<String> acceptedEventIds = ConcurrentHashMap.newKeySet();
    private volatile boolean failing;

    public void setFailing(boolean failing) {
        this.failing = failing;
        log.info("模拟接收端故障开关 -> {}", failing);
    }

    public void reset() {
        acceptedEventIds.clear();
        failing = false;
        log.info("模拟接收端已重置");
    }

    @Override
    public Ack deliver(AuditEvent event) {
        if (failing) {
            throw new ReceiverException("模拟接收端不可用，拒绝接收 eventId=" + event.eventId());
        }
        boolean firstTime = acceptedEventIds.add(event.eventId());
        if (firstTime) {
            log.info("接收端接受事件: eventId={}, seq={}", event.eventId(), event.seq());
            return Ack.ACCEPTED;
        }
        log.info("接收端识别重复投递并忽略: eventId={}, seq={}", event.eventId(), event.seq());
        return Ack.DUPLICATE;
    }
}
