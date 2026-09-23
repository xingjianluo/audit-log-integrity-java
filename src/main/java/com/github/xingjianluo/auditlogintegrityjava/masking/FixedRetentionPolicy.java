package com.github.xingjianluo.auditlogintegrityjava.masking;

import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class FixedRetentionPolicy implements RetentionPolicy {

    private static final long DAY_MILLIS = TimeUnit.DAYS.toMillis(1);

    private final AuditProperties properties;

    public FixedRetentionPolicy(AuditProperties properties) {
        this.properties = properties;
    }

    @Override
    public long maxAgeMillis() {
        return properties.getRetentionDays() * DAY_MILLIS;
    }

    @Override
    public int batchSize() {
        return properties.getCleanupBatchSize();
    }
}
