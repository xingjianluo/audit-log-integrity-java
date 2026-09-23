package com.github.xingjianluo.auditlogintegrityjava.config;

import com.github.xingjianluo.auditlogintegrityjava.crypto.HashService;
import com.github.xingjianluo.auditlogintegrityjava.masking.ConfigurableFieldMaskingPolicy;
import com.github.xingjianluo.auditlogintegrityjava.masking.HashMaskingStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashSet;

/**
 * Wires the versioned masking strategy and field policy from properties.
 */
@Configuration
public class AuditConfig {

    @Bean
    public HashMaskingStrategy hashMaskingStrategy(AuditProperties props, HashService hashService) {
        return new HashMaskingStrategy(hashService, props.getMaskingSalt(), "v1");
    }

    @Bean
    public ConfigurableFieldMaskingPolicy fieldMaskingPolicy(HashMaskingStrategy strategy,
                                                             HashService hashService,
                                                             AuditProperties props) {
        return new ConfigurableFieldMaskingPolicy(strategy, hashService,
                new HashSet<>(props.getSensitiveFields()));
    }
}
