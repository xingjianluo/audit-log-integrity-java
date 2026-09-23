package com.github.xingjianluo.auditlogintegrityjava;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import com.github.xingjianluo.auditlogintegrityjava.config.AuditProperties;

@SpringBootApplication
@EnableConfigurationProperties(AuditProperties.class)
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
