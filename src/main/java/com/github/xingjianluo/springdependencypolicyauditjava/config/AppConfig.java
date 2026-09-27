package com.github.xingjianluo.springdependencypolicyauditjava.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * 应用 Bean 配置（骨架）。
 */
@Configuration
@EnableConfigurationProperties({AuditProperties.class, PolicyProperties.class})
public class AppConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
