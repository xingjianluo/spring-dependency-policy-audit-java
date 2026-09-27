package com.github.xingjianluo.springdependencypolicyauditjava.config;

import com.github.xingjianluo.springdependencypolicyauditjava.decision.PolicyEngine;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 基础 Bean 装配：可注入固定时钟以便确定性测试。 */
@Configuration
public class AppConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public PolicyEngine policyEngine(Clock clock) {
        return new PolicyEngine(clock);
    }
}
