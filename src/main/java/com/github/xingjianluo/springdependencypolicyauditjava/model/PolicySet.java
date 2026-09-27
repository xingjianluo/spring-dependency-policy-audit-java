package com.github.xingjianluo.springdependencypolicyauditjava.model;

import java.util.List;
import java.util.Map;

/**
 * 一整套可配置策略，带版本号，保证结论可追溯与可复现。
 */
public record PolicySet(
        String policyVersion,
        Verdict defaultVerdict,
        Severity severityThreshold,
        List<PolicyRule> rules,
        List<PolicyException> exceptions,
        Map<String, Severity> advisorySeverityByName
) {
}
