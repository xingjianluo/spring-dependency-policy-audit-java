package com.github.xingjianluo.springdependencypolicyauditjava.model;

import java.time.Instant;

/**
 * 单个依赖的判定结论。
 */
public record DependencyDecision(
        String dependencyFingerprint,
        String name,
        String version,
        DependencyScope scope,
        Verdict verdict,
        FailureReason failureReason,
        Severity advisorySeverity,
        String matchedRule,
        String matchedExceptionId,
        String policyVersion,
        String basis,
        Instant decidedAt
) {
}
