package com.github.xingjianluo.springdependencypolicyauditjava.decision;

import com.github.xingjianluo.springdependencypolicyauditjava.model.Dependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;

import java.util.List;

/**
 * 单个依赖的判定记录：结论、依据、命中策略/情报/例外，保证可解释、可复现。
 */
public record DependencyDecision(
        String coordinate,
        String fingerprint,
        Decision decision,
        Severity severity,
        String reasonCode,
        String reason,
        List<String> matchedRuleIds,
        String matchedAdvisoryId,
        String matchedExceptionId,
        String policyVersion) {
}
