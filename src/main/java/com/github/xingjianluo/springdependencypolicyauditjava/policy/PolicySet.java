package com.github.xingjianluo.springdependencypolicyauditjava.policy;

import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;

import java.util.List;

/**
 * 完整策略集合。策略一旦加载即不可变，保证判定可重复。
 */
public record PolicySet(
        String policyVersion,
        Severity maxSeverity,
        List<String> enforcedScopes,
        List<PolicyRule> rules,
        List<Advisory> advisories,
        List<ExceptionGrant> exceptions) {

    public PolicySet {
        rules = rules == null ? List.of() : List.copyOf(rules);
        advisories = advisories == null ? List.of() : List.copyOf(advisories);
        exceptions = exceptions == null ? List.of() : List.copyOf(exceptions);
        enforcedScopes = enforcedScopes == null ? List.of() : List.copyOf(enforcedScopes);
    }
}
