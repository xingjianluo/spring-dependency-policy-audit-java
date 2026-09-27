package com.github.xingjianluo.springdependencypolicyauditjava.tests.policy;

import com.github.xingjianluo.springdependencypolicyauditjava.model.DependencyDecision;
import com.github.xingjianluo.springdependencypolicyauditjava.model.DependencyScope;
import com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason;
import com.github.xingjianluo.springdependencypolicyauditjava.model.NormalizedDependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.PolicyException;
import com.github.xingjianluo.springdependencypolicyauditjava.model.PolicyRule;
import com.github.xingjianluo.springdependencypolicyauditjava.model.PolicySet;
import com.github.xingjianluo.springdependencypolicyauditjava.model.RuleAction;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Verdict;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.LocalPolicyLoader;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyEvaluator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 覆盖：阈值放行/阻断、ALLOW/DENY 名单、冲突 DENY 优先、
 * 例外生效/过期/作用域不匹配、默认 DENY、确定性重复执行、策略加载校验。
 */
class PolicyEvaluationTest {

    private static final Instant NOW = Instant.parse("2026-09-28T00:00:00Z");
    private final PolicyEvaluator evaluator =
            new PolicyEvaluator(Clock.fixed(NOW, ZoneOffset.UTC));

    private NormalizedDependency dep(String name, String version, DependencyScope scope) {
        return new NormalizedDependency(name, version, scope,
                "fp-" + name + ":" + version, name + ":" + version, "manifest-json");
    }

    private PolicySet policy(Verdict defaultVerdict,
                             Severity threshold,
                             List<PolicyRule> rules,
                             List<PolicyException> exceptions,
                             Map<String, Severity> advisory) {
        return new PolicySet("test-policy-1", defaultVerdict, threshold,
                rules, exceptions, advisory);
    }

    @Test
    void severity_below_threshold_passes_when_allowed() {
        PolicySet set = policy(Verdict.DENY, Severity.HIGH,
                List.of(new PolicyRule(RuleAction.ALLOW, "org.example:*", "*", Set.of(), "")),
                List.of(), Map.of("org.example:lib", Severity.LOW));
        DependencyDecision d = evaluator.evaluate(set, dep("org.example:lib", "1.0.0", DependencyScope.COMPILE));
        assertThat(d.verdict()).isEqualTo(Verdict.PASS);
        assertThat(d.failureReason()).isNull();
        assertThat(d.advisorySeverity()).isEqualTo(Severity.LOW);
    }

    @Test
    void severity_at_threshold_is_denied_without_exception() {
        PolicySet set = policy(Verdict.DENY, Severity.HIGH,
                List.of(new PolicyRule(RuleAction.ALLOW, "org.example:*", "*", Set.of(), "")),
                List.of(), Map.of("org.example:risky", Severity.HIGH));
        DependencyDecision d = evaluator.evaluate(set, dep("org.example:risky", "2.3.4", DependencyScope.RUNTIME));
        assertThat(d.verdict()).isEqualTo(Verdict.DENY);
        assertThat(d.failureReason()).isEqualTo(FailureReason.SEVERITY_THRESHOLD_EXCEEDED);
        assertThat(d.basis()).contains("HIGH");
    }

    @Test
    void active_exception_makes_conditional_pass_with_audit_fields() {
        PolicyException exc = new PolicyException("EXC-1", "org.example:risky", "2.3.*",
                Set.of(DependencyScope.RUNTIME),
                NOW.plusSeconds(3600), "alice@local", "risk accepted");
        PolicySet set = policy(Verdict.DENY, Severity.HIGH,
                List.of(), List.of(exc), Map.of("org.example:risky", Severity.CRITICAL));
        DependencyDecision d = evaluator.evaluate(set, dep("org.example:risky", "2.3.9", DependencyScope.RUNTIME));
        assertThat(d.verdict()).isEqualTo(Verdict.CONDITIONAL_PASS);
        assertThat(d.matchedExceptionId()).isEqualTo("EXC-1");
        assertThat(d.policyVersion()).isEqualTo("test-policy-1");
        assertThat(d.basis()).contains("alice@local", "risk accepted", "CRITICAL");
    }

    @Test
    void expired_exception_is_ignored_and_reason_is_exception_expired() {
        PolicyException exc = new PolicyException("EXC-OLD", "org.example:risky", "*",
                Set.of(), NOW.minusSeconds(1), "bob@local", "old");
        PolicySet set = policy(Verdict.DENY, Severity.HIGH,
                List.of(), List.of(exc), Map.of("org.example:risky", Severity.HIGH));
        DependencyDecision d = evaluator.evaluate(set, dep("org.example:risky", "2.3.9", DependencyScope.COMPILE));
        assertThat(d.verdict()).isEqualTo(Verdict.DENY);
        assertThat(d.failureReason()).isEqualTo(FailureReason.EXCEPTION_EXPIRED);
        assertThat(d.basis()).contains("EXC-OLD", "expired");
    }

    @Test
    void exception_scoped_to_test_does_not_apply_to_compile() {
        PolicyException exc = new PolicyException("EXC-S", "org.example:risky", "*",
                Set.of(DependencyScope.TEST), NOW.plusSeconds(3600), "carol@local", "test only");
        PolicySet set = policy(Verdict.DENY, Severity.HIGH,
                List.of(), List.of(exc), Map.of("org.example:risky", Severity.HIGH));
        DependencyDecision d = evaluator.evaluate(set, dep("org.example:risky", "2.3.9", DependencyScope.COMPILE));
        assertThat(d.verdict()).isEqualTo(Verdict.DENY);
        assertThat(d.failureReason()).isEqualTo(FailureReason.SCOPE_MISMATCH);
        assertThat(d.basis()).contains("EXC-S", "scope mismatch");
    }

    @Test
    void deny_rule_outranks_allow_rule_and_conflict_is_explained() {
        PolicySet set = policy(Verdict.DENY, Severity.CRITICAL,
                List.of(
                        new PolicyRule(RuleAction.ALLOW, "com.bad:lib", "*", Set.of(), ""),
                        new PolicyRule(RuleAction.DENY, "com.bad:lib", "*", Set.of(), "banned")),
                List.of(), Map.of());
        DependencyDecision d = evaluator.evaluate(set, dep("com.bad:lib", "1.0.0", DependencyScope.COMPILE));
        assertThat(d.verdict()).isEqualTo(Verdict.DENY);
        assertThat(d.failureReason()).isEqualTo(FailureReason.POLICY_CONFLICT);
        assertThat(d.basis()).contains("DENY-wins", "banned");
    }

    @Test
    void scope_mismatched_deny_rule_does_not_fire_then_allow_applies() {
        PolicySet set = policy(Verdict.DENY, Severity.CRITICAL,
                List.of(
                        new PolicyRule(RuleAction.DENY, "com.acme:legacy-log4j", "1.*",
                                Set.of(DependencyScope.COMPILE, DependencyScope.RUNTIME), "no prod"),
                        new PolicyRule(RuleAction.ALLOW, "com.acme:legacy-log4j", "1.*",
                                Set.of(DependencyScope.TEST), "test ok")),
                List.of(), Map.of());
        DependencyDecision testScope = evaluator.evaluate(set,
                dep("com.acme:legacy-log4j", "1.9.9", DependencyScope.TEST));
        assertThat(testScope.verdict()).isEqualTo(Verdict.PASS);
        DependencyDecision compileScope = evaluator.evaluate(set,
                dep("com.acme:legacy-log4j", "1.9.9", DependencyScope.COMPILE));
        assertThat(compileScope.verdict()).isEqualTo(Verdict.DENY);
        assertThat(compileScope.failureReason()).isEqualTo(FailureReason.DENIED_BY_RULE);
    }

    @Test
    void default_deny_with_no_match_reports_no_applicable_policy() {
        PolicySet set = policy(Verdict.DENY, Severity.CRITICAL, List.of(), List.of(), Map.of());
        DependencyDecision d = evaluator.evaluate(set, dep("org.unknown:thing", "9.9.9", DependencyScope.COMPILE));
        assertThat(d.verdict()).isEqualTo(Verdict.DENY);
        assertThat(d.failureReason()).isEqualTo(FailureReason.NO_APPLICABLE_POLICY);
    }

    @Test
    void repeated_evaluation_is_deterministic() {
        PolicyException exc = new PolicyException("EXC-2", "org.example:risky", "2.3.*",
                Set.of(), NOW.plusSeconds(3600), "dave@local", "j");
        PolicySet set = policy(Verdict.DENY, Severity.HIGH,
                List.of(new PolicyRule(RuleAction.ALLOW, "org.example:*", "*", Set.of(), "")),
                List.of(exc,
                        new PolicyException("EXC-1", "org.example:risky", "2.3.*",
                                Set.of(), NOW.plusSeconds(7200), "eve@local", "j2")),
                Map.of("org.example:risky", Severity.HIGH));
        NormalizedDependency d = dep("org.example:risky", "2.3.1", DependencyScope.COMPILE);
        DependencyDecision first = evaluator.evaluate(set, d);
        for (int i = 0; i < 10; i++) {
            DependencyDecision again = evaluator.evaluate(set, d);
            assertThat(again).usingRecursiveComparison().isEqualTo(first);
        }
        // 多个有效例外时选择 id 最小者，保证确定性
        assertThat(first.matchedExceptionId()).isEqualTo("EXC-1");
    }

    @Test
    void loader_rejects_duplicate_and_invalid_policy() {
        LocalPolicyLoader loader = new LocalPolicyLoader();
        String duplicateRule = """
                { "policyVersion":"v1",
                  "rules":[
                    {"action":"DENY","name":"a:b","versionPattern":"*"},
                    {"action":"DENY","name":"a:b","versionPattern":"*"}
                  ] }
                """;
        assertThatThrownBy(() -> loader.parse(duplicateRule))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("duplicate rule");

        String badEnum = """
                { "policyVersion":"v1",
                  "rules":[{"action":"WHATEVER","name":"a:b"}] }
                """;
        assertThatThrownBy(() -> loader.parse(badEnum))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void loader_requires_policy_version() {
        assertThatThrownBy(() -> new LocalPolicyLoader().parse("{\"defaultVerdict\":\"PASS\"}"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("policyVersion");
    }
}
