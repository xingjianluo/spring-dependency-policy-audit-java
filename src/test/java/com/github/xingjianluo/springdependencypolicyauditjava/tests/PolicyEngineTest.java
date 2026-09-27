package com.github.xingjianluo.springdependencypolicyauditjava.tests;

import com.github.xingjianluo.springdependencypolicyauditjava.decision.Decision;
import com.github.xingjianluo.springdependencypolicyauditjava.decision.DependencyDecision;
import com.github.xingjianluo.springdependencypolicyauditjava.decision.PolicyEngine;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Dependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Ecosystem;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.Advisory;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.AllowDeny;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.ExceptionGrant;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyRule;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicySet;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PolicyEngineTest {

    private static final LocalDate TODAY = LocalDate.of(2026, 9, 28);
    private final PolicyEngine engine = new PolicyEngine(
            Clock.fixed(Instant.parse("2026-09-28T00:00:00Z"), ZoneOffset.UTC));

    private Dependency maven(String group, String name, String version, String scope) {
        return new Dependency(Ecosystem.MAVEN, group, name, version, scope, "manifest");
    }

    private PolicySet policy(Severity threshold,
                             List<PolicyRule> rules,
                             List<Advisory> advisories,
                             List<ExceptionGrant> exceptions) {
        return new PolicySet("t-1", threshold, List.of("compile", "runtime"),
                rules, advisories, exceptions);
    }

    @Test
    void cleanDependencyPasses() {
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(), List.of());
        DependencyDecision d = engine.evaluate(maven("com.a", "n", "1.0.0", "compile"), ps);
        assertEquals(Decision.PASS, d.decision());
        assertEquals("CLEAN", d.reasonCode());
    }

    @Test
    void outOfScopeScopeIsExcluded() {
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(), List.of());
        DependencyDecision d = engine.evaluate(maven("com.a", "n", "1.0.0", "test"), ps);
        assertEquals(Decision.OUT_OF_SCOPE, d.decision());
        assertTrue(d.reason().contains("test"));
    }

    @Test
    void denyRuleBlocks() {
        PolicyRule deny = new PolicyRule("D1", AllowDeny.DENY, Ecosystem.MAVEN,
                "com.bad", "x", "*", List.of("compile"), "禁止使用");
        PolicySet ps = policy(Severity.HIGH, List.of(deny), List.of(), List.of());
        DependencyDecision d = engine.evaluate(maven("com.bad", "x", "1.0.0", "compile"), ps);
        assertEquals(Decision.DENY, d.decision());
        assertEquals("DENY_RULE", d.reasonCode());
        assertTrue(d.matchedRuleIds().contains("D1"));
    }

    @Test
    void denyWinsOverAllowWhenConflict() {
        PolicyRule deny = new PolicyRule("D1", AllowDeny.DENY, Ecosystem.MAVEN,
                "com.x", "lib", "*", List.of(), "拒绝");
        PolicyRule allow = new PolicyRule("A1", AllowDeny.ALLOW, Ecosystem.MAVEN,
                "com.x", "lib", "*", List.of(), "允许");
        PolicySet ps = policy(Severity.HIGH, List.of(deny, allow), List.of(), List.of());
        DependencyDecision d = engine.evaluate(maven("com.x", "lib", "1.0.0", "compile"), ps);
        assertEquals(Decision.DENY, d.decision());
        assertEquals("RULE_CONFLICT", d.reasonCode(), "冲突必须给出确定性原因码");
        assertTrue(d.matchedRuleIds().containsAll(List.of("D1", "A1")));
        assertTrue(d.reason().contains("安全优先"));
    }

    @Test
    void allowRuleOnlyProducesExplicitPass() {
        PolicyRule allow = new PolicyRule("A1", AllowDeny.ALLOW, Ecosystem.MAVEN,
                "com.ok", "lib", "*", List.of(), "内部允许");
        PolicySet ps = policy(Severity.HIGH, List.of(allow), List.of(), List.of());
        DependencyDecision d = engine.evaluate(maven("com.ok", "lib", "1.0.0", "compile"), ps);
        assertEquals(Decision.PASS, d.decision());
        assertEquals("ALLOW_RULE", d.reasonCode());
    }

    @Test
    void severityAtThresholdBlocks() {
        Advisory adv = new Advisory("ADV-1", Ecosystem.MAVEN, "com.v", "core",
                "[1.0.0,2.0.0)", Severity.CRITICAL, "RCE");
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(adv), List.of());
        DependencyDecision d = engine.evaluate(maven("com.v", "core", "1.5.0", "compile"), ps);
        assertEquals(Decision.DENY, d.decision());
        assertEquals("SEVERITY_THRESHOLD", d.reasonCode());
        // 修复到范围外版本应放行
        DependencyDecision fixed = engine.evaluate(maven("com.v", "core", "2.0.0", "compile"), ps);
        assertEquals(Decision.PASS, fixed.decision());
    }

    @Test
    void severityBelowThresholdWarnsAndAuditable() {
        Advisory adv = new Advisory("ADV-1", Ecosystem.MAVEN, "com.v", "core",
                "*", Severity.MODERATE, "中等风险");
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(adv), List.of());
        DependencyDecision d = engine.evaluate(maven("com.v", "core", "1.0.0", "compile"), ps);
        assertEquals(Decision.WARN, d.decision());
        assertEquals("SEVERITY_BELOW_THRESHOLD", d.reasonCode());
        assertEquals("ADV-1", d.matchedAdvisoryId());
    }

    @Test
    void activeExceptionOverridesBlockAsWarn() {
        Advisory adv = new Advisory("ADV-1", Ecosystem.MAVEN, "com.v", "core",
                "*", Severity.CRITICAL, "RCE");
        ExceptionGrant grant = new ExceptionGrant("EX-1", Ecosystem.MAVEN, "com.v", "core",
                "*", List.of("compile"), TODAY.plusDays(1), "bob", "迁移窗口内豁免");
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(adv), List.of(grant));
        DependencyDecision d = engine.evaluate(maven("com.v", "core", "1.0.0", "compile"), ps);
        assertEquals(Decision.WARN, d.decision());
        assertEquals("EXCEPTION_OVERRIDES_BLOCK", d.reasonCode());
        assertEquals("EX-1", d.matchedExceptionId());
        assertTrue(d.reason().contains("bob"));
    }

    @Test
    void expiredExceptionDoesNotOverrideBlock() {
        Advisory adv = new Advisory("ADV-1", Ecosystem.MAVEN, "com.v", "core",
                "*", Severity.CRITICAL, "RCE");
        ExceptionGrant grant = new ExceptionGrant("EX-OLD", Ecosystem.MAVEN, "com.v", "core",
                "*", List.of("compile"), LocalDate.of(2025, 1, 1), "bob", "已过期");
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(adv), List.of(grant));
        DependencyDecision d = engine.evaluate(maven("com.v", "core", "1.0.0", "compile"), ps);
        assertEquals(Decision.DENY, d.decision());
        assertEquals("EXCEPTION_EXPIRED", d.reasonCode());
        assertEquals("EX-OLD", d.matchedExceptionId(), "过期例外 id 仍应留痕");
        assertTrue(d.reason().contains("到期"));
    }

    @Test
    void exceptionExpiringTodayIsStillActive() {
        Advisory adv = new Advisory("ADV-1", Ecosystem.MAVEN, "com.v", "core",
                "*", Severity.CRITICAL, "RCE");
        ExceptionGrant grant = new ExceptionGrant("EX-TODAY", Ecosystem.MAVEN, "com.v", "core",
                "*", List.of("compile"), TODAY, "bob", "到期日当天有效");
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(adv), List.of(grant));
        DependencyDecision d = engine.evaluate(maven("com.v", "core", "1.0.0", "compile"), ps);
        assertEquals(Decision.WARN, d.decision());
    }

    @Test
    void scopeMismatchedExceptionDoesNotApply() {
        Advisory adv = new Advisory("ADV-1", Ecosystem.MAVEN, "com.v", "core",
                "*", Severity.CRITICAL, "RCE");
        // 例外只对 runtime 生效，依赖是 compile => 例外不可用 => 阻断
        ExceptionGrant grant = new ExceptionGrant("EX-RT", Ecosystem.MAVEN, "com.v", "core",
                "*", List.of("runtime"), TODAY.plusDays(10), "bob", "仅运行时");
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(adv), List.of(grant));
        DependencyDecision d = engine.evaluate(maven("com.v", "core", "1.0.0", "compile"), ps);
        assertEquals(Decision.DENY, d.decision());
        assertEquals("SEVERITY_THRESHOLD", d.reasonCode());
    }

    @Test
    void denyRuleStillBlocksEvenWithActiveException() {
        // 拒绝名单优先级高于例外：DENY 规则是硬性禁令，例外只豁免风险阈值
        PolicyRule deny = new PolicyRule("D1", AllowDeny.DENY, Ecosystem.MAVEN,
                "com.v", "core", "*", List.of(), "许可证禁止");
        ExceptionGrant grant = new ExceptionGrant("EX-1", Ecosystem.MAVEN, "com.v", "core",
                "*", List.of(), TODAY.plusDays(10), "bob", "申请豁免");
        PolicySet ps = policy(Severity.HIGH, List.of(deny), List.of(), List.of(grant));
        DependencyDecision d = engine.evaluate(maven("com.v", "core", "1.0.0", "compile"), ps);
        assertEquals(Decision.DENY, d.decision());
        assertEquals("DENY_RULE", d.reasonCode());
    }

    @Test
    void sameInputProducesSameDecisionRepeatedly() {
        Advisory adv = new Advisory("ADV-1", Ecosystem.MAVEN, "com.v", "core",
                "*", Severity.HIGH, "高危");
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(adv), List.of());
        Dependency dep = maven("com.v", "core", "1.0.0", "compile");
        DependencyDecision first = engine.evaluate(dep, ps);
        for (int i = 0; i < 10; i++) {
            DependencyDecision again = engine.evaluate(dep, ps);
            assertEquals(first.decision(), again.decision());
            assertEquals(first.reasonCode(), again.reasonCode());
            assertEquals(first.fingerprint(), again.fingerprint());
            assertEquals(first.reason(), again.reason());
        }
    }

    @Test
    void fingerprintIsStableSha256() {
        Dependency dep = maven("com.a", "n", "1.0.0", "compile");
        PolicySet ps = policy(Severity.HIGH, List.of(), List.of(), List.of());
        DependencyDecision d1 = engine.evaluate(dep, ps);
        DependencyDecision d2 = engine.evaluate(dep, ps);
        assertEquals(64, d1.fingerprint().length());
        assertEquals(d1.fingerprint(), d2.fingerprint());
    }
}
