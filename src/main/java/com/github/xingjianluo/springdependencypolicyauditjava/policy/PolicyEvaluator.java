package com.github.xingjianluo.springdependencypolicyauditjava.policy;

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
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 策略判定引擎。
 *
 * <p>纯确定性：只依赖 policy、dependency 与注入的时钟；同一输入在策略不变、
 * 时刻不变时结论严格一致（规则按声明顺序选取，例外按 id 排序选取）。</p>
 *
 * <h3>判定优先级（高 → 低，冲突的确定处理）</h3>
 * <ol>
 *   <li><b>DENY 名单（最高，安全优先）</b>：命中拒绝规则即 DENY。
 *       若同时命中 ALLOW 与 DENY，以 DENY 胜出，failureReason=POLICY_CONFLICT，
 *       basis 中记录双方规则，结论可解释。</li>
 *   <li><b>生效中的例外</b>：未过期且作用域匹配的例外，可放行包括超阈值在内的问题，
 *       结论为 CONDITIONAL_PASS（有条件放行，须审计操作者与依据）。
 *       多条例外命中时取 id 字典序最小者，保证确定性。</li>
 *   <li><b>严重级别阈值</b>：本地咨询级别 ≥ 阈值且无有效例外 → DENY。</li>
 *   <li><b>ALLOW 名单</b>：命中允许规则 → PASS。</li>
 *   <li><b>默认判定</b>：policy.defaultVerdict；为 DENY 时原因 NO_APPLICABLE_POLICY。</li>
 * </ol>
 *
 * <p>过期例外与作用域不匹配不静默：作为 basis 备注记录；当某依赖仅因
 * 作用域不匹配而无法适用唯一有效例外并导致 DENY 时，failureReason=SCOPE_MISMATCH。</p>
 */
@Component
public class PolicyEvaluator {

    private final Clock clock;

    public PolicyEvaluator(Clock clock) {
        this.clock = clock;
    }

    public DependencyDecision evaluate(PolicySet policy, NormalizedDependency dependency) {
        Instant now = clock.instant();
        List<String> notes = new ArrayList<>();

        List<PolicyRule> matchedAllow = new ArrayList<>();
        List<PolicyRule> matchedDeny = new ArrayList<>();
        for (PolicyRule rule : policy.rules()) {
            if (matches(rule.name(), rule.versionPattern(),
                    rule.scopes(), dependency, notes, "rule")) {
                if (rule.action() == RuleAction.DENY) {
                    matchedDeny.add(rule);
                } else {
                    matchedAllow.add(rule);
                }
            }
        }

        List<PolicyException> expired = new ArrayList<>();
        List<PolicyException> scopeMismatched = new ArrayList<>();
        List<PolicyException> active = new ArrayList<>();
        for (PolicyException exception : policy.exceptions()) {
            if (!nameAndVersionMatches(exception.name(), exception.versionPattern(), dependency)) {
                continue;
            }
            if (!exception.expiresAt().isAfter(now)) {
                expired.add(exception);
                notes.add("exception " + exception.id() + " EXPIRED at " + exception.expiresAt());
                continue;
            }
            if (!scopeMatches(exception.scopes(), dependency.scope())) {
                scopeMismatched.add(exception);
                notes.add("exception " + exception.id() + " scope mismatch: requires "
                        + exception.scopes() + ", dependency is " + dependency.scope());
                continue;
            }
            active.add(exception);
        }
        for (PolicyException ex : expired) {
            notes.add("note: expired exception not applied: " + ex.id());
        }
        for (PolicyException ex : scopeMismatched) {
            notes.add("note: out-of-scope exception not applied: " + ex.id());
        }

        Severity advisory = policy.advisorySeverityByName().getOrDefault(dependency.name(), Severity.NONE);
        boolean thresholdExceeded = advisory.ordinal() >= policy.severityThreshold().ordinal()
                && advisory != Severity.NONE;

        String matchedRuleDesc = null;
        String matchedExceptionId = null;
        Verdict verdict;
        FailureReason reason = null;
        String basis;

        // 1) DENY 名单优先；同时命中 ALLOW 构成策略冲突，DENY 胜出但显式记录冲突
        if (!matchedDeny.isEmpty()) {
            PolicyRule deny = matchedDeny.get(0);
            matchedRuleDesc = describe(deny);
            if (!matchedAllow.isEmpty()) {
                reason = FailureReason.POLICY_CONFLICT;
                basis = "conflicting ALLOW and DENY rules; resolved by DENY-wins precedence: denied by ["
                        + describe(deny) + "]"
                        + (deny.reasonText().isBlank() ? "" : ": " + deny.reasonText())
                        + ", conflicting allow: ["
                        + describe(matchedAllow.get(0)) + "]";
            } else {
                reason = FailureReason.DENIED_BY_RULE;
                basis = "denied by explicit DENY rule [" + describe(deny) + "]"
                        + (deny.reasonText().isBlank() ? "" : ": " + deny.reasonText());
            }
            verdict = Verdict.DENY;
        } else {
            // 2) 生效中的例外（条件放行）
            PolicyException chosen = active.stream()
                    .min(Comparator.comparing(PolicyException::id))
                    .orElse(null);
            if (chosen != null) {
                matchedExceptionId = chosen.id();
                verdict = Verdict.CONDITIONAL_PASS;
                String reasonText;
                if (thresholdExceeded) {
                    reasonText = "active exception " + chosen.id()
                            + " overrides severity " + advisory
                            + " (threshold " + policy.severityThreshold() + ")";
                } else if (policy.defaultVerdict() == Verdict.DENY && matchedAllow.isEmpty()) {
                    reasonText = "active exception " + chosen.id()
                            + " overrides default DENY (no ALLOW rule matched)";
                } else {
                    reasonText = "active exception " + chosen.id() + " applied";
                }
                basis = reasonText
                        + "; approver=" + chosen.approver()
                        + "; expiresAt=" + chosen.expiresAt()
                        + "; justification=" + chosen.justification();
            } else if (thresholdExceeded) {
                // 3) 阈值超标
                verdict = Verdict.DENY;
                if (!scopeMismatched.isEmpty() && matchedAllow.isEmpty()) {
                    reason = FailureReason.SCOPE_MISMATCH;
                    basis = "advisory severity " + advisory + " meets/exceeds threshold "
                            + policy.severityThreshold()
                            + "; only matching exception(s) out of scope: "
                            + scopeMismatched.stream().map(PolicyException::id).sorted().toList();
                } else if (!expired.isEmpty()) {
                    reason = FailureReason.EXCEPTION_EXPIRED;
                    basis = "advisory severity " + advisory + " meets/exceeds threshold "
                            + policy.severityThreshold()
                            + "; matching exception(s) expired: "
                            + expired.stream().map(PolicyException::id).sorted().toList();
                } else {
                    reason = FailureReason.SEVERITY_THRESHOLD_EXCEEDED;
                    basis = "advisory severity " + advisory + " meets/exceeds threshold "
                            + policy.severityThreshold();
                }
            } else if (!matchedAllow.isEmpty()) {
                // 4) ALLOW 名单
                PolicyRule allow = matchedAllow.get(0);
                matchedRuleDesc = describe(allow);
                verdict = Verdict.PASS;
                basis = "allowed by explicit ALLOW rule [" + describe(allow) + "]";
            } else {
                // 5) 默认判定
                verdict = policy.defaultVerdict();
                matchedRuleDesc = "default:" + verdict;
                if (verdict == Verdict.DENY) {
                    if (!scopeMismatched.isEmpty()) {
                        reason = FailureReason.SCOPE_MISMATCH;
                        basis = "default DENY; matching exception(s) out of scope: "
                                + scopeMismatched.stream().map(PolicyException::id).sorted().toList();
                    } else if (!expired.isEmpty()) {
                        reason = FailureReason.EXCEPTION_EXPIRED;
                        basis = "default DENY; matching exception(s) expired: "
                                + expired.stream().map(PolicyException::id).sorted().toList();
                    } else {
                        reason = FailureReason.NO_APPLICABLE_POLICY;
                        basis = "default verdict DENY: no rule or active exception matched";
                    }
                } else {
                    basis = "default verdict PASS: no rule matched";
                }
            }
        }

        if (!notes.isEmpty()) {
            basis = basis + " | notes: " + String.join("; ", notes);
        }

        return new DependencyDecision(
                dependency.fingerprint(),
                dependency.name(),
                dependency.version(),
                dependency.scope(),
                verdict,
                reason,
                advisory,
                matchedRuleDesc,
                matchedExceptionId,
                policy.policyVersion(),
                basis,
                now);
    }

    private static boolean matches(String ruleName, String versionPattern,
                                   java.util.Set<DependencyScope> ruleScopes,
                                   NormalizedDependency dependency,
                                   List<String> notes, String kind) {
        if (!nameAndVersionMatches(ruleName, versionPattern, dependency)) {
            return false;
        }
        if (!scopeMatches(ruleScopes, dependency.scope())) {
            notes.add(kind + " '" + ruleName + "' scope mismatch (requires "
                    + ruleScopes + ", dependency is " + dependency.scope() + ")");
            return false;
        }
        return true;
    }

    private static boolean nameAndVersionMatches(String ruleName, String versionPattern,
                                                 NormalizedDependency dependency) {
        if (!matchesName(ruleName, dependency.name())) {
            return false;
        }
        return matchesVersion(versionPattern, dependency.version());
    }

    static boolean matchesName(String pattern, String name) {
        if (pattern == null || pattern.isBlank() || "*".equals(pattern)) {
            return true;
        }
        // 尾随 * 表示前缀通配（如 org.example:*、org.example:safe-*），其余精确匹配
        if (pattern.endsWith("*")) {
            String prefix = pattern.substring(0, pattern.length() - 1);
            return name.startsWith(prefix);
        }
        return pattern.trim().equals(name);
    }

    static boolean matchesVersion(String pattern, String version) {
        if (pattern == null || pattern.isBlank() || "*".equals(pattern)) {
            return true;
        }
        // 尾随 * 表示前缀通配（如 1.2.*），其余精确匹配
        if (pattern.endsWith("*")) {
            String prefix = pattern.substring(0, pattern.length() - 1);
            return version.startsWith(prefix);
        }
        return pattern.trim().equals(version);
    }

    private static boolean scopeMatches(java.util.Set<DependencyScope> ruleScopes,
                                        DependencyScope dependencyScope) {
        if (ruleScopes == null || ruleScopes.isEmpty()) {
            return true; // 空表示全作用域
        }
        return ruleScopes.contains(dependencyScope);
    }

    private static String describe(PolicyRule rule) {
        return rule.action() + ":" + rule.name() + ":" + rule.versionPattern()
                + (rule.scopes().isEmpty() ? "" : ":" + rule.scopes());
    }
}
