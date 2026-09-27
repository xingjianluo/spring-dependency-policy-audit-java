package com.github.xingjianluo.springdependencypolicyauditjava.decision;

import com.github.xingjianluo.springdependencypolicyauditjava.model.Dependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.Advisory;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.AllowDeny;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.ExceptionGrant;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyRule;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicySet;
import com.github.xingjianluo.springdependencypolicyauditjava.util.Fingerprints;

import java.time.Clock;
import java.time.LocalDate;
import java.util.Comparator;
import java.util.List;

/**
 * 策略判定引擎。固定优先级（从高到低）：
 * <ol>
 *   <li><b>生效范围</b>：依赖 scope 不在 enforcedScopes 内 => OUT_OF_SCOPE（不参与风险判定）；</li>
 *   <li><b>拒绝名单</b>：命中 DENY 规则 => DENY（最高阻断优先级）；</li>
 *   <li><b>冲突处理</b>：同一依赖同时命中 DENY 与 ALLOW 规则 => DENY，原因码 RULE_CONFLICT，
 *       冲突规则 id 全部留痕，解释“安全优先”；</li>
 *   <li><b>有效例外</b>：存在未到期且坐标/版本/作用域匹配的例外 => WARN（有条件放行，须审计）；</li>
 *   <li><b>严重级别阈值</b>：命中情报且级别 ≥ maxSeverity => DENY；低于阈值 => WARN；</li>
 *   <li><b>允许名单</b>：仅命中 ALLOW 且无情报 => PASS（带显式依据）；</li>
 *   <li>其余 => PASS。</li>
 * </ol>
 *
 * <p>过期例外不豁免，原因码 EXCEPTION_EXPIRED 仍按底层规则/阈值判定并在依据中说明；
 * 作用域不匹配的例外同理（EXCEPTION_SCOPE_MISMATCH）。
 * 规则/情报/例外集合均按 id 排序后选择，保证同输入同策略结论一致。
 */
public class PolicyEngine {

    private final Clock clock;

    public PolicyEngine(Clock clock) {
        this.clock = clock;
    }

    /** 对单个依赖做判定。 */
    public DependencyDecision evaluate(Dependency dependency, PolicySet policy) {
        LocalDate today = LocalDate.now(clock);
        String coordinate = coordinateOf(dependency);
        String fingerprint = Fingerprints.sha256(
                dependency.ecosystem() + "|" + dependency.group() + "|" + dependency.name()
                        + "|" + dependency.version() + "|" + dependency.scope());
        String pv = policy.policyVersion();

        // 1. 生效范围
        boolean inScope = policy.enforcedScopes().isEmpty()
                || policy.enforcedScopes().stream().anyMatch(s -> s.equalsIgnoreCase(dependency.scope()));
        if (!inScope) {
            return new DependencyDecision(coordinate, fingerprint, Decision.OUT_OF_SCOPE,
                    Severity.NONE, "OUT_OF_SCOPE",
                    "作用域 " + dependency.scope() + " 不在策略生效范围 " + policy.enforcedScopes() + " 内，跳过风险判定",
                    List.of(), null, null, pv);
        }

        // 2. 命中规则（按 id 排序保证确定性）
        List<PolicyRule> matchedRules = policy.rules().stream()
                .filter(r -> r.matches(dependency))
                .sorted(Comparator.comparing(PolicyRule::id))
                .toList();
        List<String> matchedRuleIds = matchedRules.stream().map(PolicyRule::id).toList();
        boolean hasDeny = matchedRules.stream().anyMatch(r -> r.action() == AllowDeny.DENY);
        boolean hasAllow = matchedRules.stream().anyMatch(r -> r.action() == AllowDeny.ALLOW);

        // 3. 冲突：DENY 与 ALLOW 同时命中，安全优先 => DENY
        if (hasDeny && hasAllow) {
            PolicyRule deny = matchedRules.stream().filter(r -> r.action() == AllowDeny.DENY)
                    .sorted(Comparator.comparing(PolicyRule::id)).findFirst().orElseThrow();
            return new DependencyDecision(coordinate, fingerprint, Decision.DENY,
                    Severity.HIGH, "RULE_CONFLICT",
                    "同时命中拒绝与允许规则，按安全优先原则阻断；拒绝规则=" + deny.id()
                            + "，允许规则=" + matchedRules.stream()
                            .filter(r -> r.action() == AllowDeny.ALLOW).map(PolicyRule::id).toList()
                            + "；" + deny.reason(),
                    matchedRuleIds, null, null, pv);
        }
        if (hasDeny) {
            PolicyRule deny = matchedRules.stream()
                    .filter(r -> r.action() == AllowDeny.DENY)
                    .min(Comparator.comparing(PolicyRule::id)).orElseThrow();
            return new DependencyDecision(coordinate, fingerprint, Decision.DENY,
                    Severity.HIGH, "DENY_RULE",
                    "命中拒绝名单规则 " + deny.id() + ": " + deny.reason(),
                    List.of(deny.id()), null, null, pv);
        }

        // 4. 风险情报（取最高严重级别；同级别取 id 最小）
        List<Advisory> matchedAdvisories = policy.advisories().stream()
                .filter(a -> a.matches(dependency))
                .sorted(Comparator.comparing(Advisory::id))
                .toList();
        Advisory advisory = matchedAdvisories.stream()
                .max(Comparator.comparingInt((Advisory a) -> a.severity().level())
                        .thenComparing(Comparator.comparing(Advisory::id).reversed()))
                .orElse(null);
        Severity severity = advisory == null ? Severity.NONE : advisory.severity();

        // 5. 例外评估：选出坐标/版本/作用域匹配的例外，区分过期与作用域不匹配
        List<ExceptionGrant> coordinateMatched = policy.exceptions().stream()
                .filter(e -> sameCoordinate(e, dependency))
                .sorted(Comparator.comparing(ExceptionGrant::id))
                .toList();
        ExceptionGrant activeException = coordinateMatched.stream()
                .filter(e -> e.matches(dependency) && e.isActiveOn(today))
                // 到期日最晚者优先，其次 id 最小，保证选择确定
                .max(Comparator.comparing(ExceptionGrant::expiresOn,
                        Comparator.nullsFirst(Comparator.naturalOrder()))
                        .thenComparing(Comparator.comparing(ExceptionGrant::id).reversed()))
                .orElse(null);
        ExceptionGrant expiredException = coordinateMatched.stream()
                .filter(e -> e.matches(dependency) && !e.isActiveOn(today))
                .min(Comparator.comparing(ExceptionGrant::id))
                .orElse(null);

        if (advisory != null) {
            boolean overThreshold = severity.level() >= policy.maxSeverity().level();
            if (activeException != null) {
                // 有效例外：有条件放行（无论是否超阈值），必须审计
                return new DependencyDecision(coordinate, fingerprint, Decision.WARN,
                        severity, overThreshold ? "EXCEPTION_OVERRIDES_BLOCK" : "EXCEPTION_GRANTED",
                        "依据例外 " + activeException.id() + " 有条件放行（申请人="
                                + activeException.requestedBy() + "，到期=" + activeException.expiresOn()
                                + "，理由=" + activeException.justification() + "）；情报="
                                + advisory.id() + "（" + severity + "）：" + advisory.reason(),
                        matchedRuleIds, advisory.id(), activeException.id(), pv);
            }
            if (overThreshold) {
                String suffix = expiredException != null
                        ? "；注意例外 " + expiredException.id() + " 已于 " + expiredException.expiresOn()
                        + " 到期（EXCEPTION_EXPIRED），不再豁免"
                        : "";
                return new DependencyDecision(coordinate, fingerprint, Decision.DENY,
                        severity, expiredException != null ? "EXCEPTION_EXPIRED" : "SEVERITY_THRESHOLD",
                        "风险级别 " + severity + " 达到/超过阈值 " + policy.maxSeverity()
                                + "，情报=" + advisory.id() + ": " + advisory.reason() + suffix,
                        matchedRuleIds, advisory.id(),
                        expiredException == null ? null : expiredException.id(), pv);
            }
            String suffix = expiredException != null
                    ? "；例外 " + expiredException.id() + " 已过期（EXCEPTION_EXPIRED）"
                    : "";
            return new DependencyDecision(coordinate, fingerprint, Decision.WARN,
                    severity, "SEVERITY_BELOW_THRESHOLD",
                    "风险级别 " + severity + " 低于阻断阈值 " + policy.maxSeverity()
                            + "，有条件放行并记录审计；情报=" + advisory.id() + ": "
                            + advisory.reason() + suffix,
                    matchedRuleIds, advisory.id(),
                    expiredException == null ? null : expiredException.id(), pv);
        }

        // 6. 无情报：仅允许名单命中 => 显式 PASS；否则普通 PASS
        if (hasAllow) {
            PolicyRule allow = matchedRules.stream()
                    .min(Comparator.comparing(PolicyRule::id)).orElseThrow();
            return new DependencyDecision(coordinate, fingerprint, Decision.PASS,
                    Severity.NONE, "ALLOW_RULE",
                    "命中允许名单规则 " + allow.id() + ": " + allow.reason(),
                    List.of(allow.id()), null, null, pv);
        }
        if (expiredException != null) {
            return new DependencyDecision(coordinate, fingerprint, Decision.PASS,
                    Severity.NONE, "EXCEPTION_EXPIRED",
                    "未命中风险情报；历史例外 " + expiredException.id() + " 已于 "
                            + expiredException.expiresOn() + " 到期，不再作为放行依据",
                    List.of(), null, expiredException.id(), pv);
        }
        return new DependencyDecision(coordinate, fingerprint, Decision.PASS,
                Severity.NONE, "CLEAN",
                "未命中任何拒绝名单或风险情报，默认放行",
                List.of(), null, null, pv);
    }

    /** 仅比较生态/group/name/version（不含 scope），用于识别作用域不匹配的例外。 */
    private boolean sameCoordinate(ExceptionGrant e, Dependency d) {
        if (e.ecosystem() != d.ecosystem()) {
            return false;
        }
        if (e.group() != null && !e.group().isBlank() && !e.group().trim().equals(d.group())) {
            return false;
        }
        if (e.name() != null && !e.name().isBlank() && !e.name().trim().equals(d.name())) {
            return false;
        }
        return e.versionRange() == null || e.versionRange().isBlank()
                || com.github.xingjianluo.springdependencypolicyauditjava.version.VersionConstraint
                .satisfies(d.version(), e.versionRange().trim());
    }

    private static String coordinateOf(Dependency d) {
        return switch (d.ecosystem()) {
            case MAVEN -> d.group() + ":" + d.name() + ":" + d.version();
            case NPM, PIP -> d.name() + "@" + d.version();
        } + " (" + d.scope() + ")";
    }
}
