package com.github.xingjianluo.springdependencypolicyauditjava.scan;

import com.github.xingjianluo.springdependencypolicyauditjava.audit.AuditStore;
import com.github.xingjianluo.springdependencypolicyauditjava.audit.SafeLogger;
import com.github.xingjianluo.springdependencypolicyauditjava.manifest.LocalManifestReader;
import com.github.xingjianluo.springdependencypolicyauditjava.manifest.ManifestFormatRegistry;
import com.github.xingjianluo.springdependencypolicyauditjava.model.AuditRecord;
import com.github.xingjianluo.springdependencypolicyauditjava.model.DependencyDecision;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseIssue;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseOutcome;
import com.github.xingjianluo.springdependencypolicyauditjava.model.PolicySet;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ScanResult;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Verdict;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.LocalPolicyLoader;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyProvider;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyEvaluator;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 扫描编排：读取 → 解析归一 → 策略判定 → 阻断/审计。
 *
 * <p>幂等模型：请求指纹 = SHA256(类型 | 源名 | 清单原文)，
 * 审计幂等键 = 请求指纹:依赖指纹。同一批内容重复提交（无论串行还是并发）：</p>
 * <ul>
 *   <li>不重复放行/不重复审计（{@code AuditStore.putIfAbsent} 原子抢占）；</li>
 *   <li>结论不互相覆盖（存储为 append-only，读回首次记录）；</li>
 *   <li>响应标记 {@code duplicateSubmission=true}，但判定结论与首次完全一致。</li>
 * </ul>
 */
@Service
public class ScanService {

    private final ManifestFormatRegistry registry;
    private final LocalManifestReader manifestReader;
    private final LocalPolicyLoader policyLoader;
    private final PolicyEvaluator evaluator;
    private final AuditStore auditStore;
    private final SafeLogger safeLogger;
    private final Fingerprints fingerprints;
    private final Clock clock;
    private final PolicyProvider policyProvider;

    public ScanService(ManifestFormatRegistry registry,
                       LocalManifestReader manifestReader,
                       LocalPolicyLoader policyLoader,
                       PolicyEvaluator evaluator,
                       AuditStore auditStore,
                       SafeLogger safeLogger,
                       Fingerprints fingerprints,
                       Clock clock,
                       PolicyProvider policyProvider) {
        this.registry = registry;
        this.manifestReader = manifestReader;
        this.policyLoader = policyLoader;
        this.evaluator = evaluator;
        this.auditStore = auditStore;
        this.safeLogger = safeLogger;
        this.fingerprints = fingerprints;
        this.clock = clock;
        this.policyProvider = policyProvider;
    }

    /** 从本地路径扫描。 */
    public ScanResult scan(Path manifestPath, String manifestType, String operator) {
        String rawContent = manifestReader.read(manifestPath);
        return doScan(manifestType, manifestPath.toString(), rawContent, normalizeOperator(operator));
    }

    /** 直接提交清单文本扫描（测试与 HTTP 入口共用）。 */
    public ScanResult scanRaw(String manifestType, String sourceName,
                              String rawContent, String operator) {
        return doScan(manifestType,
                sourceName == null || sourceName.isBlank() ? "<inline>" : sourceName,
                rawContent == null ? "" : rawContent, normalizeOperator(operator));
    }

    private ScanResult doScan(String manifestType, String sourceName,
                              String rawContent, String operator) {
        PolicySet policy = policyProvider.current();

        String requestFingerprint = fingerprints.sha256(
                String.join("|", manifestType == null ? "" : manifestType,
                        sourceName, rawContent));
        boolean duplicate = !auditStore.findByRequestFingerprint(requestFingerprint).isEmpty();

        ParseOutcome outcome = registry.parse(manifestType, sourceName, rawContent);

        List<DependencyDecision> decisions = new ArrayList<>();
        for (var dependency : outcome.dependencies()) {
            DependencyDecision decision = evaluator.evaluate(policy, dependency);
            AuditRecord record = new AuditRecord(
                    requestFingerprint + ":" + dependency.fingerprint(),
                    requestFingerprint,
                    operator,
                    policy.policyVersion(),
                    dependency.fingerprint(),
                    decision.verdict(),
                    decision.basis(),
                    decision.failureReason() == null ? "" : decision.failureReason().name(),
                    clock.instant());
            // 原子抢占：并发/重复提交时只有首个结论落审计，其余读回既有记录
            AuditRecord stored = auditStore.putIfAbsent(record).orElse(record);
            decisions.add(decision);

            Map<String, Object> fields = new HashMap<>();
            fields.put("event", "dependency-decision");
            fields.put("requestFingerprint", requestFingerprint);
            fields.put("dependencyFingerprint", dependency.fingerprint());
            fields.put("name", dependency.name());
            fields.put("version", dependency.version());
            fields.put("scope", dependency.scope().name());
            fields.put("manifestType", outcome.manifestType());
            fields.put("policyVersion", stored.policyVersion());
            fields.put("matchedRule", decision.matchedRule() == null ? "" : decision.matchedRule());
            fields.put("matchedExceptionId",
                    decision.matchedExceptionId() == null ? "" : decision.matchedExceptionId());
            fields.put("advisorySeverity", decision.advisorySeverity().name());
            fields.put("verdict", stored.verdict().name());
            fields.put("failureReason",
                    decision.failureReason() == null ? "" : decision.failureReason().name());
            fields.put("operator", stored.operator());
            // basis 中只含规则/例外描述，绝无凭据；仍走 SafeLogger 白名单+脱敏
            fields.put("basis", stored.decisionBasis());
            safeLogger.decision(fields);
        }

        boolean blocked = !outcome.issues().isEmpty()
                || decisions.stream().anyMatch(d -> d.verdict() == Verdict.DENY);

        for (ParseIssue issue : outcome.issues()) {
            Map<String, Object> fields = new HashMap<>();
            fields.put("event", "manifest-issue");
            fields.put("requestFingerprint", requestFingerprint);
            fields.put("name", issue.entryKey());
            fields.put("failureReason", issue.reason().name());
            fields.put("basis", issue.message());
            safeLogger.decision(fields);
        }

        String scanId = requestFingerprint.substring(0, 16);
        Map<String, Object> summary = new HashMap<>();
        summary.put("event", "scan-summary");
        summary.put("scanId", scanId);
        summary.put("requestFingerprint", requestFingerprint);
        summary.put("policyVersion", policy.policyVersion());
        summary.put("blocked", Boolean.toString(blocked));
        summary.put("duplicateSubmission", Boolean.toString(duplicate));
        summary.put("issueCount", Integer.toString(outcome.issues().size()));
        summary.put("decisionCount", Integer.toString(decisions.size()));
        safeLogger.decision(summary);

        return new ScanResult(scanId, requestFingerprint, blocked,
                policy.policyVersion(), List.copyOf(decisions),
                List.copyOf(outcome.issues()), duplicate);
    }

    private static String normalizeOperator(String operator) {
        if (operator == null || operator.isBlank()) {
            return "anonymous";
        }
        return operator.trim();
    }
}
