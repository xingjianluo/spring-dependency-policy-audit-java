package com.github.xingjianluo.springdependencypolicyauditjava.scan;

import com.github.xingjianluo.springdependencypolicyauditjava.audit.AuditLogger;
import com.github.xingjianluo.springdependencypolicyauditjava.audit.AuditRecord;
import com.github.xingjianluo.springdependencypolicyauditjava.audit.AuditStore;
import com.github.xingjianluo.springdependencypolicyauditjava.decision.Decision;
import com.github.xingjianluo.springdependencypolicyauditjava.decision.DependencyDecision;
import com.github.xingjianluo.springdependencypolicyauditjava.decision.PolicyEngine;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Dependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ManifestType;
import com.github.xingjianluo.springdependencypolicyauditjava.model.NormalizedManifest;
import com.github.xingjianluo.springdependencypolicyauditjava.parser.ManifestParser;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyLoader;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicySet;
import com.github.xingjianluo.springdependencypolicyauditjava.util.Fingerprints;
import com.github.xingjianluo.springdependencypolicyauditjava.util.SafeLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 默认扫描服务。
 *
 * <p>职责：解析归一 → 逐依赖策略判定 → 汇总阻断/放行 → 为有条件放行与阻断写审计。
 *
 * <p>并发与重复提交：以 {@code idempotencyKey}（缺省由 内容指纹+批次+操作者 推导）
 * 在 {@link #inFlight} 与 {@link #finished} 两个并发 Map 上做去重。
 * 同一幂等键的并发请求阻塞等待首次计算结果，串行重复提交直接返回缓存结论：
 * 不重复放行、不重复写审计、结论不被覆盖。
 */
@Service
public class DefaultScanService implements ScanService {

    private static final Logger log = LoggerFactory.getLogger(DefaultScanService.class);

    private final ManifestParser manifestParser;
    private final PolicyLoader policyLoader;
    private final PolicyEngine policyEngine;
    private final AuditStore auditStore;
    private final AuditLogger auditLogger;
    private final Clock clock;

    /** 幂等键 -> 进行中扫描的占位锁（并发请求在同一把锁上等待）。 */
    private final ConcurrentHashMap<String, Object> inFlight = new ConcurrentHashMap<>();
    /** 幂等键 -> 已完成结论（重复提交直接返回）。 */
    private final ConcurrentHashMap<String, ScanOutcome> finished = new ConcurrentHashMap<>();

    public DefaultScanService(ManifestParser manifestParser,
                              PolicyLoader policyLoader,
                              PolicyEngine policyEngine,
                              AuditStore auditStore,
                              AuditLogger auditLogger,
                              Clock clock) {
        this.manifestParser = manifestParser;
        this.policyLoader = policyLoader;
        this.policyEngine = policyEngine;
        this.auditStore = auditStore;
        this.auditLogger = auditLogger;
        this.clock = clock;
    }

    @Override
    public ScanOutcome scan(ScanRequest request) {
        validate(request);
        ManifestType type = ManifestType.fromString(request.manifestType());
        if (type == null) {
            throw new IllegalArgumentException("不支持的清单类型: " + request.manifestType());
        }
        String operator = request.operator() == null || request.operator().isBlank()
                ? "anonymous" : request.operator().trim();
        String batchId = request.batchId() == null || request.batchId().isBlank()
                ? "batch-" + Fingerprints.sha256(request.contents()).substring(0, 12)
                : request.batchId().trim();
        String idempotencyKey = (request.idempotencyKey() == null || request.idempotencyKey().isBlank())
                ? Fingerprints.sha256(request.contents().trim() + "|" + batchId + "|" + operator)
                : request.idempotencyKey().trim();

        ScanOutcome cached = finished.get(idempotencyKey);
        if (cached != null) {
            log.info("scan deduplicated idempotencyKey={} batchId={} status={}",
                    idempotencyKey, SafeLog.redact(batchId), cached.status());
            return cached;
        }
        Object lock = inFlight.computeIfAbsent(idempotencyKey, k -> new Object());
        synchronized (lock) {
            try {
                ScanOutcome again = finished.get(idempotencyKey);
                if (again != null) {
                    return again;
                }
                ScanOutcome outcome = doScan(type, request.contents(), operator, batchId, idempotencyKey);
                finished.put(idempotencyKey, outcome);
                return outcome;
            } finally {
                inFlight.remove(idempotencyKey, lock);
            }
        }
    }

    private ScanOutcome doScan(ManifestType type, String contents, String operator,
                               String batchId, String idempotencyKey) {
        PolicySet policy = policyLoader.load();
        // 解析失败直接抛出 ManifestParseException（由 Web 层转 422），不会静默跳过
        NormalizedManifest manifest = manifestParser.parse(type, contents);

        Instant decidedAt = Instant.now(clock);
        List<DependencyDecision> decisions = new ArrayList<>();
        int passed = 0;
        int warned = 0;
        int denied = 0;
        int outOfScope = 0;
        for (Dependency dependency : manifest.dependencies()) {
            DependencyDecision decision = policyEngine.evaluate(dependency, policy);
            decisions.add(decision);
            switch (decision.decision()) {
                case PASS -> passed++;
                case WARN -> warned++;
                case DENY -> denied++;
                case OUT_OF_SCOPE -> outOfScope++;
            }
            // 有条件放行（WARN）与阻断（DENY）必须留痕；PASS/OUT_OF_SCOPE 只保留汇总轨迹
            if (decision.decision() == Decision.WARN || decision.decision() == Decision.DENY) {
                AuditRecord record = new AuditRecord(
                        auditIdOf(batchId, decision.fingerprint(), policy.policyVersion()),
                        decidedAt,
                        batchId,
                        operator,
                        policy.policyVersion(),
                        decision.fingerprint(),
                        decision.coordinate(),
                        decision.severity(),
                        decision.decision(),
                        decision.reasonCode(),
                        decision.reason());
                auditStore.append(record); // 存储按 auditId 幂等
                auditLogger.log(record);
            }
        }

        boolean blocked = denied > 0;
        ScanOutcome outcome = new ScanOutcome(
                ScanOutcome.deriveStatus(blocked, denied, warned),
                batchId, idempotencyKey, blocked, decidedAt, policy.policyVersion(),
                manifest.contentFingerprint(),
                decisions.size(), passed, warned, denied, outOfScope,
                List.copyOf(decisions));

        log.info("scan complete contentFingerprint={} batchId={} operator={} policyVersion={}"
                        + " total={} passed={} warned={} denied={} outOfScope={} finalDecision={}",
                manifest.contentFingerprint(), SafeLog.redact(batchId), SafeLog.redact(operator),
                SafeLog.redact(policy.policyVersion()),
                outcome.total(), passed, warned, denied, outOfScope, outcome.status());
        return outcome;
    }

    /** 审计 id 由批次+指纹+策略版本推导，保证同一批次同一依赖同一策略仅一条审计。 */
    private static String auditIdOf(String batchId, String dependencyFingerprint, String policyVersion) {
        return Fingerprints.sha256(batchId + "|" + dependencyFingerprint + "|" + policyVersion);
    }

    private void validate(ScanRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("请求体不能为空");
        }
        if (request.contents() == null || request.contents().isBlank()) {
            throw new IllegalArgumentException("contents 不能为空");
        }
        if (request.manifestType() == null || request.manifestType().isBlank()) {
            throw new IllegalArgumentException("manifestType 不能为空");
        }
    }
}
