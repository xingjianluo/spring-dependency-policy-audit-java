package com.github.xingjianluo.springdependencypolicyauditjava.audit;

import com.github.xingjianluo.springdependencypolicyauditjava.decision.Decision;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;

import java.time.Instant;

/**
 * 一条可追溯审计记录（不包含任何敏感配置或凭据）。
 */
public record AuditRecord(
        String auditId,
        Instant decidedAt,
        String batchId,
        String operator,
        String policyVersion,
        String dependencyFingerprint,
        String coordinate,
        Severity severity,
        Decision decision,
        String reasonCode,
        String basis) {
}
