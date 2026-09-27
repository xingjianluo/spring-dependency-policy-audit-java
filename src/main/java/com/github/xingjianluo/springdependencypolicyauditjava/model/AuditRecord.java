package com.github.xingjianluo.springdependencypolicyauditjava.model;

import java.time.Instant;

/**
 * 审计记录：操作者、策略版本、决策依据、依赖指纹，绝不包含敏感配置/凭据。
 */
public record AuditRecord(
        String idempotencyKey,
        String requestFingerprint,
        String operator,
        String policyVersion,
        String dependencyFingerprint,
        Verdict verdict,
        String decisionBasis,
        String failureReason,
        Instant createdAt
) {
}
