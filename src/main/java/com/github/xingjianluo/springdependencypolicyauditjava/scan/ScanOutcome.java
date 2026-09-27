package com.github.xingjianluo.springdependencypolicyauditjava.scan;

import com.github.xingjianluo.springdependencypolicyauditjava.decision.DependencyDecision;

import java.time.Instant;
import java.util.List;

/**
 * 一次批次扫描的总体结论。
 *
 * @param status BLOCKED / PASSED_WITH_WARNINGS / PASSED
 */
public record ScanOutcome(
        String status,
        String batchId,
        String idempotencyKey,
        boolean blocked,
        Instant decidedAt,
        String policyVersion,
        String contentFingerprint,
        int total,
        int passed,
        int warned,
        int denied,
        int outOfScope,
        List<DependencyDecision> decisions) {

    /** 由阻断/告警计数推导总体状态。 */
    public static String deriveStatus(boolean blocked, int denied, int warned) {
        if (blocked || denied > 0) {
            return "BLOCKED";
        }
        if (warned > 0) {
            return "PASSED_WITH_WARNINGS";
        }
        return "PASSED";
    }
}
