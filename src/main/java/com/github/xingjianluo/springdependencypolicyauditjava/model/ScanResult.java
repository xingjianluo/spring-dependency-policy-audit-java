package com.github.xingjianluo.springdependencypolicyauditjava.model;

import java.util.List;

/**
 * 一次扫描的整体结果。整体结论：有任何解析问题或任何 DENY 即 BLOCKED。
 */
public record ScanResult(
        String scanId,
        String requestFingerprint,
        boolean blocked,
        String policyVersion,
        List<DependencyDecision> decisions,
        List<ParseIssue> parseIssues,
        boolean duplicateSubmission
) {
}
