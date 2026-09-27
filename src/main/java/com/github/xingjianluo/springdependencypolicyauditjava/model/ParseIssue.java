package com.github.xingjianluo.springdependencypolicyauditjava.model;

/**
 * 清单解析阶段的单条问题，原因彼此可区分。
 */
public record ParseIssue(
        FailureReason reason,
        String entryKey,
        String message
) {
}
