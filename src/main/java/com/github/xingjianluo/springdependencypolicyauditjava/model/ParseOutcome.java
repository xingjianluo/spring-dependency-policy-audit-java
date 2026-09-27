package com.github.xingjianluo.springdependencypolicyauditjava.model;

import java.util.List;

/**
 * 一次清单解析的完整结果：归一依赖 + 所有发现的问题（不静默丢弃任何异常条目）。
 */
public record ParseOutcome(
        String manifestType,
        String sourceName,
        List<NormalizedDependency> dependencies,
        List<ParseIssue> issues
) {
}
