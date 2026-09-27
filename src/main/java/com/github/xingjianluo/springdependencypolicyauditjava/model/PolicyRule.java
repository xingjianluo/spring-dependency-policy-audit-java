package com.github.xingjianluo.springdependencypolicyauditjava.model;

import java.util.Set;

/**
 * 名单规则：name/versionPattern 匹配，scopes 为空表示全作用域。
 */
public record PolicyRule(
        RuleAction action,
        String name,
        String versionPattern,
        Set<DependencyScope> scopes,
        String reasonText
) {
}
