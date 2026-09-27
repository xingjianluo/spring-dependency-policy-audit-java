package com.github.xingjianluo.springdependencypolicyauditjava.policy;

import com.github.xingjianluo.springdependencypolicyauditjava.model.Dependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Ecosystem;
import com.github.xingjianluo.springdependencypolicyauditjava.version.VersionConstraint;

import java.util.List;

/**
 * 一条名单规则（允许或拒绝）。
 *
 * @param id           规则稳定标识
 * @param action       ALLOW / DENY
 * @param ecosystem    生效生态，null 表示全部
 * @param groupPattern 精确匹配 group（空/null 表示不限制；无 group 概念的生态用空串）
 * @param namePattern  精确匹配依赖名（空/null 表示不限制）
 * @param versionRange 版本约束（空/null 表示全部版本）
 * @param scopes       生效作用域集合（空表示全部作用域）
 * @param reason       人读说明
 */
public record PolicyRule(
        String id,
        AllowDeny action,
        Ecosystem ecosystem,
        String groupPattern,
        String namePattern,
        String versionRange,
        List<String> scopes,
        String reason) {

    /** 规则是否命中给定依赖（含生效范围判断）。 */
    public boolean matches(Dependency dependency) {
        if (ecosystem != null && ecosystem != dependency.ecosystem()) {
            return false;
        }
        if (groupPattern != null && !groupPattern.isBlank()
                && !groupPattern.trim().equals(dependency.group())) {
            return false;
        }
        if (namePattern != null && !namePattern.isBlank()
                && !namePattern.trim().equals(dependency.name())) {
            return false;
        }
        if (versionRange != null && !versionRange.isBlank()
                && !VersionConstraint.satisfies(dependency.version(), versionRange.trim())) {
            return false;
        }
        if (scopes != null && !scopes.isEmpty()
                && scopes.stream().noneMatch(s -> s.equalsIgnoreCase(dependency.scope()))) {
            return false;
        }
        return true;
    }
}
