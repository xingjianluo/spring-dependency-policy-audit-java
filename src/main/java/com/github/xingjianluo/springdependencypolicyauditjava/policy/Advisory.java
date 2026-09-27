package com.github.xingjianluo.springdependencypolicyauditjava.policy;

import com.github.xingjianluo.springdependencypolicyauditjava.model.Dependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Ecosystem;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;
import com.github.xingjianluo.springdependencypolicyauditjava.version.VersionConstraint;

/**
 * 本地内置风险情报条目（无外部服务），为坐标赋予严重级别。
 */
public record Advisory(
        String id,
        Ecosystem ecosystem,
        String group,
        String name,
        String versionRange,
        Severity severity,
        String reason) {

    /** 是否命中给定依赖。 */
    public boolean matches(Dependency dependency) {
        if (ecosystem != dependency.ecosystem()) {
            return false;
        }
        if (group != null && !group.isBlank() && !group.trim().equals(dependency.group())) {
            return false;
        }
        if (name != null && !name.isBlank() && !name.trim().equals(dependency.name())) {
            return false;
        }
        return versionRange == null || versionRange.isBlank()
                || VersionConstraint.satisfies(dependency.version(), versionRange.trim());
    }
}
