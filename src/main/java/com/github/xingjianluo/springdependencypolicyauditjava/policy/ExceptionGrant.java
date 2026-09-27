package com.github.xingjianluo.springdependencypolicyauditjava.policy;

import com.github.xingjianluo.springdependencypolicyauditjava.model.Dependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Ecosystem;
import com.github.xingjianluo.springdependencypolicyauditjava.version.VersionConstraint;

import java.time.LocalDate;
import java.util.List;

/**
 * 例外（豁免）：有到期时间与生效范围；到期后自动失效。
 *
 * @param expiresOn 到期日（含），即该日期当天仍有效，次日起失效
 */
public record ExceptionGrant(
        String id,
        Ecosystem ecosystem,
        String group,
        String name,
        String versionRange,
        List<String> scopes,
        LocalDate expiresOn,
        String requestedBy,
        String justification) {

    /** 坐标、版本与作用域是否匹配（与是否到期无关）。 */
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
        if (versionRange != null && !versionRange.isBlank()
                && !VersionConstraint.satisfies(dependency.version(), versionRange.trim())) {
            return false;
        }
        return scopes == null || scopes.isEmpty()
                || scopes.stream().anyMatch(s -> s.equalsIgnoreCase(dependency.scope()));
    }

    /** 在给定日期是否仍然有效。 */
    public boolean isActiveOn(LocalDate today) {
        return expiresOn == null || !today.isAfter(expiresOn);
    }
}
