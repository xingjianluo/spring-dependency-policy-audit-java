package com.github.xingjianluo.springdependencypolicyauditjava.model;

import java.time.Instant;
import java.util.Set;

/**
 * 例外放行，带到期时间与生效作用域。
 */
public record PolicyException(
        String id,
        String name,
        String versionPattern,
        Set<DependencyScope> scopes,
        Instant expiresAt,
        String approver,
        String justification
) {
}
