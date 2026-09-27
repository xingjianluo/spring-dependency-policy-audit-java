package com.github.xingjianluo.springdependencypolicyauditjava.model;

/**
 * 归一后的依赖条目。
 */
public record NormalizedDependency(
        String name,
        String version,
        DependencyScope scope,
        String fingerprint,
        String rawCoordinate,
        String sourceFormat
) {
}
