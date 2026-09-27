package com.github.xingjianluo.springdependencypolicyauditjava.model;

/**
 * 归一后的依赖坐标。group 在无 group 概念的生态中为空串。
 */
public record Dependency(
        Ecosystem ecosystem,
        String group,
        String name,
        String version,
        String scope,
        String source) {
}
