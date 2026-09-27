package com.github.xingjianluo.springdependencypolicyauditjava.model;

/**
 * 依赖生效范围。
 */
public enum DependencyScope {
    COMPILE,
    RUNTIME,
    TEST,
    PROVIDED,
    UNKNOWN
}
