package com.github.xingjianluo.springdependencypolicyauditjava.model;

/**
 * 单条解析问题：原因 + 定位 + 细节。
 */
public record ParseIssue(
        ParseFailureReason reason,
        String location,
        String detail) {
}
