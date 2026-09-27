package com.github.xingjianluo.springdependencypolicyauditjava.web;

/** 扫描请求体 JSON 映射（字段与 ScanRequest 对应）。 */
public record ScanApi(
        String manifestType,
        String contents,
        String operator,
        String batchId,
        String idempotencyKey) {
}
