package com.github.xingjianluo.springdependencypolicyauditjava.scan;

/**
 * 扫描请求：清单类型 + 原始内容 + 操作者与批次/幂等信息。
 */
public record ScanRequest(
        String manifestType,
        String contents,
        String operator,
        String batchId,
        String idempotencyKey) {
}
