package com.github.xingjianluo.springdependencypolicyauditjava.scan;

/** 发布前扫描与策略阻断编排入口。 */
public interface ScanService {
    ScanOutcome scan(ScanRequest request);
}
