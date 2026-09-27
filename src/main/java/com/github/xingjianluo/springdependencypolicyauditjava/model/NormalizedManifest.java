package com.github.xingjianluo.springdependencypolicyauditjava.model;

import java.util.List;

/**
 * 解析归一结果：原始内容指纹 + 有序依赖列表（按坐标键排序，保证判定确定性）。
 */
public record NormalizedManifest(
        String contentFingerprint,
        List<Dependency> dependencies) {
}
