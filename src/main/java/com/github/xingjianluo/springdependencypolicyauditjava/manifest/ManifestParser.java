package com.github.xingjianluo.springdependencypolicyauditjava.manifest;

import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseOutcome;

/**
 * 本地依赖清单解析器。输入为原始文本，输出归一结果；
 * 任何格式异常、版本不完整、重复、字段缺失都进入 issues，绝不静默跳过。
 */
public interface ManifestParser {

    boolean supports(String manifestType);

    ParseOutcome parse(String manifestType, String sourceName, String rawContent);
}
