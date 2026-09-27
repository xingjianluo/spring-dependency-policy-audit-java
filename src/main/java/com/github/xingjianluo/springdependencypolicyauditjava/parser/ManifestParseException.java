package com.github.xingjianluo.springdependencypolicyauditjava.parser;

import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseIssue;

import java.util.List;

/**
 * 清单解析失败异常，携带全部可区分的问题列表，不静默跳过任何一条。
 */
public class ManifestParseException extends RuntimeException {

    private final List<ParseIssue> issues;

    public ManifestParseException(List<ParseIssue> issues) {
        super("manifest parse failed");
        this.issues = List.copyOf(issues);
    }

    public List<ParseIssue> issues() {
        return issues;
    }
}
