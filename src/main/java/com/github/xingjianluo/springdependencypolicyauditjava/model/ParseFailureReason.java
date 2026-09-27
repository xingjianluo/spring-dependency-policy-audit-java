package com.github.xingjianluo.springdependencypolicyauditjava.model;

/**
 * 清单解析失败原因，彼此可区分。
 */
public enum ParseFailureReason {
    FORMAT_ERROR("格式异常，内容不是合法结构"),
    MISSING_FIELD("必填字段缺失"),
    VERSION_INCOMPLETE("版本信息缺失或不完整"),
    DUPLICATE_ENTRY("同一坐标出现重复条目"),
    UNSUPPORTED_ECOSYSTEM("生态系统类型不受支持");

    private final String label;

    ParseFailureReason(String label) {
        this.label = label;
    }

    public String code() {
        return name();
    }

    public String label() {
        return label;
    }
}
