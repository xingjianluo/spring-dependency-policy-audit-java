package com.github.xingjianluo.springdependencypolicyauditjava.model;

/** 安全/风险严重级别，level 越大越严重。 */
public enum Severity {
    NONE(0),
    LOW(10),
    MODERATE(20),
    HIGH(30),
    CRITICAL(40);

    private final int level;

    Severity(int level) {
        this.level = level;
    }

    public int level() {
        return level;
    }

    /**
     * 解析外部字符串（大小写不敏感，兼容 info/minor/major/critical 等常见写法）。
     * 非法或 null 值返回 null。
     */
    public static Severity fromString(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase()) {
            case "none", "info", "informational" -> NONE;
            case "low", "minor" -> LOW;
            case "moderate", "medium", "major" -> MODERATE;
            case "high" -> HIGH;
            case "critical", "blocker" -> CRITICAL;
            default -> null;
        };
    }
}
