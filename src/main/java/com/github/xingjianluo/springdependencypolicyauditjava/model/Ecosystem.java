package com.github.xingjianluo.springdependencypolicyauditjava.model;

/** 依赖生态系统类型。 */
public enum Ecosystem {
    MAVEN, NPM, PIP;

    /**
     * 解析外部字符串（大小写不敏感，兼容 maven/npm/pypi 等常见写法）。
     * 非法或 null 值返回 null，由调用方归因为 UNSUPPORTED_ECOSYSTEM。
     */
    public static Ecosystem fromString(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase()) {
            case "maven", "mvn" -> MAVEN;
            case "npm", "node" -> NPM;
            case "pip", "pypi", "python" -> PIP;
            default -> null;
        };
    }
}
