package com.github.xingjianluo.springdependencypolicyauditjava.model;

/** 支持的本地清单格式。 */
public enum ManifestType {
    MANIFEST_JSON, LOCK_JSON;

    /** 解析外部字符串，非法值返回 null。 */
    public static ManifestType fromString(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase()) {
            case "manifest", "manifest_json", "manifest.json" -> MANIFEST_JSON;
            case "lock", "lock_json", "lock.json", "lockfile" -> LOCK_JSON;
            default -> null;
        };
    }
}
