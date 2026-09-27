package com.github.xingjianluo.springdependencypolicyauditjava.policy;

/** 名单动作：允许 / 拒绝。 */
public enum AllowDeny {
    ALLOW, DENY;

    /** 大小写不敏感解析，非法值返回 null。 */
    public static AllowDeny fromString(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase()) {
            case "allow", "allowlist", "permit", "whitelist" -> ALLOW;
            case "deny", "denylist", "block", "blacklist" -> DENY;
            default -> null;
        };
    }
}
