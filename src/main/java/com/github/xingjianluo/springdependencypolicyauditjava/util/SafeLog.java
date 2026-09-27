package com.github.xingjianluo.springdependencypolicyauditjava.util;

import java.util.regex.Pattern;

/**
 * 日志脱敏：移除凭据 / token / 密码 / URL 内嵌账密等敏感片段，
 * 保证敏感配置与凭据不会进入日志。
 */
public final class SafeLog {

    private static final String MASKED = "***REDACTED***";

    /** key=value / "key":"value" 形式的敏感字段（键名小写匹配）。 */
    private static final Pattern KV_SECRET = Pattern.compile(
            "(?i)([\"']?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
                    + "private[_-]?key|credential|authorization)[\"']?\\s*[:=]\\s*)"
                    + "(\"[^\"]*\"|'[^']*'|[^\\s,;}&]+)");

    /** URL 中内嵌的账号密码，如 https://user:pass@host。 */
    private static final Pattern URL_CREDENTIALS = Pattern.compile(
            "(?i)([a-z][a-z0-9+.-]*://)([^:/\\s@]+):([^@/\\s]+)@");

    /** Authorization 头风格：Bearer xxx / Basic xxx。 */
    private static final Pattern AUTH_HEADER = Pattern.compile(
            "(?i)\\b(Bearer|Basic|Digest)\\s+[A-Za-z0-9._~+/=-]+");

    private SafeLog() {
    }

    /** 脱敏后返回安全字符串；null 原样返回。 */
    public static String redact(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        // 必须先处理 Authorization 头，否则 KV 规则会把 "Authorization:" 当键吞掉而漏掉令牌
        String out = AUTH_HEADER.matcher(input).replaceAll("$1 " + MASKED);
        out = KV_SECRET.matcher(out).replaceAll("$1\"" + MASKED + "\"");
        out = URL_CREDENTIALS.matcher(out).replaceAll("$1" + MASKED + "@");
        return out;
    }
}
