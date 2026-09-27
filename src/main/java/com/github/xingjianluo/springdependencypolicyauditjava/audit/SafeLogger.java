package com.github.xingjianluo.springdependencypolicyauditjava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 脱敏日志器。
 *
 * <p>采用两层防护，确保敏感配置/凭据绝不进入日志：</p>
 * <ol>
 *   <li>字段白名单：只有明确允许的键会被输出，未知键一律丢弃；</li>
 *   <li>键名敏感词扫描：即使调用方误传，键名（小写）含
 *       password/passwd/secret/token/credential/apikey/key/auth 等词的字段
 *       一律以 {@code [REDACTED]} 替换。</li>
 * </ol>
 * 输出单行 key=value 结构化文本，便于本地检索与断言。
 */
@Component
public class SafeLogger {

    private static final Logger log = LoggerFactory.getLogger("dependency-audit");

    /** 允许进入日志的字段名（精确匹配）。 */
    private static final Set<String> ALLOWED_KEYS = Set.of(
            "event",
            "scanId",
            "requestFingerprint",
            "dependencyFingerprint",
            "name",
            "version",
            "scope",
            "manifestType",
            "policyVersion",
            "matchedRule",
            "matchedExceptionId",
            "advisorySeverity",
            "verdict",
            "failureReason",
            "operator",
            "basis",
            "blocked",
            "duplicateSubmission",
            "issueCount",
            "decisionCount"
    );

    private static final String[] SENSITIVE_FRAGMENTS = {
            "password", "passwd", "secret", "token", "credential",
            "apikey", "api-key", "private", "authorization"
    };

    private static final String REDACTED = "[REDACTED]";

    /**
     * 记录一条判定/扫描事件日志。
     */
    public void decision(Map<String, Object> fields) {
        if (!log.isInfoEnabled()) {
            return;
        }
        Map<String, Object> safe = new TreeMap<>();
        if (fields != null) {
            for (Map.Entry<String, Object> entry : fields.entrySet()) {
                String key = entry.getKey();
                if (key == null || !ALLOWED_KEYS.contains(key)) {
                    continue;
                }
                safe.put(key, sanitize(key, entry.getValue()));
            }
        }
        log.info("{}", render(safe));
    }

    private Object sanitize(String key, Object value) {
        String lowered = key.toLowerCase();
        for (String fragment : SENSITIVE_FRAGMENTS) {
            if (lowered.contains(fragment)) {
                return REDACTED;
            }
        }
        if (value == null) {
            return "";
        }
        String text = value.toString();
        // 值层面也做一次保守扫描：形如 key=value 的凭据样式直接打码
        String loweredValue = text.toLowerCase();
        for (String fragment : SENSITIVE_FRAGMENTS) {
            if (loweredValue.contains(fragment + "=") || loweredValue.contains(fragment + ":")) {
                return REDACTED;
            }
        }
        return text;
    }

    private String render(Map<String, Object> safe) {
        StringBuilder sb = new StringBuilder(128);
        for (Map.Entry<String, Object> entry : safe.entrySet()) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            sb.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return sb.toString();
    }
}
