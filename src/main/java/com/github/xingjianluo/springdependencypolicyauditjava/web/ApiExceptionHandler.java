package com.github.xingjianluo.springdependencypolicyauditjava.web;

import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseIssue;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyLoadException;
import com.github.xingjianluo.springdependencypolicyauditjava.parser.ManifestParseException;
import com.github.xingjianluo.springdependencypolicyauditjava.util.SafeLog;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 统一错误响应：
 * 清单解析失败 422（返回彼此可区分的问题列表）；请求参数非法 400；策略配置错误 500。
 * 任何回显文本均经过脱敏。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    /** 阻断专用异常：扫描完成但策略不通过。 */
    public static class PolicyBlockedException extends RuntimeException {
        private final transient Object outcome;

        public PolicyBlockedException(Object outcome, String message) {
            super(message);
            this.outcome = outcome;
        }

        public Object outcome() {
            return outcome;
        }
    }

    @ExceptionHandler(ManifestParseException.class)
    public ResponseEntity<Map<String, Object>> handleParse(ManifestParseException ex) {
        List<Map<String, Object>> issues = ex.issues().stream()
                .map(ApiExceptionHandler::toIssueMap)
                .toList();
        Map<String, Object> body = baseBody("MANIFEST_PARSE_FAILED",
                "清单解析失败，共 " + ex.issues().size() + " 个问题");
        body.put("issues", issues);
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(body);
    }

    @ExceptionHandler(PolicyBlockedException.class)
    public ResponseEntity<Object> handleBlocked(PolicyBlockedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.outcome());
    }

    @ExceptionHandler(PolicyLoadException.class)
    public ResponseEntity<Map<String, Object>> handlePolicy(PolicyLoadException ex) {
        Map<String, Object> body = baseBody("POLICY_LOAD_FAILED", SafeLog.redact(ex.getMessage()));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegal(IllegalArgumentException ex) {
        Map<String, Object> body = baseBody("INVALID_REQUEST", SafeLog.redact(ex.getMessage()));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    private static Map<String, Object> toIssueMap(ParseIssue issue) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("reason", issue.reason().name());
        m.put("reasonLabel", issue.reason().label());
        m.put("location", SafeLog.redact(issue.location()));
        m.put("detail", SafeLog.redact(issue.detail()));
        return m;
    }

    private static Map<String, Object> baseBody(String code, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("errorCode", code);
        body.put("message", message);
        return body;
    }
}
