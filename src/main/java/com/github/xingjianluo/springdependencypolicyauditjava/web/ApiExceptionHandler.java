package com.github.xingjianluo.springdependencypolicyauditjava.web;

import com.github.xingjianluo.springdependencypolicyauditjava.manifest.ManifestParseException;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyLoadException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * 统一错误响应：错误码可区分，错误信息不包含敏感配置内容。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ManifestParseException.class)
    public ResponseEntity<Map<String, String>> handleParse(ManifestParseException ex) {
        HttpStatus status = switch (ex.getReason()) {
            case IO_ERROR -> HttpStatus.UNPROCESSABLE_ENTITY;
            case UNSUPPORTED_FORMAT -> HttpStatus.UNSUPPORTED_MEDIA_TYPE;
            default -> HttpStatus.BAD_REQUEST;
        };
        return ResponseEntity.status(status).body(Map.of(
                "errorCode", ex.getReason().name(),
                "message", ex.getMessage()));
    }

    @ExceptionHandler(PolicyLoadException.class)
    public ResponseEntity<Map<String, String>> handlePolicy(PolicyLoadException ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "errorCode", "POLICY_CONFIGURATION_ERROR",
                "message", ex.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "errorCode", "FORMAT_MALFORMED",
                "message", "request body is not valid JSON"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleBadRequest(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "errorCode", "BAD_REQUEST",
                "message", ex.getMessage()));
    }
}
