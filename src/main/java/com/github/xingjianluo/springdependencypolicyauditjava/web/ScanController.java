package com.github.xingjianluo.springdependencypolicyauditjava.web;

import com.github.xingjianluo.springdependencypolicyauditjava.model.ScanResult;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.ScanService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;

/**
 * 发布前阻断入口。
 *
 * <p>HTTP 语义：</p>
 * <ul>
 *   <li>200：扫描通过（PASS 或有条件放行）；</li>
 *   <li>403：存在解析问题或策略 DENY，发布必须阻断，响应体含每条可区分原因；</li>
 *   <li>400/422/500：请求或本地配置错误（见 {@link ApiExceptionHandler}）。</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/dependency-scans")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @PostMapping
    public ResponseEntity<ScanResult> scan(@RequestBody ScanRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request body is required");
        }
        if (request.manifestType() == null || request.manifestType().isBlank()) {
            throw new IllegalArgumentException("manifestType is required");
        }
        ScanResult result;
        boolean inlineContent = request.rawContent() != null;
        if (inlineContent) {
            result = scanService.scanRaw(request.manifestType(),
                    request.sourceName(), request.rawContent(), request.operator());
        } else {
            if (request.manifestPath() == null || request.manifestPath().isBlank()) {
                throw new IllegalArgumentException(
                        "either rawContent or manifestPath must be provided");
            }
            // 仅允许本地文件路径；任何 scheme 前缀（http://、jar: 等）一律拒绝
            String path = request.manifestPath();
            if (path.contains("://")) {
                throw new IllegalArgumentException("only local file paths are supported");
            }
            result = scanService.scan(Path.of(path),
                    request.manifestType(), request.operator());
        }
        return ResponseEntity
                .status(result.blocked() ? HttpStatus.FORBIDDEN : HttpStatus.OK)
                .body(result);
    }

    /**
     * 扫描请求。rawContent 与 manifestPath 二选一。
     */
    public record ScanRequest(String manifestType, String sourceName, String rawContent,
                              String manifestPath, String operator) {
    }
}
