package com.github.xingjianluo.springdependencypolicyauditjava.manifest;

import com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason;

/**
 * 解析级致命异常（如整个文件无法解析、IO 失败）。
 */
public class ManifestParseException extends RuntimeException {

    private final FailureReason reason;

    public ManifestParseException(FailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public ManifestParseException(FailureReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public FailureReason getReason() {
        return reason;
    }
}
