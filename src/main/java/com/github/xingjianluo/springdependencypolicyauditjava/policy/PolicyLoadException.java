package com.github.xingjianluo.springdependencypolicyauditjava.policy;

/**
 * 策略配置无法加载（文件缺失 / JSON 畸形 / 字段非法）。
 */
public class PolicyLoadException extends RuntimeException {
    public PolicyLoadException(String message) {
        super(message);
    }

    public PolicyLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}
