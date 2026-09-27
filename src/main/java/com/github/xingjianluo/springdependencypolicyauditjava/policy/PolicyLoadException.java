package com.github.xingjianluo.springdependencypolicyauditjava.policy;

/** 策略配置非法时抛出（例如规则动作未知、版本格式错误）。 */
public class PolicyLoadException extends RuntimeException {
    public PolicyLoadException(String message) {
        super(message);
    }

    public PolicyLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}
