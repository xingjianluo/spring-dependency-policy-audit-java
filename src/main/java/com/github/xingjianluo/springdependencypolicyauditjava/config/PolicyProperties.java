package com.github.xingjianluo.springdependencypolicyauditjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 策略文件本地路径配置。为空时使用内置默认策略。
 */
@ConfigurationProperties(prefix = "depaudit.policy")
public class PolicyProperties {

    private String file;

    public String getFile() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }
}
