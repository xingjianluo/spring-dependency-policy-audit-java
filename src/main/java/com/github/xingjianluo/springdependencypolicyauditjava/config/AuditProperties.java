package com.github.xingjianluo.springdependencypolicyauditjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 审计存储本地配置。
 */
@ConfigurationProperties(prefix = "depaudit.audit")
public class AuditProperties {

    private String file = "./depaudit-audit.log";

    public String getFile() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }
}
