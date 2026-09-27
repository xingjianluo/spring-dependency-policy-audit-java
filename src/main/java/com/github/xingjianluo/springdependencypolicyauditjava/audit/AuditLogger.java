package com.github.xingjianluo.springdependencypolicyauditjava.audit;

import com.github.xingjianluo.springdependencypolicyauditjava.util.SafeLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 审计日志输出。
 *
 * <p>只打印安全字段：审计 id、时间、批次、操作者、策略版本、依赖指纹、坐标、
 * 严重级别、最终判定、原因码与依据；所有字段经 {@link SafeLog} 脱敏，
 * 绝不记录原始清单内容或任何凭据/敏感配置。
 */
@Component
public class AuditLogger {

    private static final Logger log = LoggerFactory.getLogger(AuditLogger.class);

    public void log(AuditRecord record) {
        String line = "audit"
                + " auditId=" + record.auditId()
                + " decidedAt=" + record.decidedAt()
                + " batchId=" + SafeLog.redact(nullable(record.batchId()))
                + " operator=" + SafeLog.redact(nullable(record.operator()))
                + " policyVersion=" + SafeLog.redact(nullable(record.policyVersion()))
                + " dependencyFingerprint=" + nullable(record.dependencyFingerprint())
                + " coordinate=" + SafeLog.redact(nullable(record.coordinate()))
                + " severity=" + record.severity()
                + " decision=" + record.decision()
                + " reasonCode=" + SafeLog.redact(nullable(record.reasonCode()))
                + " basis=" + SafeLog.redact(nullable(record.basis()));
        switch (record.decision()) {
            case DENY -> log.warn(line);
            case WARN -> log.info(line);
            default -> log.debug(line);
        }
    }

    private static String nullable(String s) {
        return s == null ? "-" : s;
    }
}
