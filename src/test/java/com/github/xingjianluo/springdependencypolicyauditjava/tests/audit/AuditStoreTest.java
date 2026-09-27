package com.github.xingjianluo.springdependencypolicyauditjava.tests.audit;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.xingjianluo.springdependencypolicyauditjava.audit.LocalFileAuditStore;
import com.github.xingjianluo.springdependencypolicyauditjava.audit.SafeLogger;
import com.github.xingjianluo.springdependencypolicyauditjava.config.AuditProperties;
import com.github.xingjianluo.springdependencypolicyauditjava.model.AuditRecord;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Verdict;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 覆盖审计存储原子去重、按请求查询、回放；
 * 以及 SafeLogger 的白名单与凭据脱敏（敏感值绝不进入日志）。
 */
class AuditStoreTest {

    @TempDir
    Path tempDir;

    private LocalFileAuditStore store(Path file) {
        AuditProperties props = new AuditProperties();
        props.setFile(file.toString());
        LocalFileAuditStore store = new LocalFileAuditStore(props);
        store.replay();
        return store;
    }

    private AuditRecord record(String key, String request, String operator) {
        return new AuditRecord(key, request, operator, "v1", "fp-" + key,
                Verdict.CONDITIONAL_PASS, "basis", "", Instant.parse("2026-09-28T00:00:00Z"));
    }

    @Test
    void put_if_absent_returns_first_record_and_dedups() {
        LocalFileAuditStore store = store(tempDir.resolve("a.log"));
        AuditRecord first = record("k1", "req-1", "alice");
        AuditRecord second = record("k1", "req-1", "mallory");

        assertThat(store.putIfAbsent(first)).contains(first);
        Optional<AuditRecord> returned = store.putIfAbsent(second);
        assertThat(returned).contains(first);
        assertThat(store.size()).isEqualTo(1);
        assertThat(store.findByRequestFingerprint("req-1"))
                .singleElement()
                .extracting(AuditRecord::operator)
                .isEqualTo("alice");
    }

    @Test
    void records_are_persisted_as_one_json_line_each() throws Exception {
        Path file = tempDir.resolve("b.log");
        LocalFileAuditStore store = store(file);
        store.putIfAbsent(record("k1", "req-1", "alice"));
        store.putIfAbsent(record("k2", "req-1", "alice"));
        List<String> lines = Files.readAllLines(file);
        assertThat(lines).hasSize(2);
        assertThat(lines).allSatisfy(line -> {
            assertThat(line).contains("\"idempotencyKey\"");
            assertThat(line).doesNotContain("password", "apiKey", "secret");
        });
    }

    @Test
    void safe_logger_redacts_sensitive_keys_and_drops_unknown_fields() {
        Logger logger = (Logger) LoggerFactory.getLogger("dependency-audit");
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.INFO);
        try {
            SafeLogger safeLogger = new SafeLogger();
            Map<String, Object> fields = new HashMap<>();
            fields.put("event", "dependency-decision");
            fields.put("verdict", "DENY");
            fields.put("password", "super-secret-123");
            fields.put("db.apiKey", "AKIA123456789");
            fields.put("token", "bearer-abc");
            fields.put("arbitraryUserField", "should-be-dropped");

            safeLogger.decision(fields);

            List<ILoggingEvent> events = appender.list;
            assertThat(events).hasSize(1);
            String message = events.get(0).getFormattedMessage();
            assertThat(message).contains("verdict=DENY", "event=dependency-decision");
            assertThat(message)
                    .doesNotContain("super-secret-123", "AKIA123456789", "bearer-abc",
                            "arbitraryUserField", "should-be-dropped",
                            "password", "apiKey", "token");
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void safe_logger_keeps_fingerprint_policy_and_verdict_for_traceability() {
        Logger logger = (Logger) LoggerFactory.getLogger("dependency-audit");
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            Map<String, Object> fields = new HashMap<>();
            fields.put("event", "scan-summary");
            fields.put("requestFingerprint", "abc123");
            fields.put("policyVersion", "default-policy-2026.09.28");
            fields.put("matchedRule", "ALLOW:org.example:safe-*:*");
            fields.put("blocked", "false");
            new SafeLogger().decision(fields);

            String message = appender.list.get(0).getFormattedMessage();
            assertThat(message).contains(
                    "requestFingerprint=abc123",
                    "policyVersion=default-policy-2026.09.28",
                    "matchedRule=ALLOW:org.example:safe-*:*",
                    "blocked=false");
        } finally {
            logger.detachAppender(appender);
        }
    }
}
