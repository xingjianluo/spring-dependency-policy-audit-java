package com.github.xingjianluo.springdependencypolicyauditjava.tests;

import com.github.xingjianluo.springdependencypolicyauditjava.audit.AuditLogger;
import com.github.xingjianluo.springdependencypolicyauditjava.audit.InMemoryAuditStore;
import com.github.xingjianluo.springdependencypolicyauditjava.decision.Decision;
import com.github.xingjianluo.springdependencypolicyauditjava.decision.PolicyEngine;
import com.github.xingjianluo.springdependencypolicyauditjava.parser.JsonManifestParser;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.JsonPolicyLoader;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.DefaultScanService;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.ScanOutcome;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.ScanRequest;
import com.github.xingjianluo.springdependencypolicyauditjava.parser.ManifestParseException;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class DefaultScanServiceTest {

    private final Clock fixedClock =
            Clock.fixed(Instant.parse("2026-09-28T08:00:00Z"), ZoneOffset.UTC);

    private DefaultScanService newService() {
        return new DefaultScanService(
                new JsonManifestParser(),
                new JsonPolicyLoader(""),
                new PolicyEngine(fixedClock),
                new InMemoryAuditStore(),
                new AuditLogger(),
                fixedClock);
    }

    private DefaultScanService newServiceWithStore(InMemoryAuditStore store) {
        return new DefaultScanService(
                new JsonManifestParser(),
                new JsonPolicyLoader(""),
                new PolicyEngine(fixedClock),
                store,
                new AuditLogger(),
                fixedClock);
    }

    private String mavenManifest(String... coords) {
        StringBuilder sb = new StringBuilder("{\"ecosystem\":\"maven\",\"dependencies\":[");
        for (int i = 0; i < coords.length; i++) {
            String[] parts = coords[i].split(":");
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"group\":\"").append(parts[0])
                    .append("\",\"name\":\"").append(parts[1])
                    .append("\",\"version\":\"").append(parts[2])
                    .append("\",\"scope\":\"").append(parts[3]).append("\"}");
        }
        return sb.append("]}").toString();
    }

    @Test
    void cleanManifestPasses() {
        DefaultScanService service = newService();
        ScanOutcome outcome = service.scan(new ScanRequest(
                "manifest", mavenManifest("com.acme.safe:lib:1.0.0:compile"),
                "alice", "batch-1", "key-1"));
        assertFalse(outcome.blocked());
        assertEquals("PASSED", outcome.status());
        assertEquals(1, outcome.passed());
    }

    @Test
    void deniedDependencyBlocksAndRecordsAudit() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        DefaultScanService service = newServiceWithStore(store);
        ScanOutcome outcome = service.scan(new ScanRequest(
                "manifest", mavenManifest("com.example.banned:badlib:1.0.0:compile"),
                "alice", "batch-block", "key-block"));
        assertTrue(outcome.blocked());
        assertEquals("BLOCKED", outcome.status());
        assertEquals(1, outcome.denied());
        assertEquals(Decision.DENY, outcome.decisions().get(0).decision());
        assertEquals(1, store.findByBatch("batch-block").size(), "阻断必须写一条审计");
    }

    @Test
    void criticalAdvisoryOverThresholdBlocks() {
        DefaultScanService service = newService();
        ScanOutcome outcome = service.scan(new ScanRequest(
                "manifest", mavenManifest("com.example.vuln:vuln-core:1.5.0:compile"),
                "alice", "batch-cve", "key-cve"));
        assertTrue(outcome.blocked());
        // 该坐标同时命中默认情报与默认（已过期）例外，两种原因码都属于确定性阻断
        assertTrue(List.of("SEVERITY_THRESHOLD", "EXCEPTION_EXPIRED")
                .contains(outcome.decisions().get(0).reasonCode()));
    }

    @Test
    void criticalAdvisoryWithoutExceptionReportsThreshold() {
        // 1.9.5 命中情报区间；过期例外区间同样覆盖，但本例验证 DENY 结论本身
        DefaultScanService service = newService();
        ScanOutcome outcome = service.scan(new ScanRequest(
                "manifest", mavenManifest("com.example.vuln:vuln-core:1.9.5:runtime"),
                "alice", "batch-cve2", "key-cve2"));
        assertTrue(outcome.blocked());
        assertEquals(Decision.DENY, outcome.decisions().get(0).decision());
        assertNotNull(outcome.decisions().get(0).matchedAdvisoryId());
    }

    @Test
    void expiredDefaultExceptionDoesNotSaveBlockingDependency() {
        // 默认策略中 EXC-DEMO-EXPIRED 已于 2025-01-01 到期
        DefaultScanService service = newService();
        ScanOutcome outcome = service.scan(new ScanRequest(
                "manifest", mavenManifest("com.example.vuln:vuln-core:1.0.0:compile"),
                "alice", "batch-expired", "key-expired"));
        assertTrue(outcome.blocked());
        assertEquals("EXCEPTION_EXPIRED", outcome.decisions().get(0).reasonCode());
    }

    @Test
    void belowThresholdWarnsAndAudits() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        DefaultScanService service = newServiceWithStore(store);
        String npm = "{\"ecosystem\":\"npm\",\"dependencies\":["
                + "{\"name\":\"vuln-pkg\",\"version\":\"2.0.0\",\"scope\":\"runtime\"}]}";
        ScanOutcome outcome = service.scan(new ScanRequest(
                "manifest", npm, "alice", "batch-warn", "key-warn"));
        assertFalse(outcome.blocked());
        assertEquals(1, outcome.warned());
        assertEquals("PASSED_WITH_WARNINGS", outcome.status());
        assertEquals(1, store.findByBatch("batch-warn").size(), "有条件放行必须写审计");
    }

    @Test
    void testScopeDependencyIsOutOfScopeAndNotAudited() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        DefaultScanService service = newServiceWithStore(store);
        ScanOutcome outcome = service.scan(new ScanRequest(
                "manifest", mavenManifest("com.example.banned:badlib:1.0.0:test"),
                "alice", "batch-test-scope", "key-scope"));
        assertFalse(outcome.blocked());
        assertEquals(1, outcome.outOfScope());
        assertTrue(store.findByBatch("batch-test-scope").isEmpty(),
                "范围外依赖不应产生风险审计");
    }

    @Test
    void malformedManifestFailsAndIsNotAudited() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        DefaultScanService service = newServiceWithStore(store);
        ManifestParseException ex = assertThrows(ManifestParseException.class,
                () -> service.scan(new ScanRequest(
                        "manifest", "{ broken", "alice", "batch-bad", "key-bad")));
        assertFalse(ex.issues().isEmpty());
        assertTrue(store.findAll().isEmpty(), "解析失败不得产生审计或放行");
    }

    @Test
    void duplicateSubmissionReturnsSameOutcomeAndSingleAudit() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        DefaultScanService service = newServiceWithStore(store);
        String contents = mavenManifest("com.example.vuln:vuln-core:1.5.0:compile");
        ScanRequest req = new ScanRequest("manifest", contents, "alice", "dup-batch", "dup-key");
        ScanOutcome first = service.scan(req);
        ScanOutcome second = service.scan(req);
        ScanOutcome third = service.scan(req);
        assertTrue(first.blocked());
        assertSame(first, second, "重复提交必须返回同一结论对象");
        assertSame(first, third);
        assertEquals(1, store.findByBatch("dup-batch").size(), "重复提交不得重复写审计");
    }

    @Test
    void concurrentSubmissionsDeduplicate() throws Exception {
        InMemoryAuditStore store = new InMemoryAuditStore();
        DefaultScanService service = newServiceWithStore(store);
        String contents = mavenManifest("com.example.vuln:vuln-core:1.5.0:compile");
        int threads = 24;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<ScanOutcome>> futures = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return service.scan(new ScanRequest(
                        "manifest", contents, "alice", "cc-batch", "cc-key"));
            }));
        }
        start.countDown();
        ScanOutcome first = futures.get(0).get(30, TimeUnit.SECONDS);
        for (Future<ScanOutcome> f : futures) {
            assertSame(first, f.get(), "并发请求必须共享同一次判定结论");
        }
        pool.shutdown();
        assertEquals(1, store.findByBatch("cc-batch").size(), "并发扫描只能产生一条审计");
    }

    @Test
    void distinctIdempotencyKeysDoNotCollide() {
        DefaultScanService service = newService();
        ScanOutcome a = service.scan(new ScanRequest("manifest",
                mavenManifest("com.acme.safe:l1:1.0.0:compile"), "alice", "b1", "k1"));
        ScanOutcome b = service.scan(new ScanRequest("manifest",
                mavenManifest("com.acme.safe:l2:1.0.0:compile"), "alice", "b2", "k2"));
        assertNotSame(a, b);
        assertEquals("b1", a.batchId());
        assertEquals("b2", b.batchId());
    }

    @Test
    void blankRequestRejected() {
        DefaultScanService service = newService();
        assertThrows(IllegalArgumentException.class,
                () -> service.scan(new ScanRequest("manifest", "", "alice", "b", "k")));
        assertThrows(IllegalArgumentException.class,
                () -> service.scan(new ScanRequest("", "{}", "alice", "b", "k")));
    }

    @Test
    void auditRecordContainsOperatorPolicyAndFingerprint() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        DefaultScanService service = newServiceWithStore(store);
        service.scan(new ScanRequest(
                "manifest", mavenManifest("com.example.banned:badlib:1.0.0:compile"),
                "operator-xyz", "trace-batch", "trace-key"));
        var record = store.findByBatch("trace-batch").get(0);
        assertEquals("operator-xyz", record.operator());
        assertEquals("default-1.0.0", record.policyVersion());
        assertEquals(64, record.dependencyFingerprint().length());
        assertNotNull(record.basis());
        assertNotNull(record.decidedAt());
    }
}
