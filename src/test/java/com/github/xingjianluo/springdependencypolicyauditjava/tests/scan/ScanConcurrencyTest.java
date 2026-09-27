package com.github.xingjianluo.springdependencypolicyauditjava.tests.scan;

import com.github.xingjianluo.springdependencypolicyauditjava.audit.LocalFileAuditStore;
import com.github.xingjianluo.springdependencypolicyauditjava.audit.SafeLogger;
import com.github.xingjianluo.springdependencypolicyauditjava.config.AuditProperties;
import com.github.xingjianluo.springdependencypolicyauditjava.config.PolicyProperties;
import com.github.xingjianluo.springdependencypolicyauditjava.manifest.LocalManifestReader;
import com.github.xingjianluo.springdependencypolicyauditjava.manifest.ManifestFormatRegistry;
import com.github.xingjianluo.springdependencypolicyauditjava.manifest.ManifestJsonParser;
import com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ScanResult;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Verdict;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.LocalPolicyLoader;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.LocalPolicyProvider;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyEvaluator;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.Fingerprints;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.ScanService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 覆盖：并发同批提交不重复放行/不重复审计、结论一致；
 * 重复提交标记 duplicateSubmission 且审计不增加；
 * 解析失败与 DENY 必须阻断；审计文件只落一次每条依赖。
 * 全程本地文件、固定时钟、无网络无真实凭据。
 */
class ScanConcurrencyTest {

    @TempDir
    Path tempDir;

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-09-28T00:00:00Z"), ZoneOffset.UTC);

    private ScanService newService(Path auditFile) {
        AuditProperties auditProperties = new AuditProperties();
        auditProperties.setFile(auditFile.toString());
        LocalFileAuditStore store = new LocalFileAuditStore(auditProperties);
        store.replay();
        Fingerprints fingerprints = new Fingerprints();
        LocalPolicyLoader policyLoader = new LocalPolicyLoader();
        PolicyProperties policyProperties = new PolicyProperties();
        LocalPolicyProvider provider = new LocalPolicyProvider(policyProperties, policyLoader);
        PolicyEvaluator evaluator = new PolicyEvaluator(FIXED_CLOCK);
        ManifestFormatRegistry registry = new ManifestFormatRegistry(
                List.of(new ManifestJsonParser(fingerprints)));
        return new ScanService(registry, new LocalManifestReader(), policyLoader,
                evaluator, store, new SafeLogger(), fingerprints, FIXED_CLOCK, provider);
    }

    private static final String CLEAN_MANIFEST = """
            { "dependencies": [
              {"group":"org.example","name":"safe-lib","version":"1.0.0","scope":"COMPILE"}
            ]}
            """;

    private static final String DENIED_MANIFEST = """
            { "dependencies": [
              {"group":"com.knownbad","name":"malware-lib","version":"9.9.9","scope":"COMPILE"}
            ]}
            """;

    @Test
    void concurrent_identical_submissions_produce_single_audit_and_consistent_verdict()
            throws Exception {
        Path auditFile = tempDir.resolve("audit-1.log");
        ScanService service = newService(auditFile);

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        Set<String> requestFingerprints = ConcurrentHashMap.newKeySet();
        List<Future<ScanResult>> futures;
        try {
            List<Callable<ScanResult>> tasks = IntStream.range(0, threads)
                    .<Callable<ScanResult>>mapToObj(i -> () ->
                            service.scanRaw("manifest-json", "m.json", CLEAN_MANIFEST, "alice"))
                    .toList();
            futures = pool.invokeAll(tasks);
        } finally {
            pool.shutdown();
            assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();
        }

        ScanResult first = futures.get(0).get();
        for (Future<ScanResult> future : futures) {
            ScanResult result = future.get();
            assertThat(result.requestFingerprint()).isEqualTo(first.requestFingerprint());
            assertThat(result.blocked()).isFalse();
            assertThat(result.decisions()).hasSize(1);
            requestFingerprints.add(result.requestFingerprint());
        }
        assertThat(requestFingerprints).hasSize(1);

        List<String> lines = Files.readAllLines(auditFile);
        assertThat(lines).hasSize(1);
        assertThat(lines.get(0))
                .contains("\"operator\":\"alice\"")
                .contains("\"policyVersion\":\"default-policy-2026.09.28\"");
        assertThat(lines.get(0)).doesNotContain("password", "secret", "token");
    }

    @Test
    void sequential_duplicate_submission_is_flagged_and_not_audited_again() throws Exception {
        Path auditFile = tempDir.resolve("audit-2.log");
        ScanService service = newService(auditFile);

        ScanResult first = service.scanRaw("manifest-json", "m.json", CLEAN_MANIFEST, "alice");
        ScanResult second = service.scanRaw("manifest-json", "m.json", CLEAN_MANIFEST, "bob");

        assertThat(first.duplicateSubmission()).isFalse();
        assertThat(second.duplicateSubmission()).isTrue();
        // 结论不互相覆盖：两次判定本身一致，审计文件只保留首次操作者的一条
        assertThat(second.decisions().get(0).verdict()).isEqualTo(Verdict.PASS);
        assertThat(Files.readAllLines(auditFile))
                .hasSize(1)
                .singleElement()
                .asString()
                .contains("\"operator\":\"alice\"")
                .doesNotContain("bob");
    }

    @Test
    void denied_dependency_blocks_release_with_explicit_reason() {
        Path auditFile = tempDir.resolve("audit-3.log");
        ScanService service = newService(auditFile);

        ScanResult result = service.scanRaw("manifest-json", "bad.json", DENIED_MANIFEST, "alice");
        assertThat(result.blocked()).isTrue();
        assertThat(result.decisions()).hasSize(1);
        assertThat(result.decisions().get(0).verdict()).isEqualTo(Verdict.DENY);
        assertThat(result.decisions().get(0).failureReason()).isEqualTo(FailureReason.DENIED_BY_RULE);
    }

    @Test
    void malformed_manifest_blocks_and_distinguishes_reasons() {
        Path auditFile = tempDir.resolve("audit-4.log");
        ScanService service = newService(auditFile);

        String bad = """
                { "dependencies": [
                  {"group":"org.example","name":"a","version":"1.0.0","scope":"COMPILE"},
                  {"group":"org.example","name":"a","version":"2.0.0","scope":"COMPILE"},
                  {"name":"x","version":"1.0.0"}
                ]}
                """;
        ScanResult result = service.scanRaw("manifest-json", "bad.json", bad, "alice");
        assertThat(result.blocked()).isTrue();
        assertThat(result.parseIssues())
                .extracting(i -> i.reason())
                .contains(FailureReason.VERSION_CONFLICT, FailureReason.FIELD_MISSING);
        // 只有合法依赖参与判定
        assertThat(result.decisions()).hasSize(1);
    }

    @Test
    void expired_exception_ends_in_block() {
        Path auditFile = tempDir.resolve("audit-5.log");
        ScanService service = newService(auditFile);

        String manifest = """
                { "dependencies": [
                  {"group":"org.example","name":"expired-shim","version":"0.9.0","scope":"COMPILE"}
                ]}
                """;
        ScanResult result = service.scanRaw("manifest-json", "s.json", manifest, "alice");
        assertThat(result.blocked()).isTrue();
        assertThat(result.decisions().get(0).failureReason())
                .isEqualTo(FailureReason.EXCEPTION_EXPIRED);
    }

    @Test
    void audit_store_rebuilds_index_from_file_after_restart() throws Exception {
        Path auditFile = tempDir.resolve("audit-6.log");
        newService(auditFile).scanRaw("manifest-json", "m.json", CLEAN_MANIFEST, "alice");

        ScanService restarted = newService(auditFile);
        ScanResult again = restarted.scanRaw("manifest-json", "m.json", CLEAN_MANIFEST, "alice");
        assertThat(again.duplicateSubmission()).isTrue();
        assertThat(Files.readAllLines(auditFile)).hasSize(1);
    }
}
