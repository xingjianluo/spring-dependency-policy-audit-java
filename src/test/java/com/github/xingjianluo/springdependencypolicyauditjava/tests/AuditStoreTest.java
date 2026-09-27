package com.github.xingjianluo.springdependencypolicyauditjava.tests;

import com.github.xingjianluo.springdependencypolicyauditjava.audit.AuditRecord;
import com.github.xingjianluo.springdependencypolicyauditjava.audit.InMemoryAuditStore;
import com.github.xingjianluo.springdependencypolicyauditjava.decision.Decision;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class AuditStoreTest {

    private AuditRecord record(String auditId, String batch, String fingerprint) {
        return new AuditRecord(auditId, Instant.parse("2026-09-28T00:00:00Z"),
                batch, "alice", "t-1", fingerprint, "com.x:n:1.0",
                Severity.HIGH, Decision.WARN, "EXCEPTION_GRANTED", "依据");
    }

    @Test
    void duplicateAppendIsIgnored() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        AuditRecord r1 = record("id-1", "b1", "fp-1");
        store.append(r1);
        // 相同 auditId 但内容不同，也必须被忽略（结论不被覆盖）
        store.append(record("id-1", "b1", "fp-CHANGED"));
        assertEquals(1, store.findAll().size());
        assertEquals("fp-1", store.findAll().get(0).dependencyFingerprint());
    }

    @Test
    void findsByBatchAndFingerprint() {
        InMemoryAuditStore store = new InMemoryAuditStore();
        store.append(record("a", "b1", "fp-a"));
        store.append(record("b", "b2", "fp-b"));
        assertEquals(1, store.findByBatch("b1").size());
        assertTrue(store.findByDependencyFingerprint("fp-b").isPresent());
        assertTrue(store.findByDependencyFingerprint("nope").isEmpty());
    }

    @Test
    void concurrentAppendsOfSameIdYieldSingleRecord() throws Exception {
        InMemoryAuditStore store = new InMemoryAuditStore();
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    store.append(record("same-id", "b1", "fp-1"));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();
        assertEquals(1, store.findAll().size(), "并发重复写入只能保留一条审计");
    }
}
