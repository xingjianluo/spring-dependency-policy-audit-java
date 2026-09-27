package com.github.xingjianluo.springdependencypolicyauditjava.audit;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 并发安全的内存审计存储（仅依赖本地能力）。
 *
 * <p>追加按 {@code auditId} 去重：同一批次对同一依赖指纹只可能存在一条有效审计，
 * 因此并发扫描或重复提交不会产生重复放行记录或审计覆盖。
 */
@Component
public class InMemoryAuditStore implements AuditStore {

    private final CopyOnWriteArrayList<AuditRecord> records = new CopyOnWriteArrayList<>();

    @Override
    public void append(AuditRecord record) {
        for (AuditRecord existing : records) {
            if (existing.auditId().equals(record.auditId())) {
                return; // 幂等：重复提交直接忽略，结论不被覆盖
            }
        }
        records.addIfAbsent(record);
    }

    @Override
    public List<AuditRecord> findByBatch(String batchId) {
        List<AuditRecord> result = new ArrayList<>();
        for (AuditRecord r : records) {
            if (r.batchId().equals(batchId)) {
                result.add(r);
            }
        }
        return List.copyOf(result);
    }

    @Override
    public Optional<AuditRecord> findByDependencyFingerprint(String fingerprint) {
        for (AuditRecord r : records) {
            if (r.dependencyFingerprint().equals(fingerprint)) {
                return Optional.of(r);
            }
        }
        return Optional.empty();
    }

    @Override
    public List<AuditRecord> findAll() {
        return List.copyOf(records);
    }
}
