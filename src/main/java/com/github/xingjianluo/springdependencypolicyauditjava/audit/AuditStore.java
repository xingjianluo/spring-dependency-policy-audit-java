package com.github.xingjianluo.springdependencypolicyauditjava.audit;

import java.util.List;
import java.util.Optional;

/**
 * 审计存储（本地内存实现）：仅追加、按批次/指纹可查。
 */
public interface AuditStore {
    void append(AuditRecord record);

    List<AuditRecord> findByBatch(String batchId);

    Optional<AuditRecord> findByDependencyFingerprint(String fingerprint);

    List<AuditRecord> findAll();
}
