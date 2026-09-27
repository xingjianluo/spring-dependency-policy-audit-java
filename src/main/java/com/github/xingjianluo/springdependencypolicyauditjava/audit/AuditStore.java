package com.github.xingjianluo.springdependencypolicyauditjava.audit;

import com.github.xingjianluo.springdependencypolicyauditjava.model.AuditRecord;

import java.util.List;
import java.util.Optional;

/**
 * 审计存储：本地持久化，支持按幂等键去重。
 */
public interface AuditStore {

    /**
     * 若幂等键已存在则返回既有记录（不重复写入），否则原子写入并返回新记录。
     */
    Optional<AuditRecord> putIfAbsent(AuditRecord record);

    List<AuditRecord> findByRequestFingerprint(String requestFingerprint);
}
