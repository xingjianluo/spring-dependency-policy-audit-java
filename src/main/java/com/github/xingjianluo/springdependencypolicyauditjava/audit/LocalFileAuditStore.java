package com.github.xingjianluo.springdependencypolicyauditjava.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.xingjianluo.springdependencypolicyauditjava.config.AuditProperties;
import com.github.xingjianluo.springdependencypolicyauditjava.model.AuditRecord;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Verdict;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地文件 + 内存索引审计存储。
 *
 * <p>并发保证：</p>
 * <ul>
 *   <li>{@link ConcurrentHashMap#putIfAbsent} 提供 JVM 内原子去重，
 *       同一批次/并发重复提交只会落一条审计、只返回首次结论；</li>
 *   <li>追加写文件时用 {@link FileLock} 串行化跨线程/跨进程写；
 *       只有抢占到内存键的线程才会写盘，因此不会重复落盘；</li>
 *   <li>启动时回放已有审计文件重建索引。</li>
 * </ul>
 * 文件每行一条 JSON，仅包含 {@link AuditRecord} 的非敏感字段。
 */
@Component
public class LocalFileAuditStore implements AuditStore {

    private static final Logger log = LoggerFactory.getLogger(LocalFileAuditStore.class);

    private final Path file;
    private final ObjectMapper objectMapper;
    private final Map<String, AuditRecord> byKey = new ConcurrentHashMap<>();

    public LocalFileAuditStore(AuditProperties properties) {
        this.file = Path.of(properties.getFile());
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    @PostConstruct
    public void replay() {
        if (!Files.exists(file)) {
            return;
        }
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (String line : lines) {
                if (line.isBlank()) {
                    continue;
                }
                AuditRecord record = objectMapper.readValue(line, AuditRecord.class);
                byKey.putIfAbsent(record.idempotencyKey(), record);
            }
            log.info("replayed audit records count={} file={}", byKey.size(), file);
        } catch (IOException e) {
            throw new IllegalStateException("failed to replay audit file: " + file, e);
        }
    }

    @Override
    public Optional<AuditRecord> putIfAbsent(AuditRecord record) {
        AuditRecord existing = byKey.putIfAbsent(record.idempotencyKey(), record);
        if (existing != null) {
            return Optional.of(existing);
        }
        appendToFile(record);
        return Optional.of(record);
    }

    @Override
    public List<AuditRecord> findByRequestFingerprint(String requestFingerprint) {
        List<AuditRecord> result = new ArrayList<>();
        for (AuditRecord record : byKey.values()) {
            if (record.requestFingerprint().equals(requestFingerprint)) {
                result.add(record);
            }
        }
        result.sort(Comparator
                .comparing(AuditRecord::createdAt)
                .thenComparing(AuditRecord::dependencyFingerprint));
        return List.copyOf(result);
    }

    /** 测试与排障使用：当前存储中的记录数。 */
    public int size() {
        return byKey.size();
    }

    private synchronized void appendToFile(AuditRecord record) {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            try (FileChannel channel = FileChannel.open(file,
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                 FileLock ignored = channel.lock()) {
                String line = objectMapper.writeValueAsString(record) + System.lineSeparator();
                channel.write(StandardCharsets.UTF_8.encode(line));
            }
        } catch (IOException e) {
            // 写盘失败必须回滚内存键，否则会出现“已放行但无审计”的缺失
            byKey.remove(record.idempotencyKey(), record);
            throw new IllegalStateException("failed to persist audit record", e);
        }
    }
}
