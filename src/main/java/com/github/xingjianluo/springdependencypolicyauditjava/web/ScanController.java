package com.github.xingjianluo.springdependencypolicyauditjava.web;

import com.github.xingjianluo.springdependencypolicyauditjava.audit.AuditRecord;
import com.github.xingjianluo.springdependencypolicyauditjava.audit.AuditStore;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.ScanOutcome;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.ScanRequest;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.ScanService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** 本地发布前扫描与审计查询接口，不依赖任何外部服务。 */
@RestController
@RequestMapping("/api")
public class ScanController {

    private final ScanService scanService;
    private final AuditStore auditStore;

    public ScanController(ScanService scanService, AuditStore auditStore) {
        this.scanService = scanService;
        this.auditStore = auditStore;
    }

    /**
     * 提交清单扫描。
     * 200：全部通过（可能含 WARN）；403：存在被阻断依赖；422：清单解析失败。
     */
    @PostMapping("/scans")
    public ResponseEntity<?> scan(@RequestBody ScanApi body) {
        ScanRequest request = new ScanRequest(
                body.manifestType(), body.contents(), body.operator(),
                body.batchId(), body.idempotencyKey());
        ScanOutcome outcome = scanService.scan(request);
        if (outcome.blocked()) {
            throw new ApiExceptionHandler.PolicyBlockedException(outcome,
                    "存在未通过策略的依赖，发布已阻断，共 " + outcome.denied() + " 项");
        }
        return ResponseEntity.ok(outcome);
    }

    /** 列出全部审计记录（本地追溯）。 */
    @GetMapping("/audits")
    public Map<String, Object> audits() {
        List<AuditRecord> records = auditStore.findAll();
        return Map.of("total", records.size(), "records", records);
    }

    /** 按批次查询审计记录。 */
    @GetMapping("/audits/batches/{batchId}")
    public Map<String, Object> auditsByBatch(@PathVariable String batchId) {
        List<AuditRecord> records = auditStore.findByBatch(batchId);
        return Map.of("batchId", batchId, "total", records.size(), "records", records);
    }
}
