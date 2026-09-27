package com.github.xingjianluo.springdependencypolicyauditjava.policy;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.xingjianluo.springdependencypolicyauditjava.model.DependencyScope;
import com.github.xingjianluo.springdependencypolicyauditjava.model.PolicyException;
import com.github.xingjianluo.springdependencypolicyauditjava.model.PolicyRule;
import com.github.xingjianluo.springdependencypolicyauditjava.model.PolicySet;
import com.github.xingjianluo.springdependencypolicyauditjava.model.RuleAction;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Verdict;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 从本地文件系统加载策略 JSON。
 *
 * <p>策略格式示例见 {@code src/main/resources/default-policy.json}。
 * 加载时做严格校验：未知枚举、空版本号、重复规则动作冲突等都快速失败，
 * 避免运行期出现不可解释的决策。</p>
 */
@Component
public class LocalPolicyLoader {

    private final ObjectMapper objectMapper;

    public LocalPolicyLoader() {
        this.objectMapper = JsonMapper.builder()
                .addModule(new JavaTimeModule())
                .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true)
                .build()
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    /**
     * 从本地路径加载策略文件。
     */
    public PolicySet load(Path path) {
        if (path == null) {
            throw new PolicyLoadException("policy path must not be null");
        }
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            throw new PolicyLoadException("policy file not found: " + path);
        }
        try {
            return parse(Files.readString(path));
        } catch (IOException e) {
            throw new PolicyLoadException("failed to read policy file: " + path, e);
        }
    }

    /**
     * 从文本解析并严格校验。
     */
    public PolicySet parse(String json) {
        PolicyFile file;
        try {
            file = objectMapper.readValue(json, PolicyFile.class);
        } catch (IOException e) {
            throw new PolicyLoadException("policy JSON is malformed: " + e.getMessage(), e);
        }
        return validate(file);
    }

    private PolicySet validate(PolicyFile file) {
        if (file == null) {
            throw new PolicyLoadException("policy document is empty");
        }
        if (file.policyVersion == null || file.policyVersion.isBlank()) {
            throw new PolicyLoadException("policyVersion is required");
        }
        Verdict defaultVerdict = file.defaultVerdict != null ? file.defaultVerdict : Verdict.DENY;
        Severity threshold = file.severityThreshold != null
                ? file.severityThreshold : Severity.CRITICAL;

        List<PolicyRule> rules = new ArrayList<>();
        if (file.rules != null) {
            Set<String> ruleKeys = new HashSet<>();
            for (int i = 0; i < file.rules.size(); i++) {
                RuleDto dto = file.rules.get(i);
                String where = "rules[" + i + "]";
                if (dto.action == null) {
                    throw new PolicyLoadException(where + ": action is required (ALLOW/DENY)");
                }
                if (isBlank(dto.name)) {
                    throw new PolicyLoadException(where + ": name is required");
                }
                String versionPattern = isBlank(dto.versionPattern) ? "*" : dto.versionPattern.trim();
                Set<DependencyScope> scopes = parseScopes(dto.scopes, where);
                String key = dto.action + "|" + dto.name.trim() + "|" + versionPattern;
                // 同 action+name+version 重复定义属于策略配置冲突，拒绝启动式加载
                if (!ruleKeys.add(key)) {
                    throw new PolicyLoadException(where
                            + ": duplicate rule definition for " + key);
                }
                rules.add(new PolicyRule(dto.action, dto.name.trim(), versionPattern,
                        scopes, dto.reasonText == null ? "" : dto.reasonText));
            }
        }

        List<PolicyException> exceptions = new ArrayList<>();
        if (file.exceptions != null) {
            Set<String> exceptionIds = new HashSet<>();
            for (int i = 0; i < file.exceptions.size(); i++) {
                ExceptionDto dto = file.exceptions.get(i);
                String where = "exceptions[" + i + "]";
                if (isBlank(dto.id)) {
                    throw new PolicyLoadException(where + ": id is required");
                }
                if (!exceptionIds.add(dto.id.trim())) {
                    throw new PolicyLoadException(where + ": duplicate exception id " + dto.id);
                }
                if (isBlank(dto.name)) {
                    throw new PolicyLoadException(where + ": name is required");
                }
                if (dto.expiresAt == null) {
                    throw new PolicyLoadException(where + ": expiresAt is required");
                }
                if (isBlank(dto.approver)) {
                    throw new PolicyLoadException(where + ": approver is required");
                }
                String versionPattern = isBlank(dto.versionPattern) ? "*" : dto.versionPattern.trim();
                exceptions.add(new PolicyException(
                        dto.id.trim(), dto.name.trim(), versionPattern,
                        parseScopes(dto.scopes, where),
                        dto.expiresAt, dto.approver.trim(),
                        dto.justification == null ? "" : dto.justification));
            }
        }

        Map<String, Severity> advisory = new LinkedHashMap<>();
        if (file.advisorySeverity != null) {
            for (Map.Entry<String, String> entry : file.advisorySeverity.entrySet()) {
                try {
                    advisory.put(entry.getKey().trim(),
                            Severity.valueOf(entry.getValue().trim().toUpperCase()));
                } catch (IllegalArgumentException e) {
                    throw new PolicyLoadException("advisorySeverity." + entry.getKey()
                            + ": unknown severity '" + entry.getValue() + "'");
                }
            }
        }

        return new PolicySet(file.policyVersion.trim(), defaultVerdict, threshold,
                List.copyOf(rules), List.copyOf(exceptions), Map.copyOf(advisory));
    }

    private static Set<DependencyScope> parseScopes(List<String> raw, String where) {
        if (raw == null || raw.isEmpty()) {
            return Set.of();
        }
        Set<DependencyScope> scopes = new HashSet<>();
        for (String value : raw) {
            try {
                scopes.add(DependencyScope.valueOf(value.trim().toUpperCase()));
            } catch (IllegalArgumentException e) {
                throw new PolicyLoadException(where + ": unknown scope '" + value + "'");
            }
        }
        return Set.copyOf(scopes);
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    // ---------- DTO ----------

    static final class PolicyFile {
        public String policyVersion;
        public Verdict defaultVerdict;
        public Severity severityThreshold;
        public List<RuleDto> rules;
        public List<ExceptionDto> exceptions;
        public Map<String, String> advisorySeverity;
    }

    static final class RuleDto {
        public RuleAction action;
        public String name;
        public String versionPattern;
        public List<String> scopes;
        public String reasonText;
    }

    static final class ExceptionDto {
        public String id;
        public String name;
        public String versionPattern;
        public List<String> scopes;
        public Instant expiresAt;
        public String approver;
        public String justification;
    }
}
