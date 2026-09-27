package com.github.xingjianluo.springdependencypolicyauditjava.policy;

import com.github.xingjianluo.springdependencypolicyauditjava.model.Ecosystem;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Severity;
import com.github.xingjianluo.springdependencypolicyauditjava.parser.Json;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * JSON 策略加载器：优先读取 {@code policy.file} 指定的本地文件，
 * 否则回退类路径内置默认策略 {@code /default-policy.json}。
 * 加载阶段对未知枚举、错误版本约束等做严格校验，非法配置直接快速失败。
 */
@Component
public class JsonPolicyLoader implements PolicyLoader {

    private static final String CLASSPATH_DEFAULT = "/default-policy.json";

    private final String policyFile;
    private volatile PolicySet cached;

    public JsonPolicyLoader(@Value("${policy.file:}") String policyFile) {
        this.policyFile = policyFile == null ? "" : policyFile.trim();
    }

    @Override
    public PolicySet load() {
        PolicySet snapshot = cached;
        if (snapshot != null) {
            return snapshot;
        }
        synchronized (this) {
            if (cached == null) {
                cached = parse(readPolicyText());
            }
            return cached;
        }
    }

    private String readPolicyText() {
        if (!policyFile.isEmpty()) {
            Path path = Path.of(policyFile);
            if (!Files.isRegularFile(path)) {
                throw new PolicyLoadException("策略文件不存在或不是普通文件: " + policyFile);
            }
            try {
                return Files.readString(path, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new PolicyLoadException("读取策略文件失败: " + policyFile, e);
            }
        }
        try (InputStream in = JsonPolicyLoader.class.getResourceAsStream(CLASSPATH_DEFAULT)) {
            if (in == null) {
                throw new PolicyLoadException("类路径缺少默认策略: " + CLASSPATH_DEFAULT);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new PolicyLoadException("读取默认策略失败", e);
        }
    }

    private PolicySet parse(String text) {
        Object root;
        try {
            root = Json.parse(text);
        } catch (Json.JsonParseException e) {
            throw new PolicyLoadException("策略 JSON 格式非法: " + e.getMessage(), e);
        }
        if (!(root instanceof Map)) {
            throw new PolicyLoadException("策略根节点必须是 JSON 对象");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> rootMap = (Map<String, Object>) root;

        String version = stringOr(rootMap.get("policyVersion"), "0");
        Severity maxSeverity = Severity.fromString(stringOr(rootMap.get("maxSeverity"), "HIGH"));
        if (maxSeverity == null) {
            throw new PolicyLoadException("maxSeverity 非法: " + rootMap.get("maxSeverity"));
        }
        List<String> enforcedScopes = readStringList(rootMap.get("enforcedScopes"),
                List.of("compile", "runtime"));

        List<PolicyRule> rules = new ArrayList<>();
        Object rulesNode = rootMap.get("rules");
        if (rulesNode != null) {
            int idx = 0;
            for (Object item : Json.asList(rulesNode)) {
                rules.add(parseRule(asMap(item, "rules[" + idx + "]")));
                idx++;
            }
        }

        List<Advisory> advisories = new ArrayList<>();
        Object advNode = rootMap.get("advisories");
        if (advNode != null) {
            int idx = 0;
            for (Object item : Json.asList(advNode)) {
                advisories.add(parseAdvisory(asMap(item, "advisories[" + idx + "]")));
                idx++;
            }
        }

        List<ExceptionGrant> exceptions = new ArrayList<>();
        Object exNode = rootMap.get("exceptions");
        if (exNode != null) {
            int idx = 0;
            for (Object item : Json.asList(exNode)) {
                exceptions.add(parseException(asMap(item, "exceptions[" + idx + "]")));
                idx++;
            }
        }
        return new PolicySet(version, maxSeverity, enforcedScopes, rules, advisories, exceptions);
    }

    private PolicyRule parseRule(Map<String, Object> m) {
        String id = requireString(m, "id", "规则");
        AllowDeny action = AllowDeny.fromString(stringOr(m.get("action"), null));
        if (action == null) {
            throw new PolicyLoadException("规则 " + id + " 的 action 非法: " + m.get("action"));
        }
        Ecosystem eco = parseEcosystem(m.get("ecosystem"));
        List<String> scopes = readStringList(m.get("scopes"), List.of());
        return new PolicyRule(id, action, eco,
                stringOr(m.get("groupPattern"), ""),
                stringOr(m.get("namePattern"), ""),
                stringOr(m.get("versionRange"), ""),
                scopes,
                stringOr(m.get("reason"), ""));
    }

    private Advisory parseAdvisory(Map<String, Object> m) {
        String id = requireString(m, "id", "情报");
        Ecosystem eco = parseEcosystem(m.get("ecosystem"));
        Severity severity = Severity.fromString(stringOr(m.get("severity"), null));
        if (severity == null) {
            throw new PolicyLoadException("情报 " + id + " 的 severity 非法: " + m.get("severity"));
        }
        return new Advisory(id, eco,
                stringOr(m.get("group"), ""),
                requireString(m, "name", "情报 " + id),
                stringOr(m.get("versionRange"), ""),
                severity,
                stringOr(m.get("reason"), ""));
    }

    private ExceptionGrant parseException(Map<String, Object> m) {
        String id = requireString(m, "id", "例外");
        Ecosystem eco = parseEcosystem(m.get("ecosystem"));
        String expiresRaw = stringOr(m.get("expiresOn"), null);
        LocalDate expires = null;
        if (expiresRaw != null && !expiresRaw.isBlank()) {
            try {
                expires = LocalDate.parse(expiresRaw.trim());
            } catch (RuntimeException e) {
                throw new PolicyLoadException("例外 " + id + " 的 expiresOn 必须是 yyyy-MM-dd: " + expiresRaw);
            }
        }
        return new ExceptionGrant(id, eco,
                stringOr(m.get("group"), ""),
                requireString(m, "name", "例外 " + id),
                stringOr(m.get("versionRange"), ""),
                readStringList(m.get("scopes"), List.of()),
                expires,
                stringOr(m.get("requestedBy"), "unknown"),
                stringOr(m.get("justification"), ""));
    }

    private Ecosystem parseEcosystem(Object raw) {
        String s = stringOr(raw, null);
        if (s == null || s.isBlank()) {
            throw new PolicyLoadException("缺少必填的 ecosystem 字段");
        }
        Ecosystem eco = Ecosystem.fromString(s);
        if (eco == null) {
            throw new PolicyLoadException("ecosystem 不受支持: " + s);
        }
        return eco;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> asMap(Object value, String where) {
        if (!(value instanceof Map)) {
            throw new PolicyLoadException(where + " 必须是 JSON 对象");
        }
        return (Map<String, Object>) value;
    }

    private String requireString(Map<String, Object> m, String key, String what) {
        String v = stringOr(m.get(key), null);
        if (v == null || v.isBlank()) {
            throw new PolicyLoadException(what + " 缺少必填字段 " + key);
        }
        return v.trim();
    }

    private List<String> readStringList(Object node, List<String> fallback) {
        if (node == null) {
            return fallback;
        }
        List<String> result = new ArrayList<>();
        for (Object o : Json.asList(node)) {
            if (o == null) {
                throw new PolicyLoadException("字符串列表中不允许 null");
            }
            result.add(o.toString().trim());
        }
        return result;
    }

    private String stringOr(Object value, String fallback) {
        return value == null ? fallback : value.toString();
    }
}
