package com.github.xingjianluo.springdependencypolicyauditjava.manifest;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.springdependencypolicyauditjava.model.DependencyScope;
import com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason;
import com.github.xingjianluo.springdependencypolicyauditjava.model.NormalizedDependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseIssue;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseOutcome;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.Fingerprints;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 本地依赖清单 JSON 解析器。
 *
 * <p>期望格式：</p>
 * <pre>{@code
 * { "manifestType": "manifest-json",
 *   "dependencies": [
 *     {"group":"org.example","name":"lib","version":"1.2.3","scope":"COMPILE"}
 *   ] }
 * }</pre>
 *
 * <p>对每个条目分别校验，异常绝不静默跳过：</p>
 * <ul>
 *   <li>{@link FailureReason#FORMAT_MALFORMED} 整个 JSON 无法解析 / 结构错误 / 版本串本身非法；</li>
 *   <li>{@link FailureReason#FIELD_MISSING} group/name 缺失或空白；</li>
 *   <li>{@link FailureReason#VERSION_INCOMPLETE} 缺版本、动态版本（LATEST/RELEASE）、
 *       版本缺少完整数字版本段；</li>
 *   <li>{@link FailureReason#DUPLICATE_ENTRY} 同坐标重复且版本一致；</li>
 *   <li>{@link FailureReason#VERSION_CONFLICT} 同坐标出现不一致版本。</li>
 * </ul>
 */
@Component
public class ManifestJsonParser implements ManifestParser {

    public static final String TYPE = "manifest-json";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Fingerprints fingerprints;

    public ManifestJsonParser(Fingerprints fingerprints) {
        this.fingerprints = fingerprints;
    }

    @Override
    public boolean supports(String manifestType) {
        return TYPE.equalsIgnoreCase(manifestType);
    }

    @Override
    public ParseOutcome parse(String manifestType, String sourceName, String rawContent) {
        List<ParseIssue> issues = new ArrayList<>();
        List<NormalizedDependency> dependencies = new ArrayList<>();

        JsonNode root;
        try {
            root = objectMapper.readTree(rawContent == null ? "" : rawContent);
        } catch (JsonProcessingException e) {
            issues.add(new ParseIssue(FailureReason.FORMAT_MALFORMED,
                    "<root>", "manifest is not valid JSON: " + e.getOriginalMessage()));
            return new ParseOutcome(TYPE, sourceName, List.of(), issues);
        }
        if (root == null || !root.isObject()) {
            issues.add(new ParseIssue(FailureReason.FORMAT_MALFORMED,
                    "<root>", "manifest root must be a JSON object"));
            return new ParseOutcome(TYPE, sourceName, List.of(), issues);
        }
        JsonNode array = root.get("dependencies");
        if (array == null || !array.isArray()) {
            issues.add(new ParseIssue(FailureReason.FORMAT_MALFORMED,
                    "<root>", "missing or non-array 'dependencies' field"));
            return new ParseOutcome(TYPE, sourceName, List.of(), issues);
        }

        // 保持插入顺序，保证输出确定性
        Map<String, NormalizedDependency> accepted = new LinkedHashMap<>();
        Set<String> declaredCoordinates = new HashSet<>();

        int index = 0;
        for (JsonNode entryNode : array) {
            String entryKey = "dependencies[" + index + "]";
            index++;
            if (entryNode == null || !entryNode.isObject()) {
                issues.add(new ParseIssue(FailureReason.FORMAT_MALFORMED,
                        entryKey, "dependency entry must be a JSON object"));
                continue;
            }
            String group = textOrNull(entryNode, "group");
            String name = textOrNull(entryNode, "name");
            String version = textOrNull(entryNode, "version");
            String scopeText = textOrNull(entryNode, "scope");

            boolean entryValid = true;
            if (isBlank(group)) {
                issues.add(new ParseIssue(FailureReason.FIELD_MISSING,
                        entryKey, "field 'group' is required and must be non-empty"));
                entryValid = false;
            }
            if (isBlank(name)) {
                issues.add(new ParseIssue(FailureReason.FIELD_MISSING,
                        entryKey, "field 'name' is required and must be non-empty"));
                entryValid = false;
            }
            DependencyScope scope = parseScope(scopeText);
            String versionIssue = validateVersion(version);
            if (versionIssue != null) {
                issues.add(new ParseIssue(FailureReason.VERSION_INCOMPLETE,
                        entryKey, versionIssue));
                entryValid = false;
            }
            if (!entryValid) {
                continue;
            }

            String coordinate = group.trim() + ":" + name.trim();
            if (!declaredCoordinates.add(coordinate)) {
                NormalizedDependency existing = accepted.get(coordinate);
                if (existing != null && existing.version().equals(version.trim())) {
                    issues.add(new ParseIssue(FailureReason.DUPLICATE_ENTRY,
                            entryKey, "duplicate dependency entry for " + coordinate
                                    + ":" + version.trim()));
                } else {
                    issues.add(new ParseIssue(FailureReason.VERSION_CONFLICT,
                            entryKey, "conflicting versions for " + coordinate + ": "
                                    + (existing == null ? "?" : existing.version())
                                    + " vs " + version.trim()));
                }
                continue;
            }

            String cleanVersion = version.trim();
            String fingerprint = fingerprints.sha256(
                    TYPE + "|" + coordinate + "|" + cleanVersion + "|" + scope.name());
            NormalizedDependency dependency = new NormalizedDependency(
                    coordinate, cleanVersion, scope, fingerprint,
                    coordinate + ":" + cleanVersion, TYPE);
            accepted.put(coordinate, dependency);
        }

        dependencies.addAll(accepted.values());
        return new ParseOutcome(TYPE, sourceName, List.copyOf(dependencies), List.copyOf(issues));
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual()) {
            return null;
        }
        return value.asText();
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static DependencyScope parseScope(String scopeText) {
        if (isBlank(scopeText)) {
            return DependencyScope.UNKNOWN;
        }
        try {
            return DependencyScope.valueOf(scopeText.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return DependencyScope.UNKNOWN;
        }
    }

    /**
     * 版本必须以完整数字版本开头：MAJOR.MINOR.PATCH（至少三段数字）。
     * 拒绝动态版本与残缺版本。返回 null 表示合法；否则返回原因描述。
     */
    static String validateVersion(String version) {
        if (isBlank(version)) {
            return "field 'version' is required and must be non-empty";
        }
        String v = version.trim();
        String upper = v.toUpperCase();
        if ("LATEST".equals(upper) || "RELEASE".equals(upper)
                || upper.startsWith("LATEST.") || upper.startsWith("RELEASE.")) {
            return "dynamic version is not allowed in a locked manifest: " + v;
        }
        if (v.startsWith("+") || v.endsWith("+") || v.startsWith("[")) {
            return "version range is not a complete pinned version: " + v;
        }
        // 截取预发布/构建后缀前的核心版本
        String core = v.split("[-+]", 2)[0];
        String[] segments = core.split("\\.", -1);
        if (segments.length < 3) {
            return "version is incomplete, expected MAJOR.MINOR.PATCH: " + v;
        }
        for (int i = 0; i < 3; i++) {
            String segment = segments[i];
            if (segment.isEmpty() || !segment.chars().allMatch(Character::isDigit)) {
                return "version is incomplete or malformed, MAJOR.MINOR.PATCH must be numeric: " + v;
            }
        }
        return null;
    }
}
