package com.github.xingjianluo.springdependencypolicyauditjava.parser;

import com.github.xingjianluo.springdependencypolicyauditjava.model.Dependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.Ecosystem;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ManifestType;
import com.github.xingjianluo.springdependencypolicyauditjava.model.NormalizedManifest;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseFailureReason;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseIssue;
import com.github.xingjianluo.springdependencypolicyauditjava.util.Fingerprints;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 基于 {@link Json} 的本地清单解析器。
 *
 * <p>两种格式共用同一归一结构：
 * <pre>
 * { "ecosystem": "maven",
 *   "dependencies": [ {"group":"...","name":"...","version":"...","scope":"compile"} ] }
 * </pre>
 *
 * <p>以下异常都不会被静默跳过，而是收集为彼此可区分的 {@link ParseIssue}：
 * 格式异常、字段缺失、版本不完整、重复条目、不支持的生态。
 */
@Component
public class JsonManifestParser implements ManifestParser {

    /** 锁文件允许顶层使用 "locked" / "packages" 作为依赖数组键。 */
    private static final List<String> LOCK_ARRAY_KEYS = List.of("locked", "packages", "dependencies");
    /** 清单文件允许的依赖数组键。 */
    private static final List<String> MANIFEST_ARRAY_KEYS = List.of("dependencies", "packages");

    @Override
    public NormalizedManifest parse(ManifestType type, String contents) {
        if (type == null) {
            throw new ManifestParseException(List.of(new ParseIssue(
                    ParseFailureReason.FORMAT_ERROR, "$", "未指定清单类型")));
        }
        List<ParseIssue> issues = new ArrayList<>();
        Object root;
        try {
            root = Json.parse(contents);
        } catch (Json.JsonParseException e) {
            throw new ManifestParseException(List.of(new ParseIssue(
                    ParseFailureReason.FORMAT_ERROR,
                    "行 " + e.line() + " 列 " + e.column(),
                    e.getMessage())));
        }
        if (!(root instanceof Map)) {
            throw new ManifestParseException(List.of(new ParseIssue(
                    ParseFailureReason.FORMAT_ERROR, "$",
                    "根节点必须是 JSON 对象，实际为 " + (root instanceof List ? "数组" : "标量"))));
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> rootMap = (Map<String, Object>) root;

        String ecosystemRaw = stringOrNull(rootMap.get("ecosystem"));
        Ecosystem ecosystem = ecosystemRaw == null
                ? null
                : Ecosystem.fromString(ecosystemRaw);
        if (ecosystemRaw == null || ecosystemRaw.isBlank()) {
            issues.add(new ParseIssue(ParseFailureReason.MISSING_FIELD,
                    "$.ecosystem", "缺少必填字段 ecosystem"));
        } else if (ecosystem == null) {
            issues.add(new ParseIssue(ParseFailureReason.UNSUPPORTED_ECOSYSTEM,
                    "$.ecosystem", "不支持的生态系统: " + ecosystemRaw));
        }

        List<String> arrayKeys = type == ManifestType.LOCK_JSON ? LOCK_ARRAY_KEYS : MANIFEST_ARRAY_KEYS;
        Object arrayNode = null;
        String arrayPath = null;
        for (String key : arrayKeys) {
            if (rootMap.containsKey(key)) {
                arrayNode = rootMap.get(key);
                arrayPath = "$." + key;
                break;
            }
        }
        if (arrayNode == null) {
            issues.add(new ParseIssue(ParseFailureReason.MISSING_FIELD,
                    arrayKeys.get(0), "缺少依赖数组字段（可选键: " + arrayKeys + "）"));
            throw new ManifestParseException(issues);
        }
        if (!(arrayNode instanceof List)) {
            issues.add(new ParseIssue(ParseFailureReason.FORMAT_ERROR,
                    arrayPath, "依赖列表必须是 JSON 数组"));
            throw new ManifestParseException(issues);
        }

        List<?> rawDeps = (List<?>) arrayNode;
        List<Dependency> dependencies = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < rawDeps.size(); i++) {
            String itemPath = arrayPath + "[" + i + "]";
            Object item = rawDeps.get(i);
            if (!(item instanceof Map)) {
                issues.add(new ParseIssue(ParseFailureReason.FORMAT_ERROR,
                        itemPath, "依赖条目必须是 JSON 对象"));
                continue;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> depMap = (Map<String, Object>) item;

            String group = stringOrNull(depMap.get("group"));
            String name = stringOrNull(depMap.get("name"));
            String version = stringOrNull(depMap.get("version"));
            String scope = stringOrNull(depMap.get("scope"));
            String itemEcoRaw = stringOrNull(depMap.get("ecosystem"));

            Ecosystem itemEco = ecosystem;
            if (itemEcoRaw != null && !itemEcoRaw.isBlank()) {
                itemEco = Ecosystem.fromString(itemEcoRaw);
                if (itemEco == null) {
                    issues.add(new ParseIssue(ParseFailureReason.UNSUPPORTED_ECOSYSTEM,
                            itemPath + ".ecosystem", "不支持的生态系统: " + itemEcoRaw));
                    continue;
                }
            }
            if (itemEco == null) {
                continue; // 顶层 ecosystem 缺失已记录，避免重复噪声
            }
            boolean missing = false;
            if (name == null || name.isBlank()) {
                issues.add(new ParseIssue(ParseFailureReason.MISSING_FIELD,
                        itemPath + ".name", "依赖条目缺少必填字段 name"));
                missing = true;
            }
            if (itemEco == Ecosystem.MAVEN && (group == null || group.isBlank())) {
                issues.add(new ParseIssue(ParseFailureReason.MISSING_FIELD,
                        itemPath + ".group", "maven 依赖缺少必填字段 group"));
                missing = true;
            }
            if (version == null || version.isBlank()) {
                issues.add(new ParseIssue(ParseFailureReason.VERSION_INCOMPLETE,
                        itemPath + ".version", "依赖条目缺少版本号"));
                missing = true;
            } else if (!isCompleteVersion(version)) {
                issues.add(new ParseIssue(ParseFailureReason.VERSION_INCOMPLETE,
                        itemPath + ".version", "版本号不完整或含非法占位符: " + version));
                missing = true;
            }
            if (missing) {
                continue;
            }
            String normalizedGroup = group == null ? "" : group.trim();
            String normalizedName = name.trim();
            String normalizedVersion = version.trim();
            String normalizedScope = scope == null || scope.isBlank() ? "compile" : scope.trim();
            String dedupeKey = itemEco + "|" + normalizedGroup + "|" + normalizedName
                    + "|" + normalizedVersion + "|" + normalizedScope;
            if (!seen.add(dedupeKey)) {
                issues.add(new ParseIssue(ParseFailureReason.DUPLICATE_ENTRY,
                        itemPath,
                        "重复依赖条目: " + normalizedGroup + ":" + normalizedName
                                + ":" + normalizedVersion + " (" + normalizedScope + ")"));
                continue;
            }
            dependencies.add(new Dependency(itemEco, normalizedGroup, normalizedName,
                    normalizedVersion, normalizedScope,
                    type == ManifestType.LOCK_JSON ? "lock" : "manifest"));
        }

        if (!issues.isEmpty()) {
            throw new ManifestParseException(issues);
        }
        dependencies.sort(Comparator
                .comparing((Dependency d) -> d.ecosystem().name())
                .thenComparing(Dependency::group)
                .thenComparing(Dependency::name)
                .thenComparing(Dependency::version)
                .thenComparing(Dependency::scope));
        String fingerprint = Fingerprints.sha256(contents.trim());
        return new NormalizedManifest(fingerprint, List.copyOf(dependencies));
    }

    /** 版本完整性：必须至少含一个数字段，且不含 LATEST/RELEASE/星号/空括号等动态占位。 */
    static boolean isCompleteVersion(String version) {
        String v = version.trim();
        String lower = v.toLowerCase();
        if (lower.equals("latest") || lower.equals("release") || lower.contains("${")
                || v.contains("*") || v.equals("+")) {
            return false;
        }
        // 去掉快照/限定符后，主体必须是点分数字，如 1.2.3、1.2.3-rc1
        String core = v;
        int dash = core.indexOf('-');
        if (dash >= 0) {
            core = core.substring(0, dash);
        }
        if (core.isBlank()) {
            return false;
        }
        for (String part : core.split("\\.")) {
            if (part.isBlank() || !part.chars().allMatch(Character::isDigit)) {
                return false;
            }
        }
        return true;
    }

    private static String stringOrNull(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String s) {
            return s;
        }
        return value.toString();
    }
}
