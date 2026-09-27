package com.github.xingjianluo.springdependencypolicyauditjava.manifest;

import com.github.xingjianluo.springdependencypolicyauditjava.model.DependencyScope;
import com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason;
import com.github.xingjianluo.springdependencypolicyauditjava.model.NormalizedDependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseIssue;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseOutcome;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.Fingerprints;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 行式锁定文件解析器。
 *
 * <p>期望格式（每行一条，{@code #} 开头为注释，空行忽略）：</p>
 * <pre>
 * # lock-file v1
 * group:name:version:scope
 * org.example:lib:1.2.3:COMPILE
 * </pre>
 *
 * <p>列数错误 → {@link FailureReason#FORMAT_MALFORMED}；
 * 字段空白 → {@link FailureReason#FIELD_MISSING}；
 * 版本残缺/动态 → {@link FailureReason#VERSION_INCOMPLETE}；
 * 坐标重复版本一致 → {@link FailureReason#DUPLICATE_ENTRY}；
 * 坐标重复版本不一致 → {@link FailureReason#VERSION_CONFLICT}。</p>
 */
@Component
public class LockFileParser implements ManifestParser {

    public static final String TYPE = "lock-file";

    private final Fingerprints fingerprints;

    public LockFileParser(Fingerprints fingerprints) {
        this.fingerprints = fingerprints;
    }

    @Override
    public boolean supports(String manifestType) {
        return TYPE.equalsIgnoreCase(manifestType);
    }

    @Override
    public ParseOutcome parse(String manifestType, String sourceName, String rawContent) {
        List<ParseIssue> issues = new ArrayList<>();
        Map<String, NormalizedDependency> accepted = new LinkedHashMap<>();

        if (rawContent == null || rawContent.isBlank()) {
            issues.add(new ParseIssue(FailureReason.FORMAT_MALFORMED,
                    "<root>", "lock file is empty"));
            return new ParseOutcome(TYPE, sourceName, List.of(), issues);
        }

        String[] lines = rawContent.split("\\R", -1);
        int lineNo = 0;
        for (String rawLine : lines) {
            lineNo++;
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String entryKey = "line " + lineNo;
            String[] parts = line.split(":", -1);
            if (parts.length != 4) {
                issues.add(new ParseIssue(FailureReason.FORMAT_MALFORMED,
                        entryKey, "expected exactly 4 colon-separated fields "
                                + "'group:name:version:scope' but got " + parts.length
                                + ": " + line));
                continue;
            }
            String group = parts[0].trim();
            String name = parts[1].trim();
            String version = parts[2].trim();
            String scopeText = parts[3].trim();

            boolean entryValid = true;
            if (group.isEmpty()) {
                issues.add(new ParseIssue(FailureReason.FIELD_MISSING,
                        entryKey, "field 'group' is empty"));
                entryValid = false;
            }
            if (name.isEmpty()) {
                issues.add(new ParseIssue(FailureReason.FIELD_MISSING,
                        entryKey, "field 'name' is empty"));
                entryValid = false;
            }
            String versionIssue = ManifestJsonParser.validateVersion(version);
            if (versionIssue != null) {
                issues.add(new ParseIssue(FailureReason.VERSION_INCOMPLETE,
                        entryKey, versionIssue));
                entryValid = false;
            }
            DependencyScope scope;
            try {
                scope = scopeText.isEmpty()
                        ? DependencyScope.UNKNOWN
                        : DependencyScope.valueOf(scopeText.toUpperCase());
            } catch (IllegalArgumentException e) {
                issues.add(new ParseIssue(FailureReason.FORMAT_MALFORMED,
                        entryKey, "unknown scope '" + scopeText
                                + "', expected one of COMPILE/RUNTIME/TEST/PROVIDED"));
                continue;
            }
            if (!entryValid) {
                continue;
            }

            String coordinate = group + ":" + name;
            NormalizedDependency existing = accepted.get(coordinate);
            if (existing != null) {
                if (existing.version().equals(version)) {
                    issues.add(new ParseIssue(FailureReason.DUPLICATE_ENTRY,
                            entryKey, "duplicate locked entry for " + coordinate + ":" + version));
                } else {
                    issues.add(new ParseIssue(FailureReason.VERSION_CONFLICT,
                            entryKey, "conflicting locked versions for " + coordinate
                                    + ": " + existing.version() + " vs " + version));
                }
                continue;
            }

            String fingerprint = fingerprints.sha256(
                    TYPE + "|" + coordinate + "|" + version + "|" + scope.name());
            accepted.put(coordinate, new NormalizedDependency(
                    coordinate, version, scope, fingerprint,
                    coordinate + ":" + version, TYPE));
        }

        if (accepted.isEmpty() && issues.isEmpty()) {
            issues.add(new ParseIssue(FailureReason.FORMAT_MALFORMED,
                    "<root>", "lock file contains no dependency entries"));
        }
        return new ParseOutcome(TYPE, sourceName,
                List.copyOf(accepted.values()), List.copyOf(issues));
    }
}
