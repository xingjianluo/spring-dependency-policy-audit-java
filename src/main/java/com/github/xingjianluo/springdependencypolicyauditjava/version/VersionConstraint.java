package com.github.xingjianluo.springdependencypolicyauditjava.version;

import java.util.ArrayList;
import java.util.List;

/**
 * 简单语义版本约束，仅依赖本地实现：
 * <ul>
 *   <li>{@code *} 或空：全部版本；</li>
 *   <li>精确版本 {@code 1.2.3}；</li>
 *   <li>前缀通配 {@code 1.2.*}、{@code 1.x}；</li>
 *   <li>比较运算 {@code >=1.0}、{@code >}、{@code <=}、{@code <}、{@code =}、{@code !=}；</li>
 *   <li>区间 {@code [1.0,2.0)}，[] 为包含、() 为排除；</li>
 *   <li>逗号分隔的多条件 AND：{@code >=1.0,<2.0}。</li>
 * </ul>
 * 快照后缀 {@code -SNAPSHOT} 被规范化为低于同号发行版。
 */
public final class VersionConstraint {

    private VersionConstraint() {
    }

    /** 判断版本是否满足约束表达式。 */
    public static boolean satisfies(String version, String expression) {
        if (version == null || version.isBlank()) {
            throw new IllegalArgumentException("version must not be empty");
        }
        if (expression == null || expression.isBlank() || "*".equals(expression.trim())) {
            return true;
        }
        int[] actual = parseVersion(version.trim());
        for (String clause : splitClauses(expression)) {
            if (!clause.isBlank() && !satisfiesClause(actual, clause)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 按顶层逗号切分 AND 条件，但不切分区间内部的逗号（如 {@code [1.0,2.0)}）。
     */
    private static List<String> splitClauses(String expression) {
        List<String> clauses = new ArrayList<>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i < expression.length(); i++) {
            char c = expression.charAt(i);
            if (c == '[' || c == '(') {
                depth++;
            } else if (c == ']' || c == ')') {
                depth = Math.max(0, depth - 1);
            } else if (c == ',' && depth == 0) {
                clauses.add(expression.substring(start, i).trim());
                start = i + 1;
            }
        }
        clauses.add(expression.substring(start).trim());
        return clauses;
    }

    private static boolean satisfiesClause(int[] actual, String clause) {
        // 区间：[1.0,2.0)
        if (clause.length() >= 2 && (clause.charAt(0) == '[' || clause.charAt(0) == '(')
                && (clause.endsWith("]") || clause.endsWith(")"))) {
            boolean includeLow = clause.charAt(0) == '[';
            boolean includeHigh = clause.endsWith("]");
            String inner = clause.substring(1, clause.length() - 1);
            int comma = inner.indexOf(',');
            if (comma < 0) {
                throw new IllegalArgumentException("invalid range: " + clause);
            }
            String low = inner.substring(0, comma).trim();
            String high = inner.substring(comma + 1).trim();
            int cmpLow = compare(actual, parseVersion(low));
            int cmpHigh = compare(actual, parseVersion(high));
            boolean lowOk = low.isEmpty() || (includeLow ? cmpLow >= 0 : cmpLow > 0);
            boolean highOk = high.isEmpty() || (includeHigh ? cmpHigh <= 0 : cmpHigh < 0);
            return lowOk && highOk;
        }
        // 前缀通配：1.2.* / 1.x / 1.2.x
        if (clause.endsWith(".*") || clause.toLowerCase().endsWith(".x")) {
            String prefix = clause.substring(0, clause.length() - 2);
            return prefixMatch(actual, parseVersion(prefix));
        }
        // 比较运算符
        for (String op : List.of(">=", "<=", "==", "!=", "=", ">", "<")) {
            if (clause.startsWith(op)) {
                int cmp = compare(actual, parseVersion(clause.substring(op.length()).trim()));
                return switch (op) {
                    case ">=" -> cmp >= 0;
                    case "<=" -> cmp <= 0;
                    case ">", "==", "=" -> op.equals(">") ? cmp > 0 : cmp == 0;
                    case "!=" -> cmp != 0;
                    default -> cmp < 0;
                };
            }
        }
        // 纯版本 => 精确相等
        return compare(actual, parseVersion(clause)) == 0;
    }

    private static boolean prefixMatch(int[] actual, int[] prefix) {
        if (actual.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (actual[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    /** 解析点分数字版本；非数字段非法。结果末位用 -1 表示 SNAPSHOT（低于正式版）。 */
    public static int[] parseVersion(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("version must not be empty");
        }
        String v = raw.trim();
        boolean snapshot = false;
        int dash = v.indexOf('-');
        if (dash >= 0) {
            String qualifier = v.substring(dash + 1);
            snapshot = qualifier.toLowerCase().startsWith("snapshot");
            v = v.substring(0, dash);
        }
        String[] parts = v.split("\\.");
        List<Integer> numbers = new ArrayList<>();
        for (String part : parts) {
            if (part.isBlank() || !part.chars().allMatch(Character::isDigit)) {
                throw new IllegalArgumentException("not a numeric version: " + raw);
            }
            numbers.add(Integer.parseInt(part));
        }
        if (snapshot) {
            numbers.add(-1);
        }
        return numbers.stream().mapToInt(Integer::intValue).toArray();
    }

    /** 比较两个数字版本数组，缺失位按 0 处理（但 -1 的 SNAPSHOT 位低于 0）。 */
    public static int compare(int[] a, int[] b) {
        int len = Math.max(a.length, b.length);
        for (int i = 0; i < len; i++) {
            int x = i < a.length ? a[i] : 0;
            int y = i < b.length ? b[i] : 0;
            if (x != y) {
                return Integer.compare(x, y);
            }
        }
        return 0;
    }
}
