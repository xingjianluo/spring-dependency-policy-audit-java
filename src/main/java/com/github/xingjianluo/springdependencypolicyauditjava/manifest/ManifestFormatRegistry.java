package com.github.xingjianluo.springdependencypolicyauditjava.manifest;

import com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseIssue;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseOutcome;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 汇总全部本地支持的格式解析器，按 manifestType 分发。
 * 不支持的类型给出明确的 {@link FailureReason#UNSUPPORTED_FORMAT}，不静默跳过。
 */
@Component
public class ManifestFormatRegistry {

    private final List<ManifestParser> parsers;

    public ManifestFormatRegistry(List<ManifestParser> parsers) {
        this.parsers = parsers;
    }

    /**
     * 按类型选择解析器并解析。
     *
     * @throws ManifestParseException UNSUPPORTED_FORMAT 类型为空或无解析器支持
     */
    public ParseOutcome parse(String manifestType, String sourceName, String rawContent) {
        if (manifestType == null || manifestType.isBlank()) {
            throw new ManifestParseException(FailureReason.UNSUPPORTED_FORMAT,
                    "manifestType is required");
        }
        for (ManifestParser parser : parsers) {
            if (parser.supports(manifestType)) {
                return parser.parse(manifestType, sourceName, rawContent);
            }
        }
        throw new ManifestParseException(FailureReason.UNSUPPORTED_FORMAT,
                "unsupported manifest type: " + manifestType);
    }

    /**
     * 构造一个仅包含不支持格式问题的结果（供上层统一返回结构使用）。
     */
    public static ParseOutcome unsupported(String manifestType, String sourceName) {
        return new ParseOutcome(manifestType, sourceName, List.of(),
                List.of(new ParseIssue(FailureReason.UNSUPPORTED_FORMAT,
                        "<root>", "unsupported manifest type: " + manifestType)));
    }
}
