package com.github.xingjianluo.springdependencypolicyauditjava.model;

/**
 * 彼此可区分的失败/阻断原因。
 */
public enum FailureReason {
    FORMAT_MALFORMED,
    UNSUPPORTED_FORMAT,
    FIELD_MISSING,
    VERSION_INCOMPLETE,
    DUPLICATE_ENTRY,
    VERSION_CONFLICT,
    SCOPE_MISMATCH,
    EXCEPTION_EXPIRED,
    POLICY_CONFLICT,
    SEVERITY_THRESHOLD_EXCEEDED,
    DENIED_BY_RULE,
    NO_APPLICABLE_POLICY,
    IO_ERROR
}
