package com.github.xingjianluo.springdependencypolicyauditjava.decision;

/**
 * 确定的判定结果。
 * PASS：通过；WARN：有条件放行（须审计）；DENY：阻断；OUT_OF_SCOPE：不在生效范围内（放行且不审计为风险）。
 */
public enum Decision {
    PASS,
    WARN,
    DENY,
    OUT_OF_SCOPE
}
