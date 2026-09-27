package com.github.xingjianluo.springdependencypolicyauditjava.policy;

import com.github.xingjianluo.springdependencypolicyauditjava.model.PolicySet;

/**
 * 提供当前生效的策略集合。
 */
public interface PolicyProvider {

    PolicySet current();
}
