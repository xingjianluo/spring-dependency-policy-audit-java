package com.github.xingjianluo.springdependencypolicyauditjava.policy;

/** 从本地文件/类路径加载不可变策略集合。 */
public interface PolicyLoader {
    PolicySet load();
}
