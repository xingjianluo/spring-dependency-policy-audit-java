package com.github.xingjianluo.springdependencypolicyauditjava.parser;

import com.github.xingjianluo.springdependencypolicyauditjava.model.ManifestType;
import com.github.xingjianluo.springdependencypolicyauditjava.model.NormalizedManifest;

/**
 * 本地依赖清单解析器：读取清单或锁定信息并归一为统一结果。
 */
public interface ManifestParser {

    /**
     * @param type     清单格式
     * @param contents 本地文件原始内容
     * @return 归一结果；任何格式异常/字段缺失/版本不完整/重复条目都以
     *         {@link ManifestParseException} 显式失败
     */
    NormalizedManifest parse(ManifestType type, String contents);
}
