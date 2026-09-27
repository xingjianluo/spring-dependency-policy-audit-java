package com.github.xingjianluo.springdependencypolicyauditjava.manifest;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 仅从本地文件读取清单内容。不访问任何网络、不解析 URL。
 */
@Component
public class LocalManifestReader {

    /**
     * 读取本地文件的 UTF-8 文本。
     *
     * @throws ManifestParseException IO_ERROR 文件不存在或不可读
     */
    public String read(Path path) {
        if (path == null) {
            throw new ManifestParseException(
                    com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason.IO_ERROR,
                    "manifest path must not be null");
        }
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            throw new ManifestParseException(
                    com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason.IO_ERROR,
                    "manifest file not found or is not a regular file: " + path);
        }
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ManifestParseException(
                    com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason.IO_ERROR,
                    "failed to read manifest file: " + path, e);
        }
    }
}
