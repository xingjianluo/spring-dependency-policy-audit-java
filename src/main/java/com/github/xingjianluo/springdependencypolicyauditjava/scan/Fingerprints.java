package com.github.xingjianluo.springdependencypolicyauditjava.scan;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-256 指纹工具：依赖指纹、请求指纹。
 * 指纹是可追溯但不含原始敏感内容的稳定标识。
 */
@Component
public class Fingerprints {

    /**
     * 计算输入字符串的 SHA-256，输出 64 位小写十六进制。
     */
    public String sha256(String input) {
        if (input == null) {
            throw new IllegalArgumentException("fingerprint input must not be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 是 JLS 强制存在的算法
            throw new IllegalStateException("SHA-256 MessageDigest unavailable", e);
        }
    }
}
