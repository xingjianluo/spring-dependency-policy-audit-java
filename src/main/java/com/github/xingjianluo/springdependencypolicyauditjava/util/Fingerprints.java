package com.github.xingjianluo.springdependencypolicyauditjava.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256 指纹工具（仅使用本地 JDK 能力）。 */
public final class Fingerprints {

    private Fingerprints() {
    }

    /**
     * 对任意文本计算 SHA-256，返回小写十六进制。
     *
     * @throws IllegalArgumentException text 为 null 时
     */
    public static String sha256(String text) {
        if (text == null) {
            throw new IllegalArgumentException("fingerprint input must not be null");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable in this JDK", e);
        }
    }
}
