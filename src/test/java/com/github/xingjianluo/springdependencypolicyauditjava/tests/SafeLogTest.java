package com.github.xingjianluo.springdependencypolicyauditjava.tests;

import com.github.xingjianluo.springdependencypolicyauditjava.util.SafeLog;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SafeLogTest {

    @Test
    void masksPasswordKeyValuePairs() {
        String out = SafeLog.redact("db password=hunter2 connect");
        assertTrue(out.contains("REDACTED"));
        assertFalse(out.contains("hunter2"));
    }

    @Test
    void masksJsonStyleSecrets() {
        String out = SafeLog.redact("{\"apiKey\":\"sk-abcdef-123456\",\"name\":\"ok\"}");
        assertTrue(out.contains("REDACTED"));
        assertFalse(out.contains("sk-abcdef-123456"));
        assertTrue(out.contains("ok"));
    }

    @Test
    void masksBearerTokens() {
        String out = SafeLog.redact("Authorization: Bearer eyJhbGciOi.JIUzI1Ni");
        assertTrue(out.contains("REDACTED"));
        assertFalse(out.contains("eyJhbGciOi"));
    }

    @Test
    void masksUrlCredentials() {
        String out = SafeLog.redact("connect https://admin:s3cr3t@registry.example/x");
        assertTrue(out.contains("REDACTED"));
        assertFalse(out.contains("s3cr3t"));
        assertTrue(out.contains("registry.example"));
    }

    @Test
    void leavesCoordinateAndFingerprintUntouched() {
        String safe = "com.example:lib:1.0.0 fingerprint=abcdef0123";
        assertEquals(safe, SafeLog.redact(safe));
    }

    @Test
    void nullAndEmptyPassThrough() {
        assertNull(SafeLog.redact(null));
        assertEquals("", SafeLog.redact(""));
    }
}
