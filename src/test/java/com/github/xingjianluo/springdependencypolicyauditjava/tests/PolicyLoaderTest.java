package com.github.xingjianluo.springdependencypolicyauditjava.tests;

import com.github.xingjianluo.springdependencypolicyauditjava.policy.JsonPolicyLoader;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicyLoadException;
import com.github.xingjianluo.springdependencypolicyauditjava.policy.PolicySet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PolicyLoaderTest {

    private static final String VALID_POLICY = """
            { "policyVersion": "test-1",
              "maxSeverity": "MODERATE",
              "enforcedScopes": ["compile"],
              "rules": [
                {"id":"D1","action":"deny","ecosystem":"maven",
                 "groupPattern":"com.bad","namePattern":"x","versionRange":"<2.0",
                 "scopes":["compile"],"reason":"blocked"}
              ],
              "advisories": [
                {"id":"A1","ecosystem":"npm","group":"","name":"p","versionRange":"*",
                 "severity":"HIGH","reason":"r"}
              ],
              "exceptions": [
                {"id":"E1","ecosystem":"npm","group":"","name":"p","versionRange":"*",
                 "scopes":["compile"],"expiresOn":"2030-12-31",
                 "requestedBy":"alice","justification":"need it"}
              ] }
            """;

    @Test
    void loadsClasspathDefaultPolicy() {
        PolicySet set = new JsonPolicyLoader("").load();
        assertNotNull(set.policyVersion());
        assertFalse(set.rules().isEmpty());
        assertFalse(set.advisories().isEmpty());
    }

    @Test
    void loadsPolicyFromLocalFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("policy.json");
        Files.writeString(file, VALID_POLICY);
        PolicySet set = new JsonPolicyLoader(file.toString()).load();
        assertEquals("test-1", set.policyVersion());
        assertEquals(1, set.rules().size());
        assertEquals(1, set.advisories().size());
        assertEquals(1, set.exceptions().size());
        assertEquals("2030-12-31", set.exceptions().get(0).expiresOn().toString());
    }

    @Test
    void missingFileFailsFast() {
        PolicyLoadException ex = assertThrows(PolicyLoadException.class,
                () -> new JsonPolicyLoader("/nonexistent/policy-xyz.json").load());
        assertTrue(ex.getMessage().contains("不存在"));
    }

    @Test
    void invalidActionFailsFast(@TempDir Path dir) throws Exception {
        String bad = VALID_POLICY.replace("\"deny\"", "\"wat\"");
        Path file = dir.resolve("bad.json");
        Files.writeString(file, bad);
        assertThrows(PolicyLoadException.class,
                () -> new JsonPolicyLoader(file.toString()).load());
    }

    @Test
    void invalidDateFailsFast(@TempDir Path dir) throws Exception {
        String bad = VALID_POLICY.replace("2030-12-31", "31/12/2030");
        Path file = dir.resolve("bad-date.json");
        Files.writeString(file, bad);
        assertThrows(PolicyLoadException.class,
                () -> new JsonPolicyLoader(file.toString()).load());
    }

    @Test
    void malformedJsonFailsFast(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("broken.json");
        Files.writeString(file, "{ broken");
        assertThrows(PolicyLoadException.class,
                () -> new JsonPolicyLoader(file.toString()).load());
    }
}
