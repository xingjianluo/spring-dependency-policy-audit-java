package com.github.xingjianluo.springdependencypolicyauditjava.tests;

import com.github.xingjianluo.springdependencypolicyauditjava.model.Dependency;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ManifestType;
import com.github.xingjianluo.springdependencypolicyauditjava.model.NormalizedManifest;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseFailureReason;
import com.github.xingjianluo.springdependencypolicyauditjava.parser.JsonManifestParser;
import com.github.xingjianluo.springdependencypolicyauditjava.parser.ManifestParseException;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class ManifestParserTest {

    private final JsonManifestParser parser = new JsonManifestParser();

    @Test
    void parsesValidManifestAndNormalizesOrder() {
        String json = """
                { "ecosystem": "maven",
                  "dependencies": [
                    {"group":"com.b","name":"z","version":"2.0.0","scope":"runtime"},
                    {"group":"com.a","name":"y","version":"1.0.0"}
                  ] }
                """;
        NormalizedManifest result = parser.parse(ManifestType.MANIFEST_JSON, json);
        assertEquals(2, result.dependencies().size());
        Dependency first = result.dependencies().get(0);
        assertEquals("com.a", first.group());
        assertEquals("compile", first.scope(), "缺失 scope 应归一为 compile");
        assertNotNull(result.contentFingerprint());
        assertEquals(64, result.contentFingerprint().length());
    }

    @Test
    void parsesLockFileWithLockedKey() {
        String json = """
                { "ecosystem": "npm",
                  "locked": [ {"name":"left-pad","version":"1.3.0","scope":"runtime"} ] }
                """;
        NormalizedManifest result = parser.parse(ManifestType.LOCK_JSON, json);
        assertEquals(1, result.dependencies().size());
        assertEquals("lock", result.dependencies().get(0).source());
    }

    @Test
    void malformedSyntaxReportedAsFormatError() {
        ManifestParseException ex = assertThrows(ManifestParseException.class,
                () -> parser.parse(ManifestType.MANIFEST_JSON, "{ not json"));
        assertEquals(1, ex.issues().size());
        assertEquals(ParseFailureReason.FORMAT_ERROR, ex.issues().get(0).reason());
    }

    @Test
    void nonArrayDependenciesReportedAsFormatError() {
        ManifestParseException ex = assertThrows(ManifestParseException.class,
                () -> parser.parse(ManifestType.MANIFEST_JSON,
                        "{\"ecosystem\":\"maven\",\"dependencies\":{}}"));
        assertEquals(Set.of(ParseFailureReason.FORMAT_ERROR), reasonSet(ex));
    }

    @Test
    void missingFieldReasonsAreDistinct() {
        String json = """
                { "ecosystem": "maven",
                  "dependencies": [
                    {"group":"com.x","version":"1.0.0"},
                    {"name":"no-group","version":"1.0.0"},
                    {"group":"com.y","name":"ok"}
                  ] }
                """;
        ManifestParseException ex = assertThrows(ManifestParseException.class,
                () -> parser.parse(ManifestType.MANIFEST_JSON, json));
        assertTrue(reasonSet(ex).contains(ParseFailureReason.MISSING_FIELD));
        assertTrue(reasonSet(ex).contains(ParseFailureReason.VERSION_INCOMPLETE));
        long missingName = ex.issues().stream()
                .filter(i -> i.reason() == ParseFailureReason.MISSING_FIELD
                        && i.location().endsWith(".name"))
                .count();
        assertEquals(1, missingName, "缺少 name 必须单独报告");
        long missingGroup = ex.issues().stream()
                .filter(i -> i.reason() == ParseFailureReason.MISSING_FIELD
                        && i.location().endsWith(".group"))
                .count();
        assertEquals(1, missingGroup, "maven 缺少 group 必须单独报告");
    }

    @Test
    void incompleteVersionsRejected() {
        for (String bad : List.of("LATEST", "RELEASE", "1.*", "${project.version}", "+", "")) {
            String json = "{\"ecosystem\":\"maven\",\"dependencies\":["
                    + "{\"group\":\"com.x\",\"name\":\"n\",\"version\":\"" + bad + "\"}]}";
            ManifestParseException ex = assertThrows(ManifestParseException.class,
                    () -> parser.parse(ManifestType.MANIFEST_JSON, json),
                    "版本 " + bad + " 应被拒绝");
            assertEquals(ParseFailureReason.VERSION_INCOMPLETE, ex.issues().get(0).reason(),
                    "版本 " + bad + " 的失败原因必须是 VERSION_INCOMPLETE");
        }
    }

    @Test
    void duplicateEntriesReported() {
        String json = """
                { "ecosystem": "maven",
                  "dependencies": [
                    {"group":"com.x","name":"dup","version":"1.0.0","scope":"compile"},
                    {"group":"com.x","name":"dup","version":"1.0.0","scope":"compile"}
                  ] }
                """;
        ManifestParseException ex = assertThrows(ManifestParseException.class,
                () -> parser.parse(ManifestType.MANIFEST_JSON, json));
        assertEquals(Set.of(ParseFailureReason.DUPLICATE_ENTRY), reasonSet(ex));
        assertTrue(ex.issues().get(0).detail().contains("dup"));
    }

    @Test
    void sameCoordinateDifferentScopeIsNotDuplicate() {
        String json = """
                { "ecosystem": "maven",
                  "dependencies": [
                    {"group":"com.x","name":"dup","version":"1.0.0","scope":"compile"},
                    {"group":"com.x","name":"dup","version":"1.0.0","scope":"test"}
                  ] }
                """;
        NormalizedManifest result = parser.parse(ManifestType.MANIFEST_JSON, json);
        assertEquals(2, result.dependencies().size());
    }

    @Test
    void unsupportedEcosystemReported() {
        String json = """
                { "ecosystem": "conan",
                  "dependencies": [ {"name":"x","version":"1.0"} ] }
                """;
        ManifestParseException ex = assertThrows(ManifestParseException.class,
                () -> parser.parse(ManifestType.MANIFEST_JSON, json));
        assertEquals(Set.of(ParseFailureReason.UNSUPPORTED_ECOSYSTEM), reasonSet(ex));
    }

    @Test
    void missingDependenciesArrayReportedAsMissingField() {
        ManifestParseException ex = assertThrows(ManifestParseException.class,
                () -> parser.parse(ManifestType.MANIFEST_JSON, "{\"ecosystem\":\"maven\"}"));
        assertEquals(ParseFailureReason.MISSING_FIELD, ex.issues().get(0).reason());
    }

    private static Set<ParseFailureReason> reasonSet(ManifestParseException ex) {
        return ex.issues().stream().map(i -> i.reason()).collect(Collectors.toSet());
    }
}
