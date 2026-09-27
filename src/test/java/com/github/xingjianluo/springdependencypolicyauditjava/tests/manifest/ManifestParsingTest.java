package com.github.xingjianluo.springdependencypolicyauditjava.tests.manifest;

import com.github.xingjianluo.springdependencypolicyauditjava.manifest.LockFileParser;
import com.github.xingjianluo.springdependencypolicyauditjava.manifest.ManifestJsonParser;
import com.github.xingjianluo.springdependencypolicyauditjava.model.FailureReason;
import com.github.xingjianluo.springdependencypolicyauditjava.model.ParseOutcome;
import com.github.xingjianluo.springdependencypolicyauditjava.scan.Fingerprints;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 覆盖：畸形 JSON、字段缺失、版本不完整、重复条目、版本冲突，
 * 以及 lock-file 格式的同类问题。每种失败原因必须彼此可区分。
 */
class ManifestParsingTest {

    private final ManifestJsonParser jsonParser = new ManifestJsonParser(new Fingerprints());
    private final LockFileParser lockParser = new LockFileParser(new Fingerprints());

    @Test
    void malformed_json_is_reported_as_format_malformed() {
        ParseOutcome outcome = jsonParser.parse("manifest-json", "t", "{ not json");
        assertThat(outcome.dependencies()).isEmpty();
        assertThat(outcome.issues()).hasSize(1);
        assertThat(outcome.issues().get(0).reason()).isEqualTo(FailureReason.FORMAT_MALFORMED);
    }

    @Test
    void root_must_be_object_with_dependencies_array() {
        assertThat(jsonParser.parse("manifest-json", "t", "[1,2,3]").issues())
                .singleElement()
                .extracting(i -> i.reason())
                .isEqualTo(FailureReason.FORMAT_MALFORMED);
        assertThat(jsonParser.parse("manifest-json", "t", "{}").issues())
                .singleElement()
                .extracting(i -> i.reason())
                .isEqualTo(FailureReason.FORMAT_MALFORMED);
    }

    @Test
    void missing_group_and_name_are_field_missing() {
        String content = """
                { "dependencies": [
                  {"version":"1.2.3","scope":"COMPILE"},
                  {"group":"org.example","version":"1.2.3"}
                ]}
                """;
        ParseOutcome outcome = jsonParser.parse("manifest-json", "t", content);
        assertThat(outcome.issues())
                .hasSize(3)
                .extracting(i -> i.reason())
                .containsOnly(FailureReason.FIELD_MISSING);
        assertThat(outcome.dependencies()).isEmpty();
    }

    @Test
    void incomplete_and_dynamic_versions_are_distinguishable() {
        String content = """
                { "dependencies": [
                  {"group":"a","name":"b","scope":"COMPILE"},
                  {"group":"a","name":"c","version":"1.2","scope":"COMPILE"},
                  {"group":"a","name":"d","version":"LATEST","scope":"COMPILE"},
                  {"group":"a","name":"e","version":"RELEASE","scope":"COMPILE"},
                  {"group":"a","name":"f","version":"[1.0,2.0)","scope":"COMPILE"}
                ]}
                """;
        ParseOutcome outcome = jsonParser.parse("manifest-json", "t", content);
        assertThat(outcome.issues())
                .hasSize(5)
                .allSatisfy(i -> assertThat(i.reason()).isEqualTo(FailureReason.VERSION_INCOMPLETE));
    }

    @Test
    void valid_entries_are_normalized_with_fingerprint_and_default_scope() {
        String content = """
                { "dependencies": [
                  {"group":"org.example","name":"lib","version":"1.2.3","scope":"COMPILE"},
                  {"group":"org.example","name":"other","version":"2.0.0"}
                ]}
                """;
        ParseOutcome outcome = jsonParser.parse("manifest-json", "t", content);
        assertThat(outcome.issues()).isEmpty();
        assertThat(outcome.dependencies()).hasSize(2);
        assertThat(outcome.dependencies().get(0).name()).isEqualTo("org.example:lib");
        assertThat(outcome.dependencies().get(0).fingerprint()).hasSize(64);
        assertThat(outcome.dependencies().get(1).scope().name()).isEqualTo("UNKNOWN");
    }

    @Test
    void duplicate_entry_same_version_is_distinct_from_version_conflict() {
        String content = """
                { "dependencies": [
                  {"group":"org.example","name":"lib","version":"1.2.3","scope":"COMPILE"},
                  {"group":"org.example","name":"lib","version":"1.2.3","scope":"TEST"},
                  {"group":"org.example","name":"lib","version":"1.9.0","scope":"COMPILE"}
                ]}
                """;
        ParseOutcome outcome = jsonParser.parse("manifest-json", "t", content);
        assertThat(outcome.issues()).hasSize(2);
        assertThat(outcome.issues().get(0).reason()).isEqualTo(FailureReason.DUPLICATE_ENTRY);
        assertThat(outcome.issues().get(1).reason()).isEqualTo(FailureReason.VERSION_CONFLICT);
        assertThat(outcome.dependencies()).hasSize(1);
    }

    @Test
    void lock_file_parses_and_distinguishes_all_failure_reasons() {
        String content = """
                # header comment
                org.example:good:1.0.0:COMPILE

                broken-line
                :missing-group:1.0.0:TEST
                org.example:nov:1.0:COMPILE
                org.example:good:1.0.0:RUNTIME
                org.example:good:2.0.0:TEST
                org.example:badscope:1.0.0:NOPE
                """;
        ParseOutcome outcome = lockParser.parse("lock-file", "lock.txt", content);
        assertThat(outcome.dependencies()).hasSize(1);
        assertThat(outcome.issues())
                .extracting(i -> i.reason())
                .containsExactly(
                        FailureReason.FORMAT_MALFORMED,
                        FailureReason.FIELD_MISSING,
                        FailureReason.VERSION_INCOMPLETE,
                        FailureReason.DUPLICATE_ENTRY,
                        FailureReason.VERSION_CONFLICT,
                        FailureReason.FORMAT_MALFORMED);
    }

    @Test
    void empty_lock_file_is_malformed_not_silently_passed() {
        ParseOutcome outcome = lockParser.parse("lock-file", "empty.lock", "   \n# only comment\n");
        assertThat(outcome.issues())
                .singleElement()
                .extracting(i -> i.reason())
                .isEqualTo(FailureReason.FORMAT_MALFORMED);
    }

    @Test
    void nothing_is_silently_skipped_issue_count_matches_bad_rows() {
        String content = """
                { "dependencies": [
                  {"group":"org.example","name":"ok","version":"1.0.0","scope":"COMPILE"},
                  {"group":"org.example","name":"noversion","scope":"COMPILE"},
                  "not-an-object"
                ]}
                """;
        ParseOutcome outcome = jsonParser.parse("manifest-json", "t", content);
        assertThat(outcome.dependencies()).hasSize(1);
        assertThat(outcome.issues()).hasSize(2);
        assertThat(outcome.issues())
                .extracting(i -> i.reason())
                .containsExactlyInAnyOrder(
                        FailureReason.VERSION_INCOMPLETE,
                        FailureReason.FORMAT_MALFORMED);
    }
}
