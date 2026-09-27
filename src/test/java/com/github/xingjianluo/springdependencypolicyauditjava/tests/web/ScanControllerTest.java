package com.github.xingjianluo.springdependencypolicyauditjava.tests.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端 HTTP 判定：通过 200、阻断 403、坏请求 400、不支持类型 415、
 * 重复提交幂等标记。不依赖外部服务。
 */
@SpringBootTest(properties = "depaudit.audit.file=./target/test-controller-audit-${random.uuid}.log")
@AutoConfigureMockMvc
class ScanControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void clean_manifest_returns_200_and_pass() throws Exception {
        String body = """
                { "manifestType":"manifest-json", "sourceName":"m.json", "operator":"alice",
                  "rawContent":"{\\"dependencies\\":[\
                    {\\"group\\":\\"org.example\\",\\"name\\":\\"safe-lib\\",\\"version\\":\\"1.0.0\\",\\"scope\\":\\"COMPILE\\"}\
                  ]}" }
                """;
        mockMvc.perform(post("/api/dependency-scans")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.blocked").value(false))
                .andExpect(jsonPath("$.policyVersion").value("default-policy-2026.09.28"))
                .andExpect(jsonPath("$.decisions[0].verdict").value("PASS"));
    }

    @Test
    void denied_manifest_returns_403_with_reason() throws Exception {
        String raw = "{\"dependencies\":[{"
                + "\"group\":\"com.knownbad\",\"name\":\"malware-lib\","
                + "\"version\":\"9.9.9\",\"scope\":\"COMPILE\"}]}";
        String body = "{\"manifestType\":\"manifest-json\",\"rawContent\":\""
                + raw.replace("\"", "\\\"") + "\"}";
        mockMvc.perform(post("/api/dependency-scans")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.blocked").value(true))
                .andExpect(jsonPath("$.decisions[0].failureReason").value("DENIED_BY_RULE"));
    }

    @Test
    void duplicate_submission_is_flagged_but_verdict_stable() throws Exception {
        String raw = "{\"dependencies\":[{"
                + "\"group\":\"org.example\",\"name\":\"safe-lib\","
                + "\"version\":\"1.0.0\",\"scope\":\"COMPILE\"}]}";
        String body = "{\"manifestType\":\"manifest-json\",\"operator\":\"alice\","
                + "\"rawContent\":\"" + raw.replace("\"", "\\\"") + "\"}";
        mockMvc.perform(post("/api/dependency-scans")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.duplicateSubmission").value(false));
        mockMvc.perform(post("/api/dependency-scans")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.duplicateSubmission").value(true))
                .andExpect(jsonPath("$.blocked").value(false));
    }

    @Test
    void missing_manifest_type_is_bad_request() throws Exception {
        mockMvc.perform(post("/api/dependency-scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rawContent\":\"{}\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("BAD_REQUEST"));
    }

    @Test
    void unsupported_manifest_type_is_rejected() throws Exception {
        mockMvc.perform(post("/api/dependency-scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"manifestType\":\"pom-xml\",\"rawContent\":\"<x/>\"}"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.errorCode").value("UNSUPPORTED_FORMAT"));
    }

    @Test
    void remote_paths_are_refused() throws Exception {
        mockMvc.perform(post("/api/dependency-scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"manifestType\":\"manifest-json\","
                                + "\"manifestPath\":\"http://evil.example/m.json\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("BAD_REQUEST"));
    }
}
