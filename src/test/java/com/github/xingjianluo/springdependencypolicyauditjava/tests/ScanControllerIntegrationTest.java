package com.github.xingjianluo.springdependencypolicyauditjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端：HTTP 状态码与可区分错误原因；全程本地，无网络、无真实凭据。
 */
@SpringBootTest(properties = "spring.task.scheduling.enabled=false")
@AutoConfigureMockMvc
class ScanControllerIntegrationTest {

    @Autowired
    private MockMvc mvc;

    private String request(String manifestType, String contentsJson,
                           String batch, String key) {
        return "{\"manifestType\":\"" + manifestType + "\",\"contents\":" + contentsJson
                + ",\"operator\":\"ci-bot\",\"batchId\":\"" + batch + "\""
                + ",\"idempotencyKey\":\"" + key + "\"}";
    }

    @Test
    void cleanScanReturns200() throws Exception {
        String body = request("manifest",
                "\"{\\\"ecosystem\\\":\\\"maven\\\",\\\"dependencies\\\":["
                        + "{\\\"group\\\":\\\"com.acme.safe\\\",\\\"name\\\":\\\"lib\\\","
                        + "\\\"version\\\":\\\"1.0.0\\\",\\\"scope\\\":\\\"compile\\\"}]}\"",
                "it-ok", "it-ok-key");
        mvc.perform(post("/api/scans").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PASSED"))
                .andExpect(jsonPath("$.blocked").value(false))
                .andExpect(jsonPath("$.contentFingerprint").isNotEmpty())
                .andExpect(jsonPath("$.policyVersion").value("default-1.0.0"));
    }

    @Test
    void blockedScanReturns403WithReason() throws Exception {
        String body = request("manifest",
                "\"{\\\"ecosystem\\\":\\\"maven\\\",\\\"dependencies\\\":["
                        + "{\\\"group\\\":\\\"com.example.banned\\\",\\\"name\\\":\\\"badlib\\\","
                        + "\\\"version\\\":\\\"1.0.0\\\",\\\"scope\\\":\\\"compile\\\"}]}\"",
                "it-block", "it-block-key");
        mvc.perform(post("/api/scans").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.blocked").value(true))
                .andExpect(jsonPath("$.decisions[0].reasonCode").value("DENY_RULE"))
                .andExpect(jsonPath("$.decisions[0].fingerprint").isNotEmpty());
    }

    @Test
    void malformedManifestReturns422WithDistinctReasons() throws Exception {
        String body = "{\"manifestType\":\"manifest\","
                + "\"contents\":\"{\\\"ecosystem\\\":\\\"maven\\\",\\\"dependencies\\\":["
                + "{\\\"group\\\":\\\"com.x\\\",\\\"version\\\":\\\"1.0\\\"},"
                + "{\\\"group\\\":\\\"com.y\\\",\\\"name\\\":\\\"n\\\",\\\"version\\\":\\\"LATEST\\\"}]}\","
                + "\"operator\":\"ci\",\"batchId\":\"it-422\",\"idempotencyKey\":\"it-422-key\"}";
        mvc.perform(post("/api/scans").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.errorCode").value("MANIFEST_PARSE_FAILED"))
                .andExpect(jsonPath("$.issues[0].reason").exists())
                .andExpect(jsonPath("$.issues[?(@.reason=='MISSING_FIELD')]").exists())
                .andExpect(jsonPath("$.issues[?(@.reason=='VERSION_INCOMPLETE')]").exists());
    }

    @Test
    void invalidRequestReturns400() throws Exception {
        String body = "{\"manifestType\":\"manifest\",\"contents\":\"\"}";
        mvc.perform(post("/api/scans").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_REQUEST"));
    }

    @Test
    void duplicatePostReturnsSameResultAndAuditEndpointExposesRecord() throws Exception {
        String body = request("manifest",
                "\"{\\\"ecosystem\\\":\\\"maven\\\",\\\"dependencies\\\":["
                        + "{\\\"group\\\":\\\"com.example.banned\\\",\\\"name\\\":\\\"badlib\\\","
                        + "\\\"version\\\":\\\"1.0.0\\\",\\\"scope\\\":\\\"compile\\\"}]}\"",
                "it-dup", "it-dup-key");
        mvc.perform(post("/api/scans").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/scans").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.decisions[0].fingerprint").isNotEmpty());

        mvc.perform(get("/api/audits/batches/it-dup"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.records[0].operator").value("ci-bot"))
                .andExpect(jsonPath("$.records[0].policyVersion").value("default-1.0.0"))
                .andExpect(jsonPath("$.records[0].decision").value("DENY"));
    }
}
