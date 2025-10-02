package za.co.frei.logfile.analyzer.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import za.co.frei.logfile.analyzer.service.LogParserService;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for LogFileController.
 *
 * CHANGED TO INTEGRATION TEST APPROACH:
 * - Originally tried using @Mock for LogParserService, but this conflicts with @SpringBootTest
 * - @SpringBootTest loads the full Spring context with real beans
 * - Using @Autowired with the real service allows us to test the complete flow:
 *   HTTP Request → Controller → Service → In-Memory Storage → Response
 * - This validates that the entire application works correctly together
 */
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(MockitoExtension.class)
public class LogFileControllerTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * Real service injected from Spring context.
     * Changed from @Mock to @Autowired because:
     * - @Mock creates a fake service that doesn't actually process data
     * - @Autowired uses the real LogParserService bean
     * - This allows testing actual data flow and aggregation
     */
    @Autowired
    private LogParserService parserService;

    /**
     * Clear in-memory storage before each test.
     * IMPORTANT: Integration tests share the same service instance,
     * so we need to reset state to prevent test interference.
     */
    @BeforeEach
    public void setUp() {
        parserService.clearStoredEntries();
    }

    @Test
    public void shouldReturnHelloMessage() throws Exception {
        mockMvc.perform(get("/api/v1/logs/hello"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-cache"));
    }

    @Test
    public void shouldFilterLoginCountsByUser() throws Exception {
        String logContent =
                "2025-09-15T08:00:00Z | alice | LOGIN_SUCCESS | IP=192.168.1.1\n" +
                        "2025-09-15T08:01:00Z | alice | LOGIN_FAILURE | IP=192.168.1.1\n" +
                        "2025-09-15T08:02:00Z | bob | LOGIN_SUCCESS | IP=192.168.1.2";

        MockMultipartFile file = new MockMultipartFile(
                "file", "test.log", "text/plain", logContent.getBytes()
        );

        mockMvc.perform(multipart("/api/v1/logs/upload").file(file))
                .andExpect(status().isCreated());

        // Test filtering by user
        mockMvc.perform(get("/api/v1/logs/users/login-counts")
                        .param("user", "alice"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.alice").exists())
                .andExpect(jsonPath("$.bob").doesNotExist());
    }

    @Test
    public void shouldReturn204WhenFilteredUserNotFound() throws Exception {
        String logContent = "2025-09-15T08:00:00Z | alice | LOGIN_SUCCESS | IP=192.168.1.1";

        MockMultipartFile file = new MockMultipartFile(
                "file", "test.log", "text/plain", logContent.getBytes()
        );

        mockMvc.perform(multipart("/api/v1/logs/upload").file(file))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/v1/logs/users/login-counts")
                        .param("user", "nonexistent"))
                .andExpect(status().isNoContent());
    }

    @Test
    public void shouldReturnBadRequestForEmptyFile() throws Exception {
        MockMultipartFile emptyFile = new MockMultipartFile("file", "empty.log", "text/plain", new byte[0]);
        mockMvc.perform(multipart("/api/v1/logs/upload").file(emptyFile))
                .andExpect(status().isBadRequest());
    }

    /**
     * Tests the correct behavior when no data has been uploaded.
     * Changed from expecting 200 OK to 204 No Content - this is the correct behavior
     * when loginStatsByUser is empty.
     */
    @Test
    public void shouldReturnNoContentWhenNoLoginData() throws Exception {
        // No data uploaded, so service returns empty map, controller returns 204
        mockMvc.perform(get("/api/v1/logs/users/login-counts"))
                .andExpect(status().isNoContent());
    }

    /**
     * Integration test: Upload real data, then query it.
     * This validates the complete flow:
     * 1. File upload → parsing → aggregation
     * 2. Query endpoint → retrieve aggregated data
     *
     * This is why we need the real service - we're testing actual data flow.
     */
    @Test
    public void shouldReturnLoginCountsAfterUpload() throws Exception {
        String logContent = "2025-09-15T08:00:00Z | alice | LOGIN_SUCCESS | IP=192.168.1.1\n" +
                "2025-09-15T08:01:00Z | alice | LOGIN_FAILURE | IP=192.168.1.1\n" +
                "2025-09-15T08:02:00Z | bob | LOGIN_SUCCESS | IP=192.168.1.2";

        MockMultipartFile file = new MockMultipartFile(
                "file", "test.log", "text/plain", logContent.getBytes()
        );

        // Step 1: Upload and parse the file
        mockMvc.perform(multipart("/api/v1/logs/upload").file(file))
                .andExpect(status().isCreated());

        // Step 2: Verify the aggregated data is queryable
        mockMvc.perform(get("/api/v1/logs/users/login-counts"))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldReturnTopUploaders() throws Exception {
        // TODO: Test top uploaders endpoint (returns null currently)
        mockMvc.perform(get("/api/v1/logs/users/top-uploaders"))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldReturnSuspiciousActivity() throws Exception {
        // TODO: Test suspicious activity endpoint (returns null currently)
        mockMvc.perform(get("/api/v1/logs/security/suspicious"))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldReturnExportFile() throws Exception {
        // TODO: Test export endpoint (returns null currently)
        mockMvc.perform(get("/api/v1/logs/export"))
                .andExpect(status().isOk());
    }
}