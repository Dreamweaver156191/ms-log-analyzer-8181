package za.co.frei.logfile.analyzer.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import za.co.frei.logfile.analyzer.exception.FileProcessingException;
import za.co.frei.logfile.analyzer.model.*;
import za.co.frei.logfile.analyzer.service.LogParserService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import za.co.frei.logfile.analyzer.exception.ExportException;

import java.time.Instant;

/**
 * REST Controller for log file analysis operations.
 * <p>
 * Provides endpoints for:
 * <ul>
 *   <li>Uploading and parsing log files (single or multiple)</li>
 *   <li>Retrieving login statistics per user</li>
 *   <li>Identifying top file uploaders</li>
 *   <li>Detecting suspicious login activity (brute-force patterns)</li>
 *   <li>Exporting complete analysis results to JSON</li>
 * </ul>
 * <p>
 * All data is stored in memory using thread-safe concurrent data structures.
 * Statistics are pre-aggregated during parsing for O(1) query performance.
 * <p>
 * Base path: {@code /api/v1/logs}
 *
 * @author Francois van der Merwe
 * @version 5.0
 * @since 2025-01-15
 */
@RestController
@RequestMapping("/api/v1/logs")
@Tag(name = "Log File Analyzer", description = "Endpoints for log file analysis and security monitoring")
public class LogFileController {

    private static final Logger logger = LoggerFactory.getLogger(LogFileController.class);
    private final LogParserService parserService;

    /**
     * Constructs the controller with dependency injection of the log parser service.
     *
     * @param parserService the service responsible for parsing and analyzing log files
     */
    public LogFileController(LogParserService parserService) {
        this.parserService = parserService;
        logger.info("LogFileController initialized");
    }

    /**
     * Health check endpoint to verify API availability.
     * <p>
     * This endpoint can be used by monitoring tools or load balancers to check
     * if the application is running and responsive.
     *
     * @return ResponseEntity with a success message and 200 OK status
     */
    @GetMapping("/hello")
    @Operation(
            summary = "Health check endpoint",
            description = "Verifies that the Log File Analyzer API is running and accessible"
    )
    @ApiResponse(responseCode = "200", description = "Service is active")
    public ResponseEntity<String> hello() {
        logger.debug("Handling GET request for /hello endpoint");
        return ResponseEntity.ok()
                .header("Cache-Control", "no-cache")
                .body("Log File Analyzer Controller is active!");
    }

    /**
     * Uploads a single log file for analysis (Swagger UI compatible endpoint).
     * <p>
     * This endpoint accepts a single file and is optimized for testing through
     * Swagger UI, which has limitations with multipart file arrays. For uploading
     * multiple files simultaneously, use the {@link #uploadLog(MultipartFile[])} endpoint
     * via Postman or cURL.
     * <p>
     * The file is parsed line-by-line, with each valid entry stored in memory
     * and aggregated for fast querying. Invalid lines are logged but don't fail
     * the entire upload.
     *
     * @param file the log file to process (.log format recommended)
     * @return ResponseEntity containing upload statistics including number of entries
     *         processed, files processed, and any errors encountered
     * @throws IllegalArgumentException if the file is empty
     * @throws FileProcessingException if file processing completely fails
     */
    @PostMapping(value = "/upload-single", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Upload a single log file (Swagger UI compatible)",
            description = "Upload one log file for analysis. This endpoint is designed for Swagger UI compatibility.\n\n" +
                    "For uploading multiple files simultaneously, use POST /upload endpoint via Postman or cURL.\n\n" +
                    "**Expected Log Format:**\n" +
                    "```\n" +
                    "2024-01-15T10:30:00Z | user1 | LOGIN_SUCCESS | IP=192.168.1.100\n" +
                    "2024-01-15T10:31:00Z | user2 | FILE_UPLOAD | IP=192.168.1.101 | FILE=report.pdf\n" +
                    "```"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "File uploaded and processed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UploadResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "No file provided or file is empty",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "422",
                    description = "File processing failed",
                    content = @Content(mediaType = "application/json")
            )
    })
    public ResponseEntity<UploadResponse> uploadSingleLog(
            @Parameter(
                    description = "Log file to upload (.log format)",
                    required = true,
                    schema = @Schema(type = "string", format = "binary")
            )
            @RequestPart("file") MultipartFile file) {

        logger.info("Processing single file upload via Swagger UI: {}", file.getOriginalFilename());

        if (file.isEmpty()) {
            logger.warn("Empty file provided");
            throw new IllegalArgumentException("File cannot be empty");
        }

        return uploadLog(new MultipartFile[]{file});
    }

    /**
     * Uploads one or more log files for analysis and aggregation.
     * <p>
     * This endpoint accepts multiple log files from different systems and aggregates
     * all data in memory. This enables cross-system analysis, such as detecting
     * suspicious login attempts from the same IP address across different system logs.
     * <p>
     * Files are processed sequentially. If some files fail to parse, successful
     * files are still stored and processed (partial success). If all files fail,
     * a FileProcessingException is thrown.
     * <p>
     * Each log entry is validated and parsed according to the expected format:
     * {@code timestamp | user | event | event-specific-fields}
     * <p>
     * Statistics are computed during parsing and stored in concurrent data structures
     * for thread-safe, high-performance querying.
     *
     * @param files array of log files to process (must contain at least one valid file)
     * @return ResponseEntity with status 201 (all successful) or 206 (partial success)
     *         containing detailed upload statistics
     * @throws IllegalArgumentException if no valid files are provided
     * @throws FileProcessingException if all files fail to process
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Upload multiple log files for analysis",
            description = "**For Swagger UI testing, use POST /upload-single endpoint instead.**\n\n" +
                    "Accepts one or more .log files from different systems and aggregates all data " +
                    "in memory for cross-system analysis. This allows detection of patterns across " +
                    "multiple systems (e.g., suspicious login attempts from the same IP across different logs).\n\n" +
                    "**Test with cURL:**\n" +
                    "```bash\n" +
                    "# Single file\n" +
                    "curl -X POST http://localhost:8181/api/v1/logs/upload \\\n" +
                    "  -F 'file=@system1.log'\n\n" +
                    "# Multiple files\n" +
                    "curl -X POST http://localhost:8181/api/v1/logs/upload \\\n" +
                    "  -F 'file=@system1.log' \\\n" +
                    "  -F 'file=@system2.log'\n" +
                    "```\n\n" +
                    "**Expected Log Format:**\n" +
                    "```\n" +
                    "2024-01-15T10:30:00Z | user1 | LOGIN_SUCCESS | IP=192.168.1.100\n" +
                    "2024-01-15T10:31:00Z | user2 | FILE_UPLOAD | IP=192.168.1.101 | FILE=report.pdf\n" +
                    "```"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "201",
                    description = "All files successfully uploaded and processed",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UploadResponse.class),
                            examples = @ExampleObject(value = """
                    {
                      "message": "Uploaded 2 of 2 file(s)",
                      "filesProcessed": ["system1.log", "system2.log"],
                      "failedFiles": [],
                      "processed": 1500,
                      "totalStored": 2750,
                      "errors": 0
                    }
                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "206",
                    description = "Partial success - some files failed to process",
                    content = @Content(schema = @Schema(implementation = UploadResponse.class))
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "No valid files provided",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "413",
                    description = "File size exceeds maximum allowed",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "422",
                    description = "All uploaded files failed to process",
                    content = @Content(mediaType = "application/json")
            )
    })
    public ResponseEntity<UploadResponse> uploadLog(
            @Parameter(
                    description = "Log files to upload (one or more .log files)",
                    required = true,
                    schema = @Schema(type = "array", format = "binary")
            )
            @RequestPart("file") MultipartFile[] files) {
        logger.info("Processing upload request with {} file(s)", files.length);

        if (files.length == 0 || (files.length == 1 && files[0].isEmpty())) {
            logger.warn("Upload attempt with no valid files");
            throw new IllegalArgumentException("No valid files provided");
        }

        int totalEntriesProcessed = 0;
        int filesProcessed = 0;
        List<String> processedFileNames = new ArrayList<>();
        List<String> failedFiles = new ArrayList<>();

        for (MultipartFile file : files) {
            String filename = file.getOriginalFilename();

            if (file.isEmpty()) {
                logger.warn("Skipping empty file: {}", filename);
                failedFiles.add(filename);
                continue;
            }

            try {
                logger.info("Processing file: {}", filename);
                List<LogEntry> entries = parserService.parseLog(file.getInputStream());

                totalEntriesProcessed += entries.size();
                filesProcessed++;
                processedFileNames.add(filename);

                logger.debug("Parsed {} entries from {}, total stored: {}",
                        entries.size(), filename, parserService.getStoredEntryCount());

            } catch (IOException e) {
                logger.error("Error parsing file {}: {}", filename, e.getMessage());
                failedFiles.add(filename);
            }
        }

        if (filesProcessed == 0) {
            logger.error("Failed to process any files out of {} attempts", files.length);
            throw new FileProcessingException("Failed to process any of the uploaded files");
        }

        logger.info("Upload complete: {} of {} files processed successfully, {} total entries",
                filesProcessed, files.length, totalEntriesProcessed);

        UploadResponse response = new UploadResponse(
                String.format("Uploaded %d of %d file(s)", filesProcessed, files.length),
                processedFileNames,
                failedFiles,
                totalEntriesProcessed,
                parserService.getStoredEntryCount(),
                failedFiles.size()
        );

        return ResponseEntity
                .status(failedFiles.isEmpty() ? HttpStatus.CREATED : HttpStatus.PARTIAL_CONTENT)
                .body(response);
    }

    /**
     * Retrieves login statistics for all users or a specific user.
     * <p>
     * Returns aggregated login data including:
     * <ul>
     *   <li>Total successful login attempts</li>
     *   <li>Total failed login attempts</li>
     *   <li>List of IP addresses used for successful logins</li>
     *   <li>List of IP addresses used for failed logins</li>
     *   <li>Timestamp of most recent successful login</li>
     *   <li>Timestamp of most recent failed login</li>
     * </ul>
     * <p>
     * Data is retrieved from pre-aggregated statistics for O(1) performance.
     *
     * @param user optional username filter; if provided, returns stats for only that user
     * @return ResponseEntity with status 200 and login statistics map, or 204 if no data exists
     */
    @GetMapping("/users/login-counts")
    @Operation(
            summary = "Get login statistics per user",
            description = "Returns success and failure counts for each user, including IPs used and timestamps of last logins"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Login statistics retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = Map.class),
                            examples = @ExampleObject(value = """
                    {
                      "user1": {
                        "user": "user1",
                        "success": 15,
                        "failure": 2,
                        "successIps": ["192.168.1.100", "10.0.0.50"],
                        "failureIps": ["192.168.1.200"],
                        "lastSuccessTimestamp": "2024-01-15T10:30:00Z",
                        "lastFailureTimestamp": "2024-01-15T09:15:00Z"
                      }
                    }
                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "204",
                    description = "No login data available"
            )
    })
    public ResponseEntity<Map<String, LoginStats>> getLoginCounts(
            @Parameter(description = "Filter by specific username (optional)")
            @RequestParam(required = false) String user) {
        logger.debug("GET /users/login-counts with user filter: {}", user);

        Map<String, LoginStats> loginCounts = parserService.getLoginCounts();

        if (loginCounts.isEmpty()) {
            logger.info("No login data available");
            return ResponseEntity.noContent().build();
        }

        if (user != null && !user.isBlank()) {
            LoginStats stats = loginCounts.get(user);
            if (stats == null) {
                logger.info("No login data for user: {}", user);
                return ResponseEntity.noContent().build();
            }
            return ResponseEntity.ok(Map.of(user, stats));
        }

        logger.debug("Returning login counts for {} users", loginCounts.size());
        return ResponseEntity.ok(loginCounts);
    }

    /**
     * Retrieves the top file uploaders ranked by number of FILE_UPLOAD events.
     * <p>
     * Users are sorted in descending order by upload count. The number of results
     * is controlled by the limit parameter (default: 3).
     * <p>
     * Uses pre-aggregated upload counts for O(1) lookup and O(n log n) sorting performance.
     *
     * @param limit maximum number of top uploaders to return (must be positive)
     * @return ResponseEntity with status 200 and list of top uploaders, or 204 if no upload data exists
     * @throws IllegalArgumentException if limit is not positive
     */
    @GetMapping("/users/top-uploaders")
    @Operation(
            summary = "Get top file uploaders",
            description = "Returns users ranked by number of FILE_UPLOAD events in descending order"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Top uploaders retrieved successfully",
                    content = @Content(
                            mediaType = "application/json",
                            examples = @ExampleObject(value = """
                    [
                      {"user": "user1", "uploads": 45},
                      {"user": "user2", "uploads": 32},
                      {"user": "user3", "uploads": 28}
                    ]
                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "204",
                    description = "No upload data available"
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid limit parameter (must be positive)"
            )
    })
    public ResponseEntity<List<Map<String, Object>>> getTopUploaders(
            @Parameter(description = "Number of top uploaders to return", example = "3")
            @RequestParam(defaultValue = "3") int limit) {
        logger.debug("Handling GET request for /users/top-uploaders endpoint with limit {}", limit);

        if (limit <= 0) {
            logger.warn("Invalid limit provided: {}", limit);
            throw new IllegalArgumentException("Limit must be positive");
        }

        List<TopUploader> topUploaders = parserService.getTopUploaders(limit);

        if (topUploaders.isEmpty()) {
            logger.info("No upload data available, returning 204 No Content");
            return ResponseEntity.noContent().build();
        }

        List<Map<String, Object>> response = topUploaders.stream()
                .map(u -> {
                    Map<String, Object> map = new HashMap<>();
                    map.put("user", u.user());
                    map.put("uploads", u.uploads());
                    return map;
                })
                .toList();

        logger.info("Returning top {} uploaders, found {} users", limit, response.size());
        return ResponseEntity.ok(response);
    }

    /**
     * Detects suspicious login activity indicative of brute-force attacks.
     * <p>
     * Analyzes LOGIN_FAILURE events to identify IP addresses with more than 3 failed
     * login attempts within a 5-minute window. This pattern is commonly associated with
     * brute-force password attacks or credential stuffing attempts.
     * <p>
     * Uses a sliding window algorithm to detect suspicious patterns across all stored
     * login failure events. Each suspicious window includes:
     * <ul>
     *   <li>IP address of the attacker</li>
     *   <li>Start and end timestamps of the suspicious activity window</li>
     *   <li>Total number of failures in the window</li>
     *   <li>Exact timestamps of each failure</li>
     *   <li>Usernames targeted in each failure</li>
     * </ul>
     *
     * @return ResponseEntity with status 200 and list of suspicious activity windows,
     *         or 204 if no suspicious activity detected
     */
    @GetMapping("/security/suspicious")
    @Operation(
            summary = "Detect suspicious login activity",
            description = "Identifies IP addresses with more than 3 LOGIN_FAILURE attempts within a 5-minute window. " +
                    "This helps detect potential brute-force attacks or credential stuffing attempts."
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Suspicious activity detected",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SuspiciousWindow.class),
                            examples = @ExampleObject(value = """
                    [
                      {
                        "ip": "192.168.1.200",
                        "start": "2024-01-15T10:00:00Z",
                        "end": "2024-01-15T10:04:30Z",
                        "failures": 5,
                        "timestamps": [
                          "2024-01-15T10:00:00Z",
                          "2024-01-15T10:01:00Z",
                          "2024-01-15T10:02:30Z",
                          "2024-01-15T10:03:45Z",
                          "2024-01-15T10:04:30Z"
                        ],
                        "users": ["user1", "user2", "user1", "user3", "user1"]
                      }
                    ]
                    """)
                    )
            ),
            @ApiResponse(
                    responseCode = "204",
                    description = "No suspicious activity detected"
            )
    })
    public ResponseEntity<List<SuspiciousWindow>> getSuspiciousActivity() {
        logger.debug("Handling GET request for /security/suspicious endpoint");

        List<SuspiciousWindow> suspiciousActivity = parserService.getSuspiciousActivity();

        if (suspiciousActivity.isEmpty()) {
            logger.info("No suspicious activity detected, returning 204 No Content");
            return ResponseEntity.noContent().build();
        }

        logger.info("Returning {} suspicious activity window(s)", suspiciousActivity.size());
        return ResponseEntity.ok(suspiciousActivity);
    }

    /**
     * Exports all analysis results to a downloadable JSON file.
     * <p>
     * Generates a comprehensive JSON export containing:
     * <ul>
     *   <li>Export timestamp</li>
     *   <li>Total number of log entries stored</li>
     *   <li>Complete login statistics for all users</li>
     *   <li>Top 3 file uploaders</li>
     *   <li>All detected suspicious activity windows</li>
     * </ul>
     * <p>
     * The JSON is formatted with indentation for readability and includes proper
     * timestamp handling via Jackson's JavaTimeModule.
     * <p>
     * The response includes appropriate headers to trigger browser download:
     * {@code Content-Disposition: attachment; filename=log-analysis-export.json}
     *
     * @return ResponseEntity containing the JSON data as a byte array with 200 OK status
     * @throws ExportException if JSON serialization fails
     */
    @GetMapping("/export")
    @Operation(
            summary = "Export all analysis results",
            description = "Generates a downloadable JSON file containing complete log analysis including " +
                    "login statistics, top uploaders, and suspicious activity detection"
    )
    @ApiResponses({
            @ApiResponse(
                    responseCode = "200",
                    description = "Export file generated successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ExportResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Failed to generate export file"
            )
    })
    public ResponseEntity<byte[]> exportResults() {
        logger.debug("Handling GET request for /export endpoint");

        try {
            ExportResponse exportData = new ExportResponse(
                    Instant.now().toString(),
                    parserService.getStoredEntryCount(),
                    parserService.getLoginCounts(),
                    parserService.getTopUploaders(3),
                    parserService.getSuspiciousActivity()
            );

            ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());
            mapper.enable(SerializationFeature.INDENT_OUTPUT);

            byte[] jsonBytes = mapper.writeValueAsBytes(exportData);

            logger.info("Successfully exported {} bytes of analysis results with {} login stats, {} top uploaders, {} suspicious activities",
                    jsonBytes.length,
                    exportData.loginStatistics().size(),
                    exportData.topUploaders().size(),
                    exportData.suspiciousActivity().size());

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=log-analysis-export.json")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(jsonBytes);

        } catch (Exception e) {
            logger.error("Error exporting results: {}", e.getMessage(), e);
            throw new ExportException("Failed to generate export file", e);
        }
    }
}