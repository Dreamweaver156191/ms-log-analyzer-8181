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

@RestController
@RequestMapping("/api/v1/logs")
@Tag(name = "Log File Analyzer", description = "Endpoints for log file analysis and security monitoring")
public class LogFileController {

    private static final Logger logger = LoggerFactory.getLogger(LogFileController.class);
    private final LogParserService parserService;

    public LogFileController(LogParserService parserService) {
        this.parserService = parserService;
        logger.info("LogFileController initialized");
    }

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
     * Single File Upload Endpoint (Swagger UI Compatible)
     *
     * Accepts a single log file for processing. This endpoint is optimized for Swagger UI testing.
     * For uploading multiple files simultaneously, use the /upload endpoint via Postman or cURL.
     *
     * @param file A single .log file to process
     * @return Upload summary with processing statistics
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

        // Validate file
        if (file.isEmpty()) {
            logger.warn("Empty file provided");
            throw new IllegalArgumentException("File cannot be empty");
        }

        // Reuse existing multi-file upload logic by converting to array
        return uploadLog(new MultipartFile[]{file});
    }

    /**
     * Log File Upload Endpoint (Multiple Files)
     *
     * Accepts one or more log files from different systems and aggregates all data
     * in memory for cross-system analysis. This allows detection of patterns across
     * multiple systems (e.g., suspicious login attempts from the same IP across
     * different system logs).
     *
     * Note: Due to Swagger UI limitations with multipart arrays, use /upload-single
     * for testing in Swagger UI, or use Postman/cURL for this endpoint.
     *
     * @param files One or more .log files to process
     * @return Upload summary with processing statistics
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

        // Validate input - let exception handler catch IllegalArgumentException
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
                // Don't throw - continue processing other files
            }
        }

        // If ALL files failed, throw exception for handler to catch
        if (filesProcessed == 0) {
            logger.error("Failed to process any files out of {} attempts", files.length);
            throw new FileProcessingException("Failed to process any of the uploaded files");
        }

        logger.info("Upload complete: {} of {} files processed successfully, {} total entries",
                filesProcessed, files.length, totalEntriesProcessed);

        // Build response
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

        // Filter by user if specified
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

        // Call the new method signature with just limit parameter
        List<TopUploader> topUploaders = parserService.getTopUploaders(limit);

        // Return 204 No Content if no upload data exists
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
     * Export Analysis Results Endpoint
     *
     * Generates a downloadable JSON file containing all log analysis results including
     * login statistics, top uploaders, and suspicious activity detection.
     *
     * @return JSON file as byte array with appropriate headers for download
     * @throws ExportException if JSON generation fails
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
            // Build structured export response
            ExportResponse exportData = new ExportResponse(
                    Instant.now().toString(),
                    parserService.getStoredEntryCount(),
                    parserService.getLoginCounts(),
                    parserService.getTopUploaders(3),
                    parserService.getSuspiciousActivity()
            );

            // Configure JSON mapper with pretty printing and Java 8 date/time support
            ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());
            mapper.enable(SerializationFeature.INDENT_OUTPUT);

            byte[] jsonBytes = mapper.writeValueAsBytes(exportData);

            logger.info("Successfully exported {} bytes of analysis results with {} login stats, {} top uploaders, {} suspicious activities",
                    jsonBytes.length,
                    exportData.loginStatistics().size(),
                    exportData.topUploaders().size(),
                    exportData.suspiciousActivity().size());

            // Return as downloadable JSON file
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