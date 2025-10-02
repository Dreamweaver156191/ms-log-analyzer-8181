package za.co.frei.logfile.analyzer.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import za.co.frei.logfile.analyzer.exception.FileProcessingException;
import za.co.frei.logfile.analyzer.model.LogEntry;
import za.co.frei.logfile.analyzer.model.LoginStats;
import za.co.frei.logfile.analyzer.model.TopUploader;
import za.co.frei.logfile.analyzer.model.UploadResponse;
import za.co.frei.logfile.analyzer.service.LogParserService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/logs")
public class LogFileController {

    private static final Logger logger = LoggerFactory.getLogger(LogFileController.class);
    private final LogParserService parserService;

    public LogFileController(LogParserService parserService) {
        this.parserService = parserService;
        logger.info("LogFileController initialized");
    }

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        logger.debug("Handling GET request for /hello endpoint");
        return ResponseEntity.ok()
                .header("Cache-Control", "no-cache")
                .body("Log File Analyzer Controller is active!");
    }

    /**
     * Log File Upload Endpoint
     *
     * Accepts one or more log files from different systems and aggregates all data
     * in memory for cross-system analysis. This allows detection of patterns across
     * multiple systems (e.g., suspicious login attempts from the same IP across
     * different system logs).
     *
     * @param files One or more .log files to process
     * @return Upload summary with processing statistics
     */
    @PostMapping("/upload")
    public ResponseEntity<UploadResponse> uploadLog(@RequestParam("file") MultipartFile[] files) {
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
    public ResponseEntity<Map<String, LoginStats>> getLoginCounts(
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
    public ResponseEntity<List<Map<String, Object>>> getTopUploaders(@RequestParam(defaultValue = "3") int limit) {
        logger.debug("Handling GET request for /users/top-uploaders endpoint with limit {}", limit);
        // TODO: Implement logic to get top uploaders based on FILE_UPLOAD events
        return ResponseEntity.ok(null);
    }

    @GetMapping("/security/suspicious")
    public ResponseEntity<List<Map<String, Object>>> getSuspiciousActivity() {
        logger.debug("Handling GET request for /security/suspicious endpoint");
        // TODO: Implement logic to detect suspicious LOGIN_FAILURE activity
        return ResponseEntity.ok(null);
    }

    @GetMapping("/export")
    public ResponseEntity<byte[]> exportResults() {
        logger.debug("Handling GET request for /export endpoint");
        // TODO: Implement logic to export results as JSON file
        return ResponseEntity.ok().body(null);
    }
}