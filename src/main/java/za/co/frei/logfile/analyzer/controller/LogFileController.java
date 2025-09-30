package za.co.frei.logfile.analyzer.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import za.co.frei.logfile.analyzer.model.LogEntry;
import za.co.frei.logfile.analyzer.service.LogParserService;

import java.io.IOException;
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
        // TODO: Implement health check logic
        return ResponseEntity.ok()
                .header("Cache-Control", "no-cache")
                .body("Log File Analyzer Controller is active!");
    }

    @PostMapping("/upload")
    public ResponseEntity<Map<String, Object>> uploadLog(@RequestParam("file") MultipartFile file) {
        logger.info("Processing upload for file: {}", file.getOriginalFilename());
        // TODO: Validate file and handle parsing
        if (file.isEmpty()) {
            logger.warn("Upload attempt with empty file");
            return ResponseEntity.badRequest().body(Map.of(
                    "status", HttpStatus.BAD_REQUEST.value(),
                    "error", "Bad Request",
                    "message", "File is empty"
            ));
        }
        try {
            // Ensure parseLog is called and its result is used
            List<LogEntry> entries = parserService.parseLog(file.getInputStream());
            logger.debug("Parsed {} entries from uploaded file", entries.size());
            return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                    "status", HttpStatus.CREATED.value(),
                    "message", "Uploaded " + file.getOriginalFilename(),
                    "processed", entries.size(),
                    "errors", 0
            ));
        } catch (IOException e) {
            logger.error("Error parsing uploaded file: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                    "status", HttpStatus.INTERNAL_SERVER_ERROR.value(),
                    "error", "Internal Server Error",
                    "message", "Error processing file: " + e.getMessage()
            ));
        }
    }

    @GetMapping("/users/login-counts")
    public ResponseEntity<Map<String, Map<String, Integer>>> getLoginCounts() {
        logger.debug("Handling GET request for /users/login-counts endpoint");
        // TODO: Implement logic to count LOGIN_SUCCESS and LOGIN_FAILURE per user
        return ResponseEntity.ok(null);
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