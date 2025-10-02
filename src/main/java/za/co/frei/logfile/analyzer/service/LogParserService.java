package za.co.frei.logfile.analyzer.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import za.co.frei.logfile.analyzer.model.EventType;
import za.co.frei.logfile.analyzer.model.LogEntry;
import za.co.frei.logfile.analyzer.model.LoginStats;
import za.co.frei.logfile.analyzer.model.SuspiciousWindow;
import za.co.frei.logfile.analyzer.model.TopUploader;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class LogParserService {

    private static final Logger logger = LoggerFactory.getLogger(LogParserService.class);

    // Thread-safe: ConcurrentLinkedQueue allows safe concurrent access without external synchronization
    private final ConcurrentLinkedQueue<LogEntry> storedEntries = new ConcurrentLinkedQueue<>();

    // Thread-safe: AtomicInteger provides atomic operations for thread-safe counter
    private final AtomicInteger errors = new AtomicInteger(0);

    public List<LogEntry> getStoredEntries() {
        // Wrap in unmodifiable list to prevent external modification
        return Collections.unmodifiableList(new ArrayList<>(storedEntries));
    }

    public synchronized void clearStoredEntries() {
        storedEntries.clear();
        errors.set(0);
    }

    public int getStoredEntryCount() {
        return storedEntries.size();
    }

    protected void addStoredEntry(LogEntry entry) {
        storedEntries.add(entry);  // ConcurrentLinkedQueue is thread-safe
    }

    public Map<String, Object> getParseResult() {
        return Map.of(
                "errors", errors.get(),
                "processed", storedEntries.size() + errors.get(),
                "totalStored", storedEntries.size(),
                "status", errors.get() == 0 ? 201 : 206
        );
    }

    public List<LogEntry> parseLog(InputStream inputStream) {
        List<LogEntry> entries = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.trim().isEmpty()) {
                    logger.debug("Skipping empty line at line {}", lineNumber);
                    continue;
                }

                String[] parts = line.split("\\s*\\|\\s*");
                if (parts.length < 3) {
                    logger.warn("Invalid log line at {}: {}", lineNumber, line);
                    errors.incrementAndGet();

                    continue;
                }

                try {
                    Instant timestamp = Instant.parse(parts[0].trim());
                    String user = parts[1].trim();
                    EventType event = EventType.valueOf(parts[2].trim());
                    String ip = null;
                    String file = null;

                    if (event == EventType.LOGIN_SUCCESS || event == EventType.LOGIN_FAILURE) {
                        if (parts.length > 3 && parts[3].startsWith("IP=")) {
                            ip = parts[3].substring(3).trim();
                        } else {
                            logger.warn("Missing or invalid IP at line {}: {}", lineNumber, line);
                            errors.incrementAndGet();

                            continue;
                        }
                    } else if (event == EventType.FILE_UPLOAD || event == EventType.FILE_DOWNLOAD) {
                        // Case 1: Just FILE=... (no IP provided)
                        if (parts.length == 4 && parts[3].startsWith("FILE=")) {
                            file = parts[3].substring(5).trim();
                            ip = "0.0.0.0"; // default placeholder
                        }
                        // Case 2: IP=... + FILE=...
                        else if (parts.length > 4 && parts[3].startsWith("IP=")) {
                            ip = parts[3].substring(3).trim();
                            if (parts[4].startsWith("FILE=")) {
                                file = parts[4].substring(5).trim();
                            } else {
                                logger.warn("Invalid FILE at line {}: {}", lineNumber, line);
                                errors.incrementAndGet();

                                continue;
                            }
                        } else {
                            logger.warn("Missing FILE field at line {}: {}", lineNumber, line);
                            errors.incrementAndGet();

                            continue;
                        }
                    } else if (event == EventType.LOGOUT) {
                        if (parts.length > 3 && !parts[3].isEmpty()) {
                            logger.warn("Unexpected extra field for LOGOUT at line {}: {}", lineNumber, line);
                            errors.incrementAndGet();

                            continue;
                        }
                        ip = "0.0.0.0"; // default for logout
                    } else {
                        logger.warn("Unknown event type at line {}: {}", lineNumber, line);
                        errors.incrementAndGet();

                        continue;
                    }

                    LogEntry entry = new LogEntry(timestamp, user, event, ip, file);
                    entries.add(entry);
                    addStoredEntry(entry);
                    logger.debug("Parsed entry at line {}: {}", lineNumber, entry);

                } catch (IllegalArgumentException e) {
                    logger.warn("Failed to parse line {}: {}, error: {}", lineNumber, line, e.getMessage());
                    errors.incrementAndGet();

                }
            }
            logger.info("Parsed {} entries, total stored: {}, errors: {}", entries.size(), storedEntries.size(), errors.get());
        } catch (IOException e) {
            logger.error("Error reading log file: {}", e.getMessage(), e);
            throw new RuntimeException("Error parsing log file", e);
        }
        return entries;
    }


    public Map<String, LoginStats> getLoginCounts(List<LogEntry> entries) {
        // TODO: Implement logic to count LOGIN_SUCCESS and LOGIN_FAILURE per user
        return null;
    }

    public List<TopUploader> getTopUploaders(List<LogEntry> entries, int limit) {
        // TODO: Implement logic to get top uploaders based on FILE_UPLOAD events
        return null;
    }

    public List<SuspiciousWindow> getSuspiciousActivity(List<LogEntry> entries) {
        // TODO: Implement logic to detect suspicious LOGIN_FAILURE activity
        return null;
    }
}