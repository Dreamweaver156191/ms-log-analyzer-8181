package za.co.frei.logfile.analyzer.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import za.co.frei.logfile.analyzer.model.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LogParserService {

    private static final Logger logger = LoggerFactory.getLogger(LogParserService.class);

    // Thread-safe: ConcurrentLinkedQueue allows safe concurrent access without external synchronization
    private final ConcurrentLinkedQueue<LogEntry> storedEntries = new ConcurrentLinkedQueue<>();

    // Aggregated data - maintained during parsing for O(1) query performance
    // Maps user -> login statistics (success/failure counts)
    private final ConcurrentHashMap<String, LoginStatsHolder> loginStatsByUser = new ConcurrentHashMap<>();

    // Maps user -> number of file uploads
    private final ConcurrentHashMap<String, AtomicInteger> uploadCountsByUser = new ConcurrentHashMap<>();

    // Maps IP -> timestamps of login failures (for suspicious activity detection)
    private final ConcurrentHashMap<String, ConcurrentLinkedQueue<Instant>> loginFailuresByIp = new ConcurrentHashMap<>();

    // Thread-safe: AtomicInteger provides atomic operations for thread-safe counter
    private final AtomicInteger errors = new AtomicInteger(0);

    public List<LogEntry> getStoredEntries() {
        // Creates immutable snapshot - List.copyOf() is null-safe and more efficient
        return List.copyOf(storedEntries);
    }

    /**
     * Returns login statistics by user. Thread-safe snapshot.
     */
    protected Map<String, LoginStatsHolder> getLoginStatsByUser() {
        return new HashMap<>(loginStatsByUser);
    }

    /**
     * Returns upload counts by user. Thread-safe snapshot.
     */
    protected Map<String, AtomicInteger> getUploadCountsByUser() {
        return new HashMap<>(uploadCountsByUser);
    }

    /**
     * Returns login failures grouped by IP. Thread-safe snapshot.
     */
    protected Map<String, ConcurrentLinkedQueue<Instant>> getLoginFailuresByIp() {
        return new HashMap<>(loginFailuresByIp);
    }

    public synchronized void clearStoredEntries() {
        storedEntries.clear();
        errors.set(0);
        loginStatsByUser.clear();
        uploadCountsByUser.clear();
        loginFailuresByIp.clear();
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
        Map<EventType, Integer> eventCounts = new HashMap<>();
        logger.info("Starting log parsing from InputStream");

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;

                // Progress logging for large files
                if (lineNumber % 500 == 0) {
                    logger.info("Parsed {} lines so far, {} entries added, {} errors encountered",
                            lineNumber, entries.size(), errors.get());
                }

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
                    updateAggregates(entry);
                    eventCounts.merge(event, 1, Integer::sum);
                    logger.debug("Parsed entry at line {}: {}", lineNumber, entry);

                } catch (IllegalArgumentException e) {
                    logger.warn("Failed to parse line {}: {}, error: {}", lineNumber, line, e.getMessage());
                    errors.incrementAndGet();
                }
            }

            logger.info("Event breakdown: {}", eventCounts);
            logger.info("Parsed {} entries, total stored: {}, errors: {}",
                    entries.size(), storedEntries.size(), errors.get());
        } catch (IOException e) {
            logger.error("Error reading log file: {}", e.getMessage(), e);
            throw new RuntimeException("Error parsing log file", e);
        }
        return entries;
    }

    /**
     * Updates aggregated data structures based on the log entry.
     * This allows O(1) query performance for endpoint calls.
     */
    private void updateAggregates(LogEntry entry) {
        switch (entry.event()) {
            case LOGIN_SUCCESS:
                loginStatsByUser
                        .computeIfAbsent(entry.user(), k -> new LoginStatsHolder())
                        .incrementSuccess();
                break;

            case LOGIN_FAILURE:
                // Track by user
                loginStatsByUser
                        .computeIfAbsent(entry.user(), k -> new LoginStatsHolder())
                        .incrementFailure();

                // Track by IP for suspicious activity detection
                loginFailuresByIp
                        .computeIfAbsent(entry.ip(), k -> new ConcurrentLinkedQueue<>())
                        .add(entry.timestamp());
                break;

            case FILE_UPLOAD:
                uploadCountsByUser
                        .computeIfAbsent(entry.user(), k -> new AtomicInteger(0))
                        .incrementAndGet();
                break;

            case FILE_DOWNLOAD:
            case LOGOUT:
                // No aggregation needed for these events currently
                break;
        }
    }

    /**
     * Retrieves login statistics for all users from pre-aggregated data.
     * Returns a map of username to LoginStats containing success and failure counts.
     *
     * @return Map of user to their login statistics, empty if no login events processed
     */
    public Map<String, LoginStats> getLoginCounts() {
        logger.debug("Generating login counts from aggregated data");

        if (loginStatsByUser.isEmpty()) {
            logger.debug("No login statistics available - loginStatsByUser is empty");
            return new HashMap<>();
        }

        Map<String, LoginStats> result = new HashMap<>();

        for (Map.Entry<String, LoginStatsHolder> entry : loginStatsByUser.entrySet()) {
            String user = entry.getKey();
            LoginStatsHolder holder = entry.getValue();
            result.put(user, new LoginStats(
                    user,
                    holder.getSuccessCount(),
                    holder.getFailureCount()
            ));
        }

        logger.info("Returning login stats for {} users", result.size());
        return result;
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