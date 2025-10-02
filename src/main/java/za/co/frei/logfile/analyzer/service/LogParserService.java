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
import java.util.stream.Collectors;

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

                    // Parse event-specific fields based on event type
                    if (event == EventType.LOGIN_SUCCESS || event == EventType.LOGIN_FAILURE) {
                        // Login events MUST have IP
                        if (parts.length > 3 && parts[3].startsWith("IP=")) {
                            ip = parts[3].substring(3).trim();
                        } else {
                            logger.warn("Missing or invalid IP for login event at line {}: {}", lineNumber, line);
                            errors.incrementAndGet();
                            continue;
                        }
                    } else if (event == EventType.FILE_UPLOAD) {
                        // FILE_UPLOAD can have: IP + FILE, or just FILE
                        if (parts.length == 4 && parts[3].startsWith("FILE=")) {
                            // Case: FILE only
                            file = parts[3].substring(5).trim();
                            ip = "0.0.0.0"; // default placeholder
                        } else if (parts.length > 4 && parts[3].startsWith("IP=")) {
                            // Case: IP + FILE
                            ip = parts[3].substring(3).trim();
                            if (parts[4].startsWith("FILE=")) {
                                file = parts[4].substring(5).trim();
                            } else {
                                logger.warn("Invalid FILE field at line {}: {}", lineNumber, line);
                                errors.incrementAndGet();
                                continue;
                            }
                        } else {
                            logger.warn("Missing FILE field for FILE_UPLOAD at line {}: {}", lineNumber, line);
                            errors.incrementAndGet();
                            continue;
                        }
                    } else if (event == EventType.FILE_DOWNLOAD) {
                        // FILE_DOWNLOAD: only has FILE field, no IP
                        if (parts.length == 4 && parts[3].startsWith("FILE=")) {
                            file = parts[3].substring(5).trim();
                            ip = "0.0.0.0"; // default placeholder
                        } else {
                            logger.warn("Missing or invalid FILE field for FILE_DOWNLOAD at line {}: {}", lineNumber, line);
                            errors.incrementAndGet();
                            continue;
                        }
                    } else if (event == EventType.LOGOUT) {
                        // LOGOUT: no additional fields expected
                        if (parts.length > 3 && !parts[3].trim().isEmpty()) {
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
                LoginStatsHolder successHolder = loginStatsByUser
                        .computeIfAbsent(entry.user(), k -> new LoginStatsHolder());
                successHolder.incrementSuccess();
                successHolder.addSuccessIp(entry.ip());
                successHolder.updateSuccessTimestamp(entry.timestamp());
                break;

            case LOGIN_FAILURE:
                // Track by user
                LoginStatsHolder failureHolder = loginStatsByUser
                        .computeIfAbsent(entry.user(), k -> new LoginStatsHolder());
                failureHolder.incrementFailure();
                failureHolder.addFailureIp(entry.ip());
                failureHolder.updateFailureTimestamp(entry.timestamp());

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
     * Returns a map of username to LoginStats containing success/failure counts,
     * separate IP lists, and timestamps.
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
                    holder.getFailureCount(),
                    holder.getSuccessIps(),           // IPs used for successful logins
                    holder.getFailureIps(),           // IPs used for failed logins
                    holder.getLastSuccessTimestamp(), // Last successful login timestamp
                    holder.getLastFailureTimestamp()  // Last failed login timestamp
            ));
        }

        logger.info("Returning login stats for {} users", result.size());
        return result;
    }

    public List<TopUploader> getTopUploaders(int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("Limit must be positive");
        }

        logger.debug("Getting top {} uploaders from aggregated data", limit);

        if (uploadCountsByUser.isEmpty()) {
            logger.debug("No upload data available");
            return List.of();
        }

        List<TopUploader> result = uploadCountsByUser.entrySet().stream()
                .map(e -> new TopUploader(e.getKey(), e.getValue().get()))
                .sorted(Comparator.comparingInt(TopUploader::uploads).reversed())
                .limit(limit)
                .toList();

        logger.info("Returning top {} uploaders, found {} users with uploads",
                limit, uploadCountsByUser.size());
        return result;
    }

    /**
     * Gets total count of unique users who have uploaded files.
     */
    public int getTotalUsersWithUploads() {
        return uploadCountsByUser.size();
    }

    public List<SuspiciousWindow> getSuspiciousActivity(List<LogEntry> entries) {
        // TODO: Implement logic to detect suspicious LOGIN_FAILURE activity
        return null;
    }
}