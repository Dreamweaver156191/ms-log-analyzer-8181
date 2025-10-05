package za.co.frei.logfile.analyzer.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import za.co.frei.logfile.analyzer.exception.FileProcessingException;
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

/**
 * Service responsible for parsing log files and maintaining aggregated statistics.
 * <p>
 * This service provides core functionality for:
 * <ul>
 *   <li>Parsing log files in pipe-delimited format</li>
 *   <li>Storing log entries in thread-safe, in-memory data structures</li>
 *   <li>Pre-aggregating statistics during parsing for O(1) query performance</li>
 *   <li>Detecting suspicious login activity using sliding window algorithm</li>
 *   <li>Providing thread-safe access to aggregated data</li>
 * </ul>
 * <p>
 * <strong>Thread Safety:</strong>
 * All data structures are thread-safe, allowing concurrent file uploads and queries.
 * Uses {@link ConcurrentLinkedQueue} for entry storage, {@link ConcurrentHashMap} for
 * aggregated data, and {@link AtomicInteger} for counters.
 * <p>
 * <strong>Performance Characteristics:</strong>
 * <ul>
 *   <li>Parsing: O(n) where n is the number of log lines</li>
 *   <li>Login counts query: O(1) - pre-aggregated</li>
 *   <li>Top uploaders query: O(u log u) where u is number of unique uploaders</li>
 *   <li>Suspicious activity detection: O(i * f) where i is IPs with failures, f is failures per IP</li>
 * </ul>
 * <p>
 * <strong>Expected Log Format:</strong>
 * <pre>
 * timestamp | username | event_type | event_specific_fields
 *
 * Examples:
 * 2024-01-15T10:30:00Z | alice | LOGIN_SUCCESS | IP=192.168.1.100
 * 2024-01-15T10:31:00Z | bob | FILE_UPLOAD | IP=192.168.1.101 | FILE=report.pdf
 * </pre>
 *
 * @author Your Name
 * @version 1.0
 * @since 2025-01-15
 * @see LogEntry
 * @see LoginStats
 * @see SuspiciousWindow
 */
@Service
public class LogParserService {

    private static final Logger logger = LoggerFactory.getLogger(LogParserService.class);

    /**
     * Internal record for tracking login failure events with timestamp and user information.
     * <p>
     * Used for suspicious activity detection to maintain both the time of the failure
     * and which user account was targeted.
     *
     * @param timestamp the instant when the login failure occurred
     * @param user the username that was attempted in the failed login
     */
    private record LoginFailureEvent(Instant timestamp, String user) {}

    /**
     * Thread-safe queue storing all parsed log entries.
     * <p>
     * Uses {@link ConcurrentLinkedQueue} for lock-free thread safety.
     * This queue maintains the complete history of parsed entries for potential
     * detailed analysis or re-processing.
     */
    private final ConcurrentLinkedQueue<LogEntry> storedEntries = new ConcurrentLinkedQueue<>();

    /**
     * Thread-safe map of pre-aggregated login statistics per user.
     * <p>
     * Key: username (String)
     * Value: {@link LoginStatsHolder} containing success/failure counts, IPs, and timestamps
     * <p>
     * Maintained during parsing for O(1) query performance on the login counts endpoint.
     */
    private final ConcurrentHashMap<String, LoginStatsHolder> loginStatsByUser = new ConcurrentHashMap<>();

    /**
     * Thread-safe map of file upload counts per user.
     * <p>
     * Key: username (String)
     * Value: {@link AtomicInteger} containing total FILE_UPLOAD event count
     * <p>
     * Maintained during parsing for efficient top uploaders queries.
     */
    private final ConcurrentHashMap<String, AtomicInteger> uploadCountsByUser = new ConcurrentHashMap<>();

    /**
     * Thread-safe map of login failures grouped by IP address.
     * <p>
     * Key: IP address (String)
     * Value: Queue of {@link LoginFailureEvent} containing timestamp and user for each failure
     * <p>
     * Used for suspicious activity detection via sliding window algorithm.
     * Maintains chronological order of failures per IP for pattern detection.
     */
    private final ConcurrentHashMap<String, ConcurrentLinkedQueue<LoginFailureEvent>> loginFailuresByIp = new ConcurrentHashMap<>();

    /**
     * Thread-safe counter for tracking parse errors.
     * <p>
     * Incremented when log lines cannot be parsed due to format errors,
     * invalid timestamps, or other parsing failures.
     */
    private final AtomicInteger errors = new AtomicInteger(0);

    /**
     * Retrieves an immutable snapshot of all stored log entries.
     * <p>
     * Creates a defensive copy to prevent external modification of the internal queue.
     * Thread-safe for concurrent access.
     *
     * @return immutable list of all log entries, empty list if no entries stored
     */
    public List<LogEntry> getStoredEntries() {
        return List.copyOf(storedEntries);
    }

    /**
     * Retrieves a snapshot of login statistics by user.
     * <p>
     * Protected visibility for testing purposes. Creates a defensive copy
     * of the internal concurrent map.
     *
     * @return map of username to LoginStatsHolder, empty map if no login data
     */
    protected Map<String, LoginStatsHolder> getLoginStatsByUser() {
        return new HashMap<>(loginStatsByUser);
    }

    /**
     * Retrieves a snapshot of upload counts by user.
     * <p>
     * Protected visibility for testing purposes. Creates a defensive copy
     * of the internal concurrent map.
     *
     * @return map of username to AtomicInteger upload count, empty map if no upload data
     */
    protected Map<String, AtomicInteger> getUploadCountsByUser() {
        return new HashMap<>(uploadCountsByUser);
    }

    /**
     * Retrieves a snapshot of login failures grouped by IP.
     * <p>
     * Protected visibility for testing purposes. Creates a defensive copy
     * of the internal concurrent map.
     *
     * @return map of IP address to queue of login failure events, empty map if no failures
     */
    protected Map<String, ConcurrentLinkedQueue<LoginFailureEvent>> getLoginFailuresByIp() {
        return new HashMap<>(loginFailuresByIp);
    }

    /**
     * Clears all stored data and resets statistics.
     * <p>
     * Synchronized to ensure atomic clearing of all data structures.
     * Useful for testing or resetting the service state.
     * <p>
     * <strong>Warning:</strong> This operation is destructive and cannot be undone.
     */
    public synchronized void clearStoredEntries() {
        storedEntries.clear();
        errors.set(0);
        loginStatsByUser.clear();
        uploadCountsByUser.clear();
        loginFailuresByIp.clear();
    }

    /**
     * Returns the total number of stored log entries.
     * <p>
     * Thread-safe operation on the concurrent queue.
     *
     * @return count of stored entries
     */
    public int getStoredEntryCount() {
        return storedEntries.size();
    }

    /**
     * Adds a log entry to the stored entries queue.
     * <p>
     * Protected visibility for testing purposes. Thread-safe operation.
     *
     * @param entry the log entry to add
     */
    protected void addStoredEntry(LogEntry entry) {
        storedEntries.add(entry);
    }

    /**
     * Returns parsing result summary including error counts and status.
     * <p>
     * Provides a comprehensive view of the parsing operation results.
     *
     * @return map containing errors, processed count, totalStored, and HTTP status code
     */
    public Map<String, Object> getParseResult() {
        return Map.of(
                "errors", errors.get(),
                "processed", storedEntries.size() + errors.get(),
                "totalStored", storedEntries.size(),
                "status", errors.get() == 0 ? 201 : 206
        );
    }

    /**
     * Parses a log file from an input stream and stores entries in memory.
     * <p>
     * This method performs line-by-line parsing of log files in the expected format:
     * {@code timestamp | user | event | event_specific_fields}
     * <p>
     * <strong>Parsing Behavior:</strong>
     * <ul>
     *   <li>Invalid lines are logged and counted but do not fail the entire parse</li>
     *   <li>Empty lines are silently skipped</li>
     *   <li>Statistics are pre-aggregated during parsing for query performance</li>
     *   <li>Progress is logged every 500 lines for large files</li>
     * </ul>
     * <p>
     * <strong>Event Type Requirements:</strong>
     * <ul>
     *   <li>LOGIN_SUCCESS, LOGIN_FAILURE: Require IP field</li>
     *   <li>FILE_UPLOAD: Requires FILE field, IP is optional</li>
     *   <li>FILE_DOWNLOAD: Requires FILE field</li>
     *   <li>LOGOUT: No additional fields</li>
     * </ul>
     * <p>
     * <strong>Thread Safety:</strong>
     * Multiple threads can call this method concurrently to parse different files.
     * All data structures are thread-safe.
     *
     * @param inputStream the input stream containing log file data
     * @return list of successfully parsed log entries from this specific file
     * @throws FileProcessingException if an I/O error occurs while reading the stream
     * @see LogEntry
     * @see EventType
     */
    public List<LogEntry> parseLog(InputStream inputStream) {
        List<LogEntry> entries = new ArrayList<>();
        Map<EventType, Integer> eventCounts = new HashMap<>();
        logger.info("Starting log parsing from InputStream");

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;

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
                            logger.warn("Missing or invalid IP for login event at line {}: {}", lineNumber, line);
                            errors.incrementAndGet();
                            continue;
                        }
                    } else if (event == EventType.FILE_UPLOAD) {
                        if (parts.length == 4 && parts[3].startsWith("FILE=")) {
                            file = parts[3].substring(5).trim();
                            ip = "0.0.0.0";
                        } else if (parts.length > 4 && parts[3].startsWith("IP=")) {
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
                        if (parts.length == 4 && parts[3].startsWith("FILE=")) {
                            file = parts[3].substring(5).trim();
                            ip = "0.0.0.0";
                        } else {
                            logger.warn("Missing or invalid FILE field for FILE_DOWNLOAD at line {}: {}", lineNumber, line);
                            errors.incrementAndGet();
                            continue;
                        }
                    } else if (event == EventType.LOGOUT) {
                        if (parts.length > 3 && !parts[3].trim().isEmpty()) {
                            logger.warn("Unexpected extra field for LOGOUT at line {}: {}", lineNumber, line);
                            errors.incrementAndGet();
                            continue;
                        }
                        ip = "0.0.0.0";
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
            throw new FileProcessingException("Error parsing log file", e);
        }
        return entries;
    }

    /**
     * Updates aggregated statistics based on a parsed log entry.
     * <p>
     * This method is called for each successfully parsed entry during the parsing process.
     * It maintains pre-aggregated data structures for O(1) query performance on endpoints.
     * <p>
     * <strong>Updates performed based on event type:</strong>
     * <ul>
     *   <li>LOGIN_SUCCESS: Increments success count, adds IP to success list, updates timestamp</li>
     *   <li>LOGIN_FAILURE: Increments failure count, adds IP to failure list, updates timestamp, tracks for suspicious activity</li>
     *   <li>FILE_UPLOAD: Increments upload count for the user</li>
     *   <li>FILE_DOWNLOAD, LOGOUT: No aggregation (can be extended if needed)</li>
     * </ul>
     * <p>
     * Thread-safe through use of concurrent data structures and atomic operations.
     *
     * @param entry the log entry to aggregate into statistics
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
                LoginStatsHolder failureHolder = loginStatsByUser
                        .computeIfAbsent(entry.user(), k -> new LoginStatsHolder());
                failureHolder.incrementFailure();
                failureHolder.addFailureIp(entry.ip());
                failureHolder.updateFailureTimestamp(entry.timestamp());

                loginFailuresByIp
                        .computeIfAbsent(entry.ip(), k -> new ConcurrentLinkedQueue<>())
                        .add(new LoginFailureEvent(entry.timestamp(), entry.user()));
                break;

            case FILE_UPLOAD:
                uploadCountsByUser
                        .computeIfAbsent(entry.user(), k -> new AtomicInteger(0))
                        .incrementAndGet();
                break;

            case FILE_DOWNLOAD:
            case LOGOUT:
                break;
        }
    }

    /**
     * Retrieves login statistics for all users from pre-aggregated data.
     * <p>
     * Returns a comprehensive map of username to {@link LoginStats} containing:
     * <ul>
     *   <li>Total successful login attempts</li>
     *   <li>Total failed login attempts</li>
     *   <li>List of unique IP addresses used for successful logins</li>
     *   <li>List of unique IP addresses used for failed logins</li>
     *   <li>Timestamp of most recent successful login (null if none)</li>
     *   <li>Timestamp of most recent failed login (null if none)</li>
     * </ul>
     * <p>
     * <strong>Performance:</strong> O(1) lookup time due to pre-aggregation during parsing.
     * <p>
     * Thread-safe operation returning a new map with immutable LoginStats objects.
     *
     * @return map of username to login statistics, empty map if no login events processed
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
                    holder.getSuccessIps(),
                    holder.getFailureIps(),
                    holder.getLastSuccessTimestamp(),
                    holder.getLastFailureTimestamp()
            ));
        }

        logger.info("Returning login stats for {} users", result.size());
        return result;
    }

    /**
     * Retrieves the top N users by file upload count.
     * <p>
     * Returns users ranked in descending order by the number of FILE_UPLOAD events.
     * Uses pre-aggregated upload counts for efficient querying.
     * <p>
     * <strong>Performance:</strong>
     * <ul>
     *   <li>O(1) for accessing upload counts</li>
     *   <li>O(n log n) for sorting where n is the number of users with uploads</li>
     *   <li>O(k) for limiting results where k is the limit parameter</li>
     * </ul>
     * <p>
     * Thread-safe operation creating a new sorted list.
     *
     * @param limit maximum number of top uploaders to return (must be positive)
     * @return list of TopUploader objects sorted by upload count descending, empty list if no upload data
     * @throws IllegalArgumentException if limit is not positive
     */
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
     * Returns the total count of unique users who have uploaded files.
     *
     * @return number of unique users with at least one FILE_UPLOAD event
     */
    public int getTotalUsersWithUploads() {
        return uploadCountsByUser.size();
    }

    /**
     * Detects suspicious login activity using a sliding window algorithm.
     * <p>
     * Identifies IP addresses with more than 3 LOGIN_FAILURE attempts within any
     * 5-minute window. This pattern is commonly associated with brute-force password
     * attacks or credential stuffing attempts.
     * <p>
     * <strong>Algorithm:</strong>
     * <ol>
     *   <li>Groups all login failures by IP address</li>
     *   <li>For each IP with >3 failures, sorts events chronologically</li>
     *   <li>Uses sliding window to find any 5-minute period with >3 failures</li>
     *   <li>Records the window start, end, failure count, timestamps, and targeted users</li>
     * </ol>
     * <p>
     * <strong>Performance:</strong>
     * <ul>
     *   <li>O(i * f log f) where i is IPs with failures, f is failures per IP (for sorting)</li>
     *   <li>O(i * f²) worst case for sliding window detection</li>
     *   <li>In practice, very efficient as most IPs have few failures</li>
     * </ul>
     * <p>
     * <strong>Window Detection:</strong>
     * When multiple suspicious windows are detected for the same IP, only the first
     * window is reported to avoid overlapping detections. This prevents duplicate
     * alerts for continuous attack patterns.
     * <p>
     * Thread-safe operation creating new SuspiciousWindow objects.
     *
     * @return list of suspicious activity windows, empty list if no suspicious patterns detected
     * @see SuspiciousWindow
     */
    public List<SuspiciousWindow> getSuspiciousActivity() {
        logger.debug("Analyzing login failures for suspicious activity");

        logger.info("loginFailuresByIp contains {} IPs", loginFailuresByIp.size());
        for (Map.Entry<String, ConcurrentLinkedQueue<LoginFailureEvent>> entry : loginFailuresByIp.entrySet()) {
            logger.info("IP: {} has {} failure events", entry.getKey(), entry.getValue().size());
        }

        if (loginFailuresByIp.isEmpty()) {
            logger.debug("No login failure data available");
            return List.of();
        }

        List<SuspiciousWindow> suspiciousWindows = new ArrayList<>();
        final long FIVE_MINUTES_SECONDS = 300;

        for (Map.Entry<String, ConcurrentLinkedQueue<LoginFailureEvent>> entry : loginFailuresByIp.entrySet()) {
            String ip = entry.getKey();
            List<LoginFailureEvent> events = new ArrayList<>(entry.getValue());

            if (events.size() <= 3) {
                logger.debug("IP {} has only {} failures, skipping", ip, events.size());
                continue;
            }

            events.sort(Comparator.comparing(LoginFailureEvent::timestamp));

            logger.info("Analyzing IP {} with {} failures", ip, events.size());

            for (int i = 0; i < events.size(); i++) {
                Instant windowStart = events.get(i).timestamp();
                List<LoginFailureEvent> windowEvents = new ArrayList<>();
                windowEvents.add(events.get(i));

                for (int j = i + 1; j < events.size(); j++) {
                    LoginFailureEvent current = events.get(j);
                    long secondsDiff = current.timestamp().getEpochSecond() - windowStart.getEpochSecond();

                    logger.debug("Checking timestamp {} against window start {}, diff: {} seconds",
                            current.timestamp(), windowStart, secondsDiff);

                    if (secondsDiff <= FIVE_MINUTES_SECONDS) {
                        windowEvents.add(current);
                    } else {
                        break;
                    }
                }

                logger.debug("Window starting at {} contains {} failures", windowStart, windowEvents.size());

                if (windowEvents.size() > 3) {
                    Instant windowEnd = windowEvents.get(windowEvents.size() - 1).timestamp();

                    List<Instant> timestamps = windowEvents.stream()
                            .map(LoginFailureEvent::timestamp)
                            .toList();

                    List<String> users = windowEvents.stream()
                            .map(LoginFailureEvent::user)
                            .toList();

                    SuspiciousWindow window = new SuspiciousWindow(
                            ip,
                            windowStart,
                            windowEnd,
                            windowEvents.size(),
                            timestamps,
                            users
                    );

                    suspiciousWindows.add(window);

                    logger.info("Detected suspicious activity from IP {}: {} failures between {} and {}",
                            ip, windowEvents.size(), windowStart, windowEnd);

                    i = i + windowEvents.size() - 1;
                    break;
                }
            }
        }

        logger.info("Found {} suspicious activity window(s)", suspiciousWindows.size());
        return suspiciousWindows;
    }
}