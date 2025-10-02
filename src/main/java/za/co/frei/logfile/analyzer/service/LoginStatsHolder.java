package za.co.frei.logfile.analyzer.service;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.List;

/**
 * Thread-safe holder for login statistics.
 * Tracks success/failure counts, separate sets of IPs for each outcome,
 * and timestamps of last successful and failed logins.
 */
public class LoginStatsHolder {
    private final AtomicInteger successCount = new AtomicInteger(0);
    private final AtomicInteger failureCount = new AtomicInteger(0);

    // Thread-safe sets to track unique IPs for each login outcome
    private final Set<String> successIps = ConcurrentHashMap.newKeySet();
    private final Set<String> failureIps = ConcurrentHashMap.newKeySet();

    // Thread-safe references to track last timestamps
    private final AtomicReference<Instant> lastSuccessTimestamp = new AtomicReference<>(null);
    private final AtomicReference<Instant> lastFailureTimestamp = new AtomicReference<>(null);

    public void incrementSuccess() {
        successCount.incrementAndGet();
    }

    public void incrementFailure() {
        failureCount.incrementAndGet();
    }

    public void addSuccessIp(String ip) {
        if (ip != null && !ip.isBlank() && !"0.0.0.0".equals(ip)) {
            successIps.add(ip);
        }
    }

    public void addFailureIp(String ip) {
        if (ip != null && !ip.isBlank() && !"0.0.0.0".equals(ip)) {
            failureIps.add(ip);
        }
    }

    public void updateSuccessTimestamp(Instant timestamp) {
        if (timestamp != null) {
            lastSuccessTimestamp.updateAndGet(current ->
                    current == null || timestamp.isAfter(current) ? timestamp : current
            );
        }
    }

    public void updateFailureTimestamp(Instant timestamp) {
        if (timestamp != null) {
            lastFailureTimestamp.updateAndGet(current ->
                    current == null || timestamp.isAfter(current) ? timestamp : current
            );
        }
    }

    public int getSuccessCount() {
        return successCount.get();
    }

    public int getFailureCount() {
        return failureCount.get();
    }

    public List<String> getSuccessIps() {
        // Return sorted list for consistent ordering
        return successIps.stream().sorted().toList();
    }

    public List<String> getFailureIps() {
        // Return sorted list for consistent ordering
        return failureIps.stream().sorted().toList();
    }

    public Instant getLastSuccessTimestamp() {
        return lastSuccessTimestamp.get();
    }

    public Instant getLastFailureTimestamp() {
        return lastFailureTimestamp.get();
    }
}