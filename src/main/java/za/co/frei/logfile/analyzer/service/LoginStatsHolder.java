package za.co.frei.logfile.analyzer.model;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.List;

/**
 * Thread-safe holder for login statistics.
 * Tracks success/failure counts and separate sets of IPs for each outcome.
 */
public class LoginStatsHolder {
    private final AtomicInteger successCount = new AtomicInteger(0);
    private final AtomicInteger failureCount = new AtomicInteger(0);

    // Thread-safe sets to track unique IPs for each login outcome
    private final Set<String> successIps = ConcurrentHashMap.newKeySet();
    private final Set<String> failureIps = ConcurrentHashMap.newKeySet();

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
}