package za.co.frei.logfile.analyzer.service;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe holder for login statistics.
 * Used internally by LogParserService for aggregating login counts.
 */
public class LoginStatsHolder {
    private final AtomicInteger successCount = new AtomicInteger(0);
    private final AtomicInteger failureCount = new AtomicInteger(0);

    public void incrementSuccess() {
        successCount.incrementAndGet();
    }

    public void incrementFailure() {
        failureCount.incrementAndGet();
    }

    public int getSuccessCount() {
        return successCount.get();
    }

    public int getFailureCount() {
        return failureCount.get();
    }
}