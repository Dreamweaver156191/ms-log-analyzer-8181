package za.co.frei.logfile.analyzer.model;

import java.time.Instant;
import java.util.List;

public record SuspiciousWindow(String ip, Instant start, Instant end, int failures, List<Instant> timestamps) {

    public SuspiciousWindow {
        if (ip == null || ip.isBlank()) {
            throw new IllegalArgumentException("IP cannot be null or blank");
        }
        if (start == null) {
            throw new IllegalArgumentException("Start time cannot be null");
        }
        if (end == null) {
            throw new IllegalArgumentException("End time cannot be null");
        }
        if (start.isAfter(end)) {
            throw new IllegalArgumentException("Start time must be before or equal to end time");
        }
        if (failures <= 3) {
            throw new IllegalArgumentException("Failures must be more than 3 for suspicious activity");
        }
        if (timestamps == null || timestamps.isEmpty()) {
            throw new IllegalArgumentException("Timestamps cannot be null or empty");
        }
        if (timestamps.size() != failures) {
            throw new IllegalArgumentException("Number of timestamps must match failure count");
        }
    }
}