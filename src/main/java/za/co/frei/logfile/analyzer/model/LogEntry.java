package za.co.frei.logfile.analyzer.model;

import java.time.Instant;

public record LogEntry(Instant timestamp, String user, EventType event, String ip, String file) {
    public LogEntry {
        if (timestamp == null) {
            throw new IllegalArgumentException("Timestamp cannot be null");
        }
        if (user == null || user.trim().isEmpty()) {
            throw new IllegalArgumentException("User cannot be null or blank");
        }
        if (event == null) {
            throw new IllegalArgumentException("Event type cannot be null");
        }
        if (ip == null || ip.trim().isEmpty()) {
            throw new IllegalArgumentException("IP address cannot be null or blank");
        }

    }
}