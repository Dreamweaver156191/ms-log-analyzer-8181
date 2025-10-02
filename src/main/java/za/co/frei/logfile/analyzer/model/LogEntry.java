package za.co.frei.logfile.analyzer.model;

import lombok.Data;
import java.time.Instant;

@Data
public class LogEntry {
    private final Instant timestamp;
    private final String user;
    private final EventType event;
    private final String ip;
    private final String file;

    public LogEntry(Instant timestamp, String user, EventType event, String ip, String file) {
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

        this.timestamp = timestamp;
        this.user = user;
        this.event = event;
        this.ip = ip;
        this.file = file;
    }
}