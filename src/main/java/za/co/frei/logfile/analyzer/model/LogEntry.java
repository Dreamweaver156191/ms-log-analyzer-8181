package za.co.frei.logfile.analyzer.model;

import lombok.Data;

import java.time.Instant;

@Data
public class LogEntry {
    private Instant timestamp;
    private String user;
    private final EventType event; // Changed from String to EventType
    private final String ip;
    private String file;



    // TODO: Add validation logic for fields (e.g., non-null timestamp, valid event types)
    public LogEntry(Instant timestamp, String user, EventType event, String ip, String file) {
        this.timestamp = timestamp;
        this.user = user;
        this.event = event;
        this.ip = ip;
        this.file = file;
    }
}