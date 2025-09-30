package za.co.frei.logfile.analyzer.model;

import java.time.Instant;
import java.util.List;

public record SuspiciousWindow(String ip, Instant start, Instant end, int failures, List<Instant> timestamps) {
    // TODO: Add constructor validation (e.g., start <= end, failures > 3, non-null ip)
}