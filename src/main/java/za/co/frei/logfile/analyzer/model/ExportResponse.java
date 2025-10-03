package za.co.frei.logfile.analyzer.model;

import java.util.List;
import java.util.Map;

/**
 * Response model for exporting complete log analysis results.
 * Contains all aggregated statistics and analysis data in a structured format
 * suitable for JSON serialization and external consumption.
 */
public record ExportResponse(
        String exportTimestamp,
        int totalEntriesStored,
        Map<String, LoginStats> loginStatistics,
        List<TopUploader> topUploaders,
        List<SuspiciousWindow> suspiciousActivity
) {
    public ExportResponse {
        if (exportTimestamp == null || exportTimestamp.isBlank()) {
            throw new IllegalArgumentException("Export timestamp cannot be null or blank");
        }
        if (totalEntriesStored < 0) {
            throw new IllegalArgumentException("Total entries stored cannot be negative");
        }

        // Defensive copying for immutability
        loginStatistics = loginStatistics != null ? Map.copyOf(loginStatistics) : Map.of();
        topUploaders = topUploaders != null ? List.copyOf(topUploaders) : List.of();
        suspiciousActivity = suspiciousActivity != null ? List.copyOf(suspiciousActivity) : List.of();
    }
}