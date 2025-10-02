package za.co.frei.logfile.analyzer.model;

import java.util.List;

public record UploadResponse(
        String message,
        List<String> filesProcessed,
        List<String> failedFiles,
        int processed,
        int totalStored,
        int errors
) {
    public UploadResponse {
        // Defensive copying for immutability
        filesProcessed = filesProcessed != null ? List.copyOf(filesProcessed) : List.of();
        failedFiles = failedFiles != null ? List.copyOf(failedFiles) : List.of();

        if (processed < 0) {
            throw new IllegalArgumentException("Processed count cannot be negative");
        }
        if (totalStored < 0) {
            throw new IllegalArgumentException("Total stored count cannot be negative");
        }
        if (errors < 0) {
            throw new IllegalArgumentException("Errors count cannot be negative");
        }
    }
}