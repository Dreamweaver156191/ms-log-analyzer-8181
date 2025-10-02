package za.co.frei.logfile.analyzer.model;

import java.time.Instant;
import java.util.List;

/**
 * Represents login statistics for a user, including success/failure counts,
 * separate lists of IPs used for successful vs failed login attempts,
 * and timestamps of last successful and failed logins.
 */
public record LoginStats(
        String user,
        int success,
        int failure,
        List<String> successIps,      // IPs used for successful logins
        List<String> failureIps,      // IPs used for failed logins
        Instant lastSuccessTimestamp, // Timestamp of last successful login (null if none)
        Instant lastFailureTimestamp  // Timestamp of last failed login (null if none)
) {
    /**
     * Validates that user is not null/blank, counts are non-negative, and IP lists are not null.
     * Timestamps can be null if no events of that type occurred.
     */
    public LoginStats {
        if (user == null || user.isBlank()) {
            throw new IllegalArgumentException("User cannot be null or blank");
        }
        if (success < 0) {
            throw new IllegalArgumentException("Success count cannot be negative");
        }
        if (failure < 0) {
            throw new IllegalArgumentException("Failure count cannot be negative");
        }
        if (successIps == null) {
            throw new IllegalArgumentException("Success IPs list cannot be null");
        }
        if (failureIps == null) {
            throw new IllegalArgumentException("Failure IPs list cannot be null");
        }
        // Create defensive copies and ensure immutability
        successIps = List.copyOf(successIps);
        failureIps = List.copyOf(failureIps);
    }
}