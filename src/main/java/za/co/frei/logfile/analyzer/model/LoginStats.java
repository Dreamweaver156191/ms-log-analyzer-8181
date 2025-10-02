package za.co.frei.logfile.analyzer.model;

import java.util.List;

/**
 * Represents login statistics for a user, including success/failure counts
 * and separate lists of IPs used for successful vs failed login attempts.
 */
public record LoginStats(
        String user,
        int success,
        int failure,
        List<String> successIps,  // IPs used for successful logins
        List<String> failureIps   // IPs used for failed logins
) {
    /**
     * Validates that user is not null/blank, counts are non-negative, and IP lists are not null.
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