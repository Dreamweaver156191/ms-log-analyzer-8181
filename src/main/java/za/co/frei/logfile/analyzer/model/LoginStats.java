package za.co.frei.logfile.analyzer.model;

public record LoginStats(String user, int success, int failure) {
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
    }
}