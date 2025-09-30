package za.co.frei.logfile.analyzer.model;

public record LoginStats(String user, int success, int failure) {
    // TODO: Add constructor validation (e.g., user not null, counts non-negative)
}