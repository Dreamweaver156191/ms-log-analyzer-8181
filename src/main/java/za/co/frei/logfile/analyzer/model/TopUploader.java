package za.co.frei.logfile.analyzer.model;

public record TopUploader(String user, int uploads) {

    public TopUploader {
        if (user == null || user.isBlank()) {
            throw new IllegalArgumentException("User cannot be null or blank");
        }
        if (uploads < 0) {
            throw new IllegalArgumentException("Uploads count cannot be negative");
        }
    }
}