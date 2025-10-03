package za.co.frei.logfile.analyzer.exception;

/**
 * Exception thrown when export operations fail.
 * This includes JSON serialization errors, file generation issues,
 * or any other failures during the export process.
 */
public class ExportException extends RuntimeException {

    public ExportException(String message) {
        super(message);
    }

    public ExportException(String message, Throwable cause) {
        super(message, cause);
    }
}