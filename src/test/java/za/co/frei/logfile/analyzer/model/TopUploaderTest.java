package za.co.frei.logfile.analyzer.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TopUploaderTest {

    @Test
    public void shouldCreateValidTopUploader() {
        TopUploader uploader = new TopUploader("user1", 10);
        assertEquals("user1", uploader.user());
        assertEquals(10, uploader.uploads());
    }

    @Test
    public void shouldAllowZeroUploads() {
        TopUploader uploader = new TopUploader("user1", 0);
        assertEquals(0, uploader.uploads());
    }

    @Test
    public void shouldRejectNullUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new TopUploader(null, 10);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectBlankUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new TopUploader("   ", 10);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectEmptyUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new TopUploader("", 10);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectNegativeUploads() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new TopUploader("user1", -1);
        });
        assertEquals("Uploads count cannot be negative", exception.getMessage());
    }

    @Test
    public void shouldSupportLargeUploadCounts() {
        TopUploader uploader = new TopUploader("user1", 999999);
        assertEquals(999999, uploader.uploads());
    }

    @Test
    public void shouldSupportUserNamesWithSpecialCharacters() {
        TopUploader uploader = new TopUploader("USER_001", 5);
        assertEquals("USER_001", uploader.user());
    }
}