package za.co.frei.logfile.analyzer.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

public class LogEntryTest {

    @Test
    public void shouldCreateValidLogEntry() {
        Instant now = Instant.now();
        LogEntry entry = new LogEntry(now, "user1", EventType.LOGIN_SUCCESS, "192.168.1.1", null);

        assertEquals(now, entry.getTimestamp());
        assertEquals("user1", entry.getUser());
        assertEquals(EventType.LOGIN_SUCCESS, entry.getEvent());
        assertEquals("192.168.1.1", entry.getIp());
        assertNull(entry.getFile());
    }

    @Test
    public void shouldCreateLogEntryWithFile() {
        Instant now = Instant.now();
        LogEntry entry = new LogEntry(now, "user1", EventType.FILE_UPLOAD, "192.168.1.1", "test.dat");

        assertEquals("test.dat", entry.getFile());
    }

    @Test
    public void shouldSupportAllEventTypes() {
        Instant now = Instant.now();

        LogEntry loginSuccess = new LogEntry(now, "user1", EventType.LOGIN_SUCCESS, "192.168.1.1", null);
        assertEquals(EventType.LOGIN_SUCCESS, loginSuccess.getEvent());

        LogEntry loginFailure = new LogEntry(now, "user1", EventType.LOGIN_FAILURE, "192.168.1.1", null);
        assertEquals(EventType.LOGIN_FAILURE, loginFailure.getEvent());

        LogEntry fileUpload = new LogEntry(now, "user1", EventType.FILE_UPLOAD, "192.168.1.1", "file.dat");
        assertEquals(EventType.FILE_UPLOAD, fileUpload.getEvent());

        LogEntry fileDownload = new LogEntry(now, "user1", EventType.FILE_DOWNLOAD, "192.168.1.1", "file.dat");
        assertEquals(EventType.FILE_DOWNLOAD, fileDownload.getEvent());

        LogEntry logout = new LogEntry(now, "user1", EventType.LOGOUT, "192.168.1.1", null);
        assertEquals(EventType.LOGOUT, logout.getEvent());
    }

    @Test
    public void shouldRejectNullTimestamp() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LogEntry(null, "user1", EventType.LOGIN_SUCCESS, "192.168.1.1", null);
        });
        assertEquals("Timestamp cannot be null", exception.getMessage());
    }

    @Test
    public void shouldRejectNullUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LogEntry(Instant.now(), null, EventType.LOGIN_SUCCESS, "192.168.1.1", null);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectBlankUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LogEntry(Instant.now(), "   ", EventType.LOGIN_SUCCESS, "192.168.1.1", null);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectEmptyUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LogEntry(Instant.now(), "", EventType.LOGIN_SUCCESS, "192.168.1.1", null);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectNullEvent() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LogEntry(Instant.now(), "user1", null, "192.168.1.1", null);
        });
        assertEquals("Event type cannot be null", exception.getMessage());
    }

    @Test
    public void shouldRejectNullIp() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LogEntry(Instant.now(), "user1", EventType.LOGIN_SUCCESS, null, null);
        });
        assertEquals("IP address cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectBlankIp() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LogEntry(Instant.now(), "user1", EventType.LOGIN_SUCCESS, "", null);
        });
        assertEquals("IP address cannot be null or blank", exception.getMessage());
    }

}