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
}