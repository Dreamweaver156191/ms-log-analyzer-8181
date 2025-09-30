package za.co.frei.logfile.analyzer.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class SuspiciousWindowTest {

    @Test
    public void shouldCreateValidSuspiciousWindow() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.parse("2025-09-15T10:00:00Z"),
                Instant.parse("2025-09-15T10:01:00Z"),
                Instant.parse("2025-09-15T10:02:00Z"),
                Instant.parse("2025-09-15T10:03:00Z")
        );

        SuspiciousWindow window = new SuspiciousWindow("192.168.1.1", start, end, 4, timestamps);
        assertEquals("192.168.1.1", window.ip());
        assertEquals(start, window.start());
        assertEquals(end, window.end());
        assertEquals(4, window.failures());
        assertEquals(4, window.timestamps().size());
    }

    @Test
    public void shouldAllowStartEqualsEnd() {
        Instant time = Instant.parse("2025-09-15T10:00:00Z");
        List<Instant> timestamps = Arrays.asList(time, time, time, time);

        SuspiciousWindow window = new SuspiciousWindow("192.168.1.1", time, time, 4, timestamps);
        assertEquals(time, window.start());
        assertEquals(time, window.end());
    }

    @Test
    public void shouldRejectNullIp() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow(null, start, end, 4, timestamps);
        });
        assertEquals("IP cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectBlankIp() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("  ", start, end, 4, timestamps);
        });
        assertEquals("IP cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectNullStart() {
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", null, end, 4, timestamps);
        });
        assertEquals("Start time cannot be null", exception.getMessage());
    }

    @Test
    public void shouldRejectNullEnd() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, null, 4, timestamps);
        });
        assertEquals("End time cannot be null", exception.getMessage());
    }

    @Test
    public void shouldRejectStartAfterEnd() {
        Instant start = Instant.parse("2025-09-15T10:05:00Z");
        Instant end = Instant.parse("2025-09-15T10:00:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, timestamps);
        });
        assertEquals("Start time must be before or equal to end time", exception.getMessage());
    }

    @Test
    public void shouldRejectThreeFailures() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now()
        );

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 3, timestamps);
        });
        assertEquals("Failures must be more than 3 for suspicious activity", exception.getMessage());
    }

    @Test
    public void shouldRejectLessThanThreeFailures() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(Instant.now(), Instant.now());

        assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 2, timestamps);
        });
    }

    @Test
    public void shouldRejectNullTimestamps() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, null);
        });
        assertEquals("Timestamps cannot be null or empty", exception.getMessage());
    }

    @Test
    public void shouldRejectEmptyTimestamps() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, Collections.emptyList());
        });
        assertEquals("Timestamps cannot be null or empty", exception.getMessage());
    }

    @Test
    public void shouldRejectMismatchedTimestampCount() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now()
        );

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, timestamps);
        });
        assertEquals("Number of timestamps must match failure count", exception.getMessage());
    }

    @Test
    public void shouldHandleFiveFailures() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.parse("2025-09-15T10:00:00Z"),
                Instant.parse("2025-09-15T10:01:00Z"),
                Instant.parse("2025-09-15T10:02:00Z"),
                Instant.parse("2025-09-15T10:03:00Z"),
                Instant.parse("2025-09-15T10:04:00Z")
        );

        SuspiciousWindow window = new SuspiciousWindow("192.168.1.1", start, end, 5, timestamps);
        assertEquals(5, window.failures());
    }
}