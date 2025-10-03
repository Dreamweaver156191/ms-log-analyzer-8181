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
        List<String> users = Arrays.asList("user1", "user1", "user2", "user1");

        SuspiciousWindow window = new SuspiciousWindow("192.168.1.1", start, end, 4, timestamps, users);
        assertEquals("192.168.1.1", window.ip());
        assertEquals(start, window.start());
        assertEquals(end, window.end());
        assertEquals(4, window.failures());
        assertEquals(4, window.timestamps().size());
        assertEquals(4, window.users().size());
        assertEquals("user1", window.users().get(0));
    }

    @Test
    public void shouldAllowStartEqualsEnd() {
        Instant time = Instant.parse("2025-09-15T10:00:00Z");
        List<Instant> timestamps = Arrays.asList(time, time, time, time);
        List<String> users = Arrays.asList("user1", "user1", "user1", "user1");

        SuspiciousWindow window = new SuspiciousWindow("192.168.1.1", time, time, 4, timestamps, users);
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
        List<String> users = Arrays.asList("user1", "user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow(null, start, end, 4, timestamps, users);
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
        List<String> users = Arrays.asList("user1", "user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("  ", start, end, 4, timestamps, users);
        });
        assertEquals("IP cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectNullStart() {
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );
        List<String> users = Arrays.asList("user1", "user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", null, end, 4, timestamps, users);
        });
        assertEquals("Start time cannot be null", exception.getMessage());
    }

    @Test
    public void shouldRejectNullEnd() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );
        List<String> users = Arrays.asList("user1", "user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, null, 4, timestamps, users);
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
        List<String> users = Arrays.asList("user1", "user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, timestamps, users);
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
        List<String> users = Arrays.asList("user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 3, timestamps, users);
        });
        assertEquals("Failures must be more than 3 for suspicious activity", exception.getMessage());
    }

    @Test
    public void shouldRejectLessThanThreeFailures() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(Instant.now(), Instant.now());
        List<String> users = Arrays.asList("user1", "user1");

        assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 2, timestamps, users);
        });
    }

    @Test
    public void shouldRejectNullTimestamps() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<String> users = Arrays.asList("user1", "user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, null, users);
        });
        assertEquals("Timestamps cannot be null or empty", exception.getMessage());
    }

    @Test
    public void shouldRejectEmptyTimestamps() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<String> users = Arrays.asList("user1", "user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, Collections.emptyList(), users);
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
        List<String> users = Arrays.asList("user1", "user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, timestamps, users);
        });
        assertEquals("Number of timestamps must match failure count", exception.getMessage());
    }

    @Test
    public void shouldRejectNullUsers() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, timestamps, null);
        });
        assertEquals("Users cannot be null or empty", exception.getMessage());
    }

    @Test
    public void shouldRejectEmptyUsers() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, timestamps, Collections.emptyList());
        });
        assertEquals("Users cannot be null or empty", exception.getMessage());
    }

    @Test
    public void shouldRejectMismatchedUserCount() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:05:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.now(), Instant.now(), Instant.now(), Instant.now()
        );
        List<String> users = Arrays.asList("user1", "user1", "user1");

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new SuspiciousWindow("192.168.1.1", start, end, 4, timestamps, users);
        });
        assertEquals("Number of users must match failure count", exception.getMessage());
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
        List<String> users = Arrays.asList("user1", "user2", "user1", "user1", "user3");

        SuspiciousWindow window = new SuspiciousWindow("192.168.1.1", start, end, 5, timestamps, users);
        assertEquals(5, window.failures());
        assertEquals(5, window.users().size());
    }

    @Test
    public void shouldHandleMultipleUsersFromSameIp() {
        Instant start = Instant.parse("2025-09-15T10:00:00Z");
        Instant end = Instant.parse("2025-09-15T10:03:00Z");
        List<Instant> timestamps = Arrays.asList(
                Instant.parse("2025-09-15T10:00:00Z"),
                Instant.parse("2025-09-15T10:01:00Z"),
                Instant.parse("2025-09-15T10:02:00Z"),
                Instant.parse("2025-09-15T10:03:00Z")
        );
        List<String> users = Arrays.asList("alice", "bob", "alice", "charlie");

        SuspiciousWindow window = new SuspiciousWindow("192.168.1.100", start, end, 4, timestamps, users);
        assertEquals(4, window.failures());
        assertEquals(Arrays.asList("alice", "bob", "alice", "charlie"), window.users());
    }
}