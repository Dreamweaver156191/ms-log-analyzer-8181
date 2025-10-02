package za.co.frei.logfile.analyzer.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class LoginStatsTest {

    @Test
    public void shouldCreateValidLoginStats() {
        Instant now = Instant.now();
        LoginStats stats = new LoginStats("user1", 5, 2,
                List.of("192.168.1.1", "192.168.1.2"),
                List.of("192.168.1.3"),
                now,
                now.minusSeconds(60));
        assertEquals("user1", stats.user());
        assertEquals(5, stats.success());
        assertEquals(2, stats.failure());
        assertEquals(2, stats.successIps().size());
        assertEquals(1, stats.failureIps().size());
        assertEquals(now, stats.lastSuccessTimestamp());
        assertEquals(now.minusSeconds(60), stats.lastFailureTimestamp());
    }

    @Test
    public void shouldAllowZeroCounts() {
        LoginStats stats = new LoginStats("user1", 0, 0, List.of(), List.of(), null, null);
        assertEquals(0, stats.success());
        assertEquals(0, stats.failure());
        assertTrue(stats.successIps().isEmpty());
        assertTrue(stats.failureIps().isEmpty());
        assertNull(stats.lastSuccessTimestamp());
        assertNull(stats.lastFailureTimestamp());
    }

    @Test
    public void shouldRejectNullUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats(null, 5, 2, List.of("192.168.1.1"), List.of(), null, null);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectBlankUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("   ", 5, 2, List.of("192.168.1.1"), List.of(), null, null);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectEmptyUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("", 5, 2, List.of("192.168.1.1"), List.of(), null, null);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectNegativeSuccess() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", -1, 2, List.of("192.168.1.1"), List.of(), null, null);
        });
        assertEquals("Success count cannot be negative", exception.getMessage());
    }

    @Test
    public void shouldRejectNegativeFailure() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", 5, -1, List.of("192.168.1.1"), List.of(), null, null);
        });
        assertEquals("Failure count cannot be negative", exception.getMessage());
    }

    @Test
    public void shouldRejectBothNegative() {
        assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", -5, -2, List.of("192.168.1.1"), List.of(), null, null);
        });
    }

    @Test
    public void shouldRejectNullSuccessIpsList() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", 5, 2, null, List.of(), null, null);
        });
        assertEquals("Success IPs list cannot be null", exception.getMessage());
    }

    @Test
    public void shouldRejectNullFailureIpsList() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", 5, 2, List.of(), null, null, null);
        });
        assertEquals("Failure IPs list cannot be null", exception.getMessage());
    }

    @Test
    public void shouldSupportLargeCounts() {
        Instant now = Instant.now();
        LoginStats stats = new LoginStats("user1", 1000000, 999999,
                List.of("192.168.1.1"), List.of("192.168.1.2"), now, now);
        assertEquals(1000000, stats.success());
        assertEquals(999999, stats.failure());
    }

    @Test
    public void shouldAllowNullTimestamps() {
        LoginStats stats = new LoginStats("user1", 5, 2,
                List.of("192.168.1.1"), List.of("192.168.1.2"), null, null);
        assertNull(stats.lastSuccessTimestamp());
        assertNull(stats.lastFailureTimestamp());
    }

    @Test
    public void shouldCreateDefensiveCopyOfSuccessIps() {
        List<String> originalList = new ArrayList<>();
        originalList.add("192.168.1.1");
        originalList.add("192.168.1.2");

        LoginStats stats = new LoginStats("user1", 5, 2, originalList, List.of(), null, null);

        // Modify original list
        originalList.add("192.168.1.3");

        // LoginStats should not be affected
        assertEquals(2, stats.successIps().size());
        assertFalse(stats.successIps().contains("192.168.1.3"));
    }

    @Test
    public void shouldReturnUnmodifiableIpsList() {
        LoginStats stats = new LoginStats("user1", 5, 2,
                List.of("192.168.1.1"), List.of("192.168.1.2"), null, null);

        // Attempting to modify should throw exception
        assertThrows(UnsupportedOperationException.class, () -> {
            stats.successIps().add("192.168.1.3");
        });
    }
}