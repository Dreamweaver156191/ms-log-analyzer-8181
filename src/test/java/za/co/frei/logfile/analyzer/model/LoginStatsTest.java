package za.co.frei.logfile.analyzer.model;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class LoginStatsTest {

    @Test
    public void shouldCreateValidLoginStats() {
        LoginStats stats = new LoginStats("user1", 5, 2,
                List.of("192.168.1.1", "192.168.1.2"),
                List.of("192.168.1.3"));
        assertEquals("user1", stats.user());
        assertEquals(5, stats.success());
        assertEquals(2, stats.failure());
        assertEquals(2, stats.successIps().size());
        assertEquals(1, stats.failureIps().size());
    }

    @Test
    public void shouldAllowZeroCounts() {
        LoginStats stats = new LoginStats("user1", 0, 0, List.of(), List.of());
        assertEquals(0, stats.success());
        assertEquals(0, stats.failure());
        assertTrue(stats.successIps().isEmpty());
        assertTrue(stats.failureIps().isEmpty());
    }

    @Test
    public void shouldAllowEmptyIpsLists() {
        LoginStats stats = new LoginStats("user1", 5, 2, List.of(), List.of());
        assertEquals(5, stats.success());
        assertEquals(2, stats.failure());
        assertTrue(stats.successIps().isEmpty());
        assertTrue(stats.failureIps().isEmpty());
    }

    @Test
    public void shouldRejectNullUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats(null, 5, 2, List.of("192.168.1.1"), List.of());
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectBlankUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("   ", 5, 2, List.of("192.168.1.1"), List.of());
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectEmptyUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("", 5, 2, List.of("192.168.1.1"), List.of());
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectNegativeSuccess() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", -1, 2, List.of("192.168.1.1"), List.of());
        });
        assertEquals("Success count cannot be negative", exception.getMessage());
    }

    @Test
    public void shouldRejectNegativeFailure() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", 5, -1, List.of("192.168.1.1"), List.of());
        });
        assertEquals("Failure count cannot be negative", exception.getMessage());
    }

    @Test
    public void shouldRejectBothNegative() {
        assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", -5, -2, List.of("192.168.1.1"), List.of());
        });
    }

    @Test
    public void shouldRejectNullSuccessIpsList() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", 5, 2, null, List.of());
        });
        assertEquals("Success IPs list cannot be null", exception.getMessage());
    }

    @Test
    public void shouldRejectNullFailureIpsList() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", 5, 2, List.of(), null);
        });
        assertEquals("Failure IPs list cannot be null", exception.getMessage());
    }

    @Test
    public void shouldSupportLargeCounts() {
        LoginStats stats = new LoginStats("user1", 1000000, 999999,
                List.of("192.168.1.1"), List.of("192.168.1.2"));
        assertEquals(1000000, stats.success());
        assertEquals(999999, stats.failure());
    }

    @Test
    public void shouldCreateDefensiveCopyOfSuccessIps() {
        List<String> originalList = new ArrayList<>();
        originalList.add("192.168.1.1");
        originalList.add("192.168.1.2");

        LoginStats stats = new LoginStats("user1", 5, 2, originalList, List.of());

        // Modify original list
        originalList.add("192.168.1.3");

        // LoginStats should not be affected
        assertEquals(2, stats.successIps().size());
        assertFalse(stats.successIps().contains("192.168.1.3"));
    }

    @Test
    public void shouldCreateDefensiveCopyOfFailureIps() {
        List<String> originalList = new ArrayList<>();
        originalList.add("192.168.1.1");

        LoginStats stats = new LoginStats("user1", 5, 2, List.of(), originalList);

        // Modify original list
        originalList.add("192.168.1.3");

        // LoginStats should not be affected
        assertEquals(1, stats.failureIps().size());
        assertFalse(stats.failureIps().contains("192.168.1.3"));
    }

    @Test
    public void shouldReturnUnmodifiableSuccessIpsList() {
        LoginStats stats = new LoginStats("user1", 5, 2, List.of("192.168.1.1"), List.of());

        // Attempting to modify should throw exception
        assertThrows(UnsupportedOperationException.class, () -> {
            stats.successIps().add("192.168.1.2");
        });
    }

    @Test
    public void shouldReturnUnmodifiableFailureIpsList() {
        LoginStats stats = new LoginStats("user1", 5, 2, List.of(), List.of("192.168.1.1"));

        // Attempting to modify should throw exception
        assertThrows(UnsupportedOperationException.class, () -> {
            stats.failureIps().add("192.168.1.2");
        });
    }

    @Test
    public void shouldHandleMultipleIps() {
        List<String> successIps = List.of("192.168.1.1", "192.168.1.2", "192.168.1.3");
        List<String> failureIps = List.of("10.0.0.1", "10.0.0.2");

        LoginStats stats = new LoginStats("user1", 10, 3, successIps, failureIps);

        assertEquals(3, stats.successIps().size());
        assertEquals(2, stats.failureIps().size());
        assertTrue(stats.successIps().containsAll(successIps));
        assertTrue(stats.failureIps().containsAll(failureIps));
    }

    @Test
    public void shouldDifferentiateBetweenSuccessAndFailureIps() {
        LoginStats stats = new LoginStats("user1", 3, 2,
                List.of("192.168.1.1", "192.168.1.2"),  // Success IPs
                List.of("192.168.1.3", "192.168.1.4")   // Failure IPs
        );

        // Verify success IPs
        assertTrue(stats.successIps().contains("192.168.1.1"));
        assertTrue(stats.successIps().contains("192.168.1.2"));
        assertFalse(stats.successIps().contains("192.168.1.3"));

        // Verify failure IPs
        assertTrue(stats.failureIps().contains("192.168.1.3"));
        assertTrue(stats.failureIps().contains("192.168.1.4"));
        assertFalse(stats.failureIps().contains("192.168.1.1"));
    }

    @Test
    public void shouldHandleSameIpForSuccessAndFailure() {
        // Same IP can appear in both lists (user succeeded from IP, then failed from same IP)
        LoginStats stats = new LoginStats("user1", 2, 1,
                List.of("192.168.1.1"),
                List.of("192.168.1.1")
        );

        assertEquals(1, stats.successIps().size());
        assertEquals(1, stats.failureIps().size());
        assertTrue(stats.successIps().contains("192.168.1.1"));
        assertTrue(stats.failureIps().contains("192.168.1.1"));
    }
}