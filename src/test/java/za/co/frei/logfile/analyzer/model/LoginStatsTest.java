package za.co.frei.logfile.analyzer.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class LoginStatsTest {

    @Test
    public void shouldCreateValidLoginStats() {
        LoginStats stats = new LoginStats("user1", 5, 2);
        assertEquals("user1", stats.user());
        assertEquals(5, stats.success());
        assertEquals(2, stats.failure());
    }

    @Test
    public void shouldAllowZeroCounts() {
        LoginStats stats = new LoginStats("user1", 0, 0);
        assertEquals(0, stats.success());
        assertEquals(0, stats.failure());
    }

    @Test
    public void shouldRejectNullUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats(null, 5, 2);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectBlankUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("   ", 5, 2);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectEmptyUser() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("", 5, 2);
        });
        assertEquals("User cannot be null or blank", exception.getMessage());
    }

    @Test
    public void shouldRejectNegativeSuccess() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", -1, 2);
        });
        assertEquals("Success count cannot be negative", exception.getMessage());
    }

    @Test
    public void shouldRejectNegativeFailure() {
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", 5, -1);
        });
        assertEquals("Failure count cannot be negative", exception.getMessage());
    }

    @Test
    public void shouldRejectBothNegative() {
        assertThrows(IllegalArgumentException.class, () -> {
            new LoginStats("user1", -5, -2);
        });
    }

    @Test
    public void shouldSupportLargeCounts() {
        LoginStats stats = new LoginStats("user1", 1000000, 999999);
        assertEquals(1000000, stats.success());
        assertEquals(999999, stats.failure());
    }
}