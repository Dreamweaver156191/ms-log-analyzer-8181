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

}