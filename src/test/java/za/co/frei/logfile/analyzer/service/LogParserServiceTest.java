package za.co.frei.logfile.analyzer.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import za.co.frei.logfile.analyzer.model.EventType;
import za.co.frei.logfile.analyzer.model.LogEntry;
import za.co.frei.logfile.analyzer.model.TopUploader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;


@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(MockitoExtension.class)
public class LogParserServiceTest {

    @InjectMocks
    private LogParserService parserService;

    @BeforeEach
    public void setUp() {
        parserService.clearStoredEntries();
    }

    @Test
    public void shouldStartWithEmptyStorage() {
        assertEquals(0, parserService.getStoredEntryCount());
        assertTrue(parserService.getStoredEntries().isEmpty());
    }

    @Test
    public void shouldReturnUnmodifiableList() {
        List<LogEntry> entries = parserService.getStoredEntries();
        assertThrows(UnsupportedOperationException.class, () -> {
            entries.add(new LogEntry(Instant.now(), "user1", EventType.LOGIN_SUCCESS, "192.168.1.1", null));
        });
    }

    @Test
    public void shouldClearStoredEntries() {
        LogEntry entry = new LogEntry(Instant.now(), "user1", EventType.LOGIN_SUCCESS, "192.168.1.1", null);
        parserService.addStoredEntry(entry);
        assertEquals(1, parserService.getStoredEntryCount());

        parserService.clearStoredEntries();
        assertEquals(0, parserService.getStoredEntryCount());
    }

    @Test
    public void shouldStoreMultipleEntries() {
        LogEntry entry1 = new LogEntry(Instant.now(), "user1", EventType.LOGIN_SUCCESS, "192.168.1.1", null);
        LogEntry entry2 = new LogEntry(Instant.now(), "user2", EventType.LOGIN_FAILURE, "192.168.1.2", null);

        parserService.addStoredEntry(entry1);
        parserService.addStoredEntry(entry2);

        assertEquals(2, parserService.getStoredEntryCount());
        List<LogEntry> stored = parserService.getStoredEntries();
        assertTrue(stored.contains(entry1));
        assertTrue(stored.contains(entry2));
    }

    @Test
    public void shouldParseLogFile() throws IOException {
        String logContent =
                "2025-09-15T08:00:00Z | alice | LOGIN_SUCCESS | IP=192.168.1.1\n" +
                        "2025-09-15T08:01:00Z | bob | LOGIN_FAILURE | IP=192.168.1.2\n" +
                        "2025-09-15T08:02:00Z | charlie | FILE_UPLOAD | IP=192.168.1.3 | FILE=report.pdf";

        InputStream inputStream = new ByteArrayInputStream(logContent.getBytes());
        List<LogEntry> entries = parserService.parseLog(inputStream);

        assertEquals(3, entries.size());
        assertEquals("alice", entries.get(0).user());
        assertEquals(EventType.LOGIN_SUCCESS, entries.get(0).event());
        assertEquals("192.168.1.1", entries.get(0).ip());

        // Verify aggregates were updated
        assertEquals(3, parserService.getStoredEntryCount());
    }


    @Test
    public void shouldGetTopUploaders() {
        // TODO: Test getting top uploaders based on FILE_UPLOAD events
        List<LogEntry> entries = List.of(new LogEntry(Instant.now(), "user1", EventType.FILE_UPLOAD, "192.168.1.1", "file1"));
        parserService.getTopUploaders(entries, 3);
    }

    @Test
    public void shouldGetSuspiciousActivity() {
        // TODO: Test detecting suspicious LOGIN_FAILURE activity
        List<LogEntry> entries = List.of(new LogEntry(Instant.now(), "user1", EventType.LOGIN_FAILURE, "192.168.1.1", null));
        parserService.getSuspiciousActivity(entries);
    }
}