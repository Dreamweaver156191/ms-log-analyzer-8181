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
import za.co.frei.logfile.analyzer.model.SuspiciousWindow;
import za.co.frei.logfile.analyzer.model.TopUploader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.List;

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

        assertEquals(3, parserService.getStoredEntryCount());
    }

    @Test
    public void shouldGetTopUploadersFromAggregatedData() throws IOException {
        String logContent =
                "2025-09-15T08:00:00Z | user1 | FILE_UPLOAD | FILE=file1.pdf\n" +
                        "2025-09-15T08:01:00Z | user1 | FILE_UPLOAD | FILE=file2.pdf\n" +
                        "2025-09-15T08:02:00Z | user2 | FILE_UPLOAD | FILE=file3.pdf\n" +
                        "2025-09-15T08:03:00Z | user3 | LOGIN_SUCCESS | IP=192.168.1.3";

        InputStream inputStream = new ByteArrayInputStream(logContent.getBytes());
        parserService.parseLog(inputStream);

        List<TopUploader> result = parserService.getTopUploaders(2);

        assertEquals(2, result.size());
        assertEquals("user1", result.get(0).user());
        assertEquals(2, result.get(0).uploads());
        assertEquals("user2", result.get(1).user());
        assertEquals(1, result.get(1).uploads());
    }

    @Test
    public void shouldDetectSuspiciousActivityWithin5Minutes() throws IOException {
        String logContent =
                "2025-09-15T10:00:00Z | user1 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:00:30Z | user2 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:01:00Z | user3 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:01:30Z | user4 | LOGIN_FAILURE | IP=192.168.1.100";

        InputStream inputStream = new ByteArrayInputStream(logContent.getBytes());
        parserService.parseLog(inputStream);

        List<SuspiciousWindow> suspicious = parserService.getSuspiciousActivity();

        assertEquals(1, suspicious.size());
        assertEquals("192.168.1.100", suspicious.get(0).ip());
        assertEquals(4, suspicious.get(0).failures());
        assertEquals(Instant.parse("2025-09-15T10:00:00Z"), suspicious.get(0).start());
        assertEquals(Instant.parse("2025-09-15T10:01:30Z"), suspicious.get(0).end());
    }

    @Test
    public void shouldNotDetectSuspiciousActivityWith3OrFewerFailures() throws IOException {
        String logContent =
                "2025-09-15T10:00:00Z | user1 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:00:30Z | user2 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:01:00Z | user3 | LOGIN_FAILURE | IP=192.168.1.100";

        InputStream inputStream = new ByteArrayInputStream(logContent.getBytes());
        parserService.parseLog(inputStream);

        List<SuspiciousWindow> suspicious = parserService.getSuspiciousActivity();

        assertTrue(suspicious.isEmpty());
    }

    @Test
    public void shouldNotDetectSuspiciousActivityBeyond5Minutes() throws IOException {
        String logContent =
                "2025-09-15T10:00:00Z | user1 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:01:00Z | user2 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:02:00Z | user3 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:06:00Z | user4 | LOGIN_FAILURE | IP=192.168.1.100";

        InputStream inputStream = new ByteArrayInputStream(logContent.getBytes());
        parserService.parseLog(inputStream);

        List<SuspiciousWindow> suspicious = parserService.getSuspiciousActivity();

        assertTrue(suspicious.isEmpty());
    }

    @Test
    public void shouldDetectMultipleSuspiciousIps() throws IOException {
        String logContent =
                "2025-09-15T10:00:00Z | user1 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:00:15Z | user2 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:00:30Z | user3 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:00:45Z | user4 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T11:00:00Z | user5 | LOGIN_FAILURE | IP=192.168.1.200\n" +
                        "2025-09-15T11:00:30Z | user6 | LOGIN_FAILURE | IP=192.168.1.200\n" +
                        "2025-09-15T11:01:00Z | user7 | LOGIN_FAILURE | IP=192.168.1.200\n" +
                        "2025-09-15T11:01:30Z | user8 | LOGIN_FAILURE | IP=192.168.1.200\n" +
                        "2025-09-15T11:02:00Z | user9 | LOGIN_FAILURE | IP=192.168.1.200";

        InputStream inputStream = new ByteArrayInputStream(logContent.getBytes());
        parserService.parseLog(inputStream);

        List<SuspiciousWindow> suspicious = parserService.getSuspiciousActivity();

        assertEquals(2, suspicious.size());
        assertTrue(suspicious.stream().anyMatch(w -> w.ip().equals("192.168.1.100")));
        assertTrue(suspicious.stream().anyMatch(w -> w.ip().equals("192.168.1.200")));
    }

    @Test
    public void shouldHandleExactly5MinuteWindow() throws IOException {
        String logContent =
                "2025-09-15T10:00:00Z | user1 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:01:00Z | user2 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:03:00Z | user3 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:05:00Z | user4 | LOGIN_FAILURE | IP=192.168.1.100";

        InputStream inputStream = new ByteArrayInputStream(logContent.getBytes());
        parserService.parseLog(inputStream);

        List<SuspiciousWindow> suspicious = parserService.getSuspiciousActivity();

        assertEquals(1, suspicious.size());
        assertEquals(4, suspicious.get(0).failures());
    }

    @Test
    public void shouldReturnEmptyListWhenNoFailures() {
        List<SuspiciousWindow> suspicious = parserService.getSuspiciousActivity();
        assertTrue(suspicious.isEmpty());
    }

    @Test
    public void shouldIncludeAllTimestampsInWindow() throws IOException {
        String logContent =
                "2025-09-15T10:00:00Z | user1 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:00:30Z | user2 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:01:00Z | user3 | LOGIN_FAILURE | IP=192.168.1.100\n" +
                        "2025-09-15T10:01:30Z | user4 | LOGIN_FAILURE | IP=192.168.1.100";

        InputStream inputStream = new ByteArrayInputStream(logContent.getBytes());
        parserService.parseLog(inputStream);

        List<SuspiciousWindow> suspicious = parserService.getSuspiciousActivity();

        assertEquals(1, suspicious.size());
        assertEquals(4, suspicious.get(0).timestamps().size());
        assertTrue(suspicious.get(0).timestamps().contains(Instant.parse("2025-09-15T10:00:00Z")));
        assertTrue(suspicious.get(0).timestamps().contains(Instant.parse("2025-09-15T10:00:30Z")));
        assertTrue(suspicious.get(0).timestamps().contains(Instant.parse("2025-09-15T10:01:00Z")));
        assertTrue(suspicious.get(0).timestamps().contains(Instant.parse("2025-09-15T10:01:30Z")));
    }
}