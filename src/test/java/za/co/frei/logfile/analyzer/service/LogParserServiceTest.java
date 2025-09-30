package za.co.frei.logfile.analyzer.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import za.co.frei.logfile.analyzer.model.EventType;
import za.co.frei.logfile.analyzer.model.LogEntry;
import za.co.frei.logfile.analyzer.model.LoginStats;
import za.co.frei.logfile.analyzer.model.SuspiciousWindow;
import za.co.frei.logfile.analyzer.model.TopUploader;

import java.io.ByteArrayInputStream;
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

    @Test
    public void shouldParseLogFile() {
        // TODO: Test parsing of log file into List<LogEntry>
    }

    @Test
    public void shouldGetLoginCounts() {
        // TODO: Test counting LOGIN_SUCCESS and LOGIN_FAILURE per user
        List<LogEntry> entries = List.of(new LogEntry(Instant.now(), "user1", EventType.LOGIN_SUCCESS, "192.168.1.1", null));
        parserService.getLoginCounts(entries);
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