package za.co.frei.logfile.analyzer.service;

import org.springframework.stereotype.Service;
import za.co.frei.logfile.analyzer.model.EventType;
import za.co.frei.logfile.analyzer.model.LogEntry;
import za.co.frei.logfile.analyzer.model.LoginStats;
import za.co.frei.logfile.analyzer.model.SuspiciousWindow;
import za.co.frei.logfile.analyzer.model.TopUploader;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
public class LogParserService {

    private final List<LogEntry> storedEntries = new ArrayList<>();

    public List<LogEntry> getStoredEntries() {
        return Collections.unmodifiableList(storedEntries);
    }

    public void clearStoredEntries() {
        storedEntries.clear();
    }

    public int getStoredEntryCount() {
        return storedEntries.size();
    }

    protected void addStoredEntry(LogEntry entry) {
        storedEntries.add(entry);
    }

    public List<LogEntry> parseLog(InputStream inputStream) {
        // TODO: Implement logic to parse log file into List<LogEntry>
        return new ArrayList<>();
    }

    public Map<String, LoginStats> getLoginCounts(List<LogEntry> entries) {
        // TODO: Implement logic to count LOGIN_SUCCESS and LOGIN_FAILURE per user
        return null;
    }

    public List<TopUploader> getTopUploaders(List<LogEntry> entries, int limit) {
        // TODO: Implement logic to get top uploaders based on FILE_UPLOAD events
        return null;
    }

    public List<SuspiciousWindow> getSuspiciousActivity(List<LogEntry> entries) {
        // TODO: Implement logic to detect suspicious LOGIN_FAILURE activity
        return null;
    }
}