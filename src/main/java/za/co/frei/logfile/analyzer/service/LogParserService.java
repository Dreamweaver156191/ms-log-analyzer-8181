package za.co.frei.logfile.analyzer.service;

import org.springframework.stereotype.Service;
import za.co.frei.logfile.analyzer.model.LogEntry;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@Service
public class LogParserService {

    public List<LogEntry> parseLog(InputStream inputStream) {
        //TODO
        return new ArrayList<>();
    }
}