Here's a comprehensive README.md for your project:

```markdown
# Log File Analyzer

A Spring Boot application that parses system log files, performs security analysis, and provides REST API endpoints for querying aggregated statistics.

## Overview

This application processes log files from multiple systems, stores entries in memory, and provides analytical insights including:
- User login success/failure statistics
- Top file uploaders identification
- Suspicious activity detection (brute force attack patterns)
- Complete data export functionality

## Requirements

- Java 17 or higher
- Maven 3.6+
- No external database required (in-memory storage)

## Building the Project

```bash
# Clone the repository
git clone <your-repo-url>
cd logfile-analyzer

# Build with Maven
mvn clean package

# Run tests
mvn test
```

## Running the Application

```bash
# Using Maven
mvn spring-boot:run

# Or using the JAR file
java -jar target/logfile-analyzer-0.0.1-SNAPSHOT.jar
```

The application will start on `http://localhost:8181`

## Log File Format

Log entries must follow this format:

```
<timestamp> | <user> | <event> | [additional fields]
```

### Supported Events

1. **LOGIN_SUCCESS**
   ```
   2025-09-15T08:00:00Z | alice | LOGIN_SUCCESS | IP=192.168.1.1
   ```

2. **LOGIN_FAILURE**
   ```
   2025-09-15T08:01:00Z | bob | LOGIN_FAILURE | IP=192.168.1.2
   ```

3. **FILE_UPLOAD**
   ```
   2025-09-15T08:02:00Z | charlie | FILE_UPLOAD | FILE=report.pdf
   2025-09-15T08:03:00Z | david | FILE_UPLOAD | IP=192.168.1.3 | FILE=data.csv
   ```

4. **FILE_DOWNLOAD**
   ```
   2025-09-15T08:04:00Z | eve | FILE_DOWNLOAD | FILE=document.txt
   ```

5. **LOGOUT**
   ```
   2025-09-15T08:05:00Z | frank | LOGOUT
   ```

## API Endpoints

### 1. Upload Log Files

Upload one or more log files for processing.

**Endpoint:** `POST /api/v1/logs/upload`

**Request:**
```bash
curl -X POST http://localhost:8181/api/v1/logs/upload \
  -F "file=@system_logs.log"
```

**Response (201 Created):**
```json
{
  "message": "Uploaded 1 of 1 file(s)",
  "filesProcessed": ["system_logs.log"],
  "failedFiles": [],
  "processed": 1504,
  "totalStored": 1504,
  "errors": 0
}
```

### 2. Get Login Statistics

Retrieve login success/failure counts for all users or a specific user.

**Endpoint:** `GET /api/v1/logs/users/login-counts`

**Query Parameters:**
- `user` (optional) - Filter by specific username

**Examples:**
```bash
# All users
curl http://localhost:8181/api/v1/logs/users/login-counts

# Specific user
curl http://localhost:8181/api/v1/logs/users/login-counts?user=USER015
```

**Response (200 OK):**
```json
{
  "USER015": {
    "user": "USER015",
    "success": 10,
    "failure": 5,
    "successIps": ["192.168.1.1", "192.168.1.18", "192.168.1.20"],
    "failureIps": ["192.168.1.10", "192.168.1.15"],
    "lastSuccessTimestamp": "2025-09-15T16:42:49Z",
    "lastFailureTimestamp": "2025-09-15T13:49:07Z"
  }
}
```

**Response (204 No Content):** No login data available

### 3. Get Top Uploaders

Retrieve users with the most FILE_UPLOAD events.

**Endpoint:** `GET /api/v1/logs/users/top-uploaders`

**Query Parameters:**
- `limit` (optional, default: 3) - Number of top uploaders to return

**Examples:**
```bash
# Top 3 (default)
curl http://localhost:8181/api/v1/logs/users/top-uploaders

# Top 5
curl http://localhost:8181/api/v1/logs/users/top-uploaders?limit=5
```

**Response (200 OK):**
```json
[
  { "user": "USER014", "uploads": 11 },
  { "user": "USER019", "uploads": 10 },
  { "user": "USER004", "uploads": 9 }
]
```

**Response (204 No Content):** No upload data available

### 4. Get Suspicious Activity

Detect IPs with more than 3 LOGIN_FAILURE attempts within a 5-minute window.

**Endpoint:** `GET /api/v1/logs/security/suspicious`

**Example:**
```bash
curl http://localhost:8181/api/v1/logs/security/suspicious
```

**Response (200 OK):**
```json
[
  {
    "ip": "192.168.1.100",
    "start": "2025-09-15T10:00:00Z",
    "end": "2025-09-15T10:03:00Z",
    "failures": 4,
    "timestamps": [
      "2025-09-15T10:00:00Z",
      "2025-09-15T10:01:00Z",
      "2025-09-15T10:02:00Z",
      "2025-09-15T10:03:00Z"
    ],
    "users": ["user1", "user1", "user2", "user1"]
  }
]
```

**Response (204 No Content):** No suspicious activity detected

### 5. Export Results

Export all analysis results as a downloadable JSON file.

**Endpoint:** `GET /api/v1/logs/export`

**Example:**
```bash
curl http://localhost:8181/api/v1/logs/export -o results.json
```

**Response (200 OK):**
Downloads a JSON file containing:
- Export timestamp
- Total entries stored
- All login statistics
- Top 3 uploaders
- All suspicious activity detections

## Architecture

### Key Design Decisions

1. **In-Memory Storage**
   - Thread-safe `ConcurrentLinkedQueue` for log entries
   - `ConcurrentHashMap` for aggregated statistics
   - O(1) query performance for most endpoints

2. **Pre-Aggregation Strategy**
   - Statistics computed during log parsing
   - Eliminates need to scan all entries on each query
   - Optimized for read-heavy workloads

3. **Multi-File Support**
   - Aggregates data across multiple log files
   - Enables cross-system security analysis
   - Partial success handling (processes valid files even if some fail)

4. **Exception Handling**
   - Custom exceptions: `FileProcessingException`, `ExportException`
   - Global exception handler with appropriate HTTP status codes
   - Detailed error logging for debugging

5. **Thread Safety**
   - Concurrent data structures throughout
   - Atomic operations for counters
   - Safe for concurrent file uploads

## Testing

Run the test suite:

```bash
mvn test
```

**Test Coverage:**
- Model validation tests
- Service logic tests
- Integration tests for all endpoints
- Suspicious activity detection algorithm tests

## Error Handling

The API returns standard HTTP status codes:

- `200 OK` - Successful request with data
- `201 Created` - Successful file upload
- `204 No Content` - Successful request but no data available
- `206 Partial Content` - Some files failed during upload
- `400 Bad Request` - Invalid parameters
- `422 Unprocessable Entity` - File processing failed
- `500 Internal Server Error` - Unexpected server error

## Configuration

Application configuration in `src/main/resources/application.yml`:

```yaml
server:
  port: 8181

logging:
  level:
    root: INFO
    za.co.frei.logfile.analyzer: DEBUG
```

## Performance Considerations

- **Memory Usage**: All log entries stored in memory. Monitor heap size for large files.
- **File Size Limits**: Configure in application.yml if needed
- **Concurrent Uploads**: Supported via thread-safe data structures
- **Query Performance**: O(1) for most queries due to pre-aggregation

## Project Structure

```
src/main/java/za/co/frei/logfile/analyzer/
├── controller/          # REST API endpoints
├── service/            # Business logic
├── model/              # Domain models and DTOs
└── exception/          # Custom exceptions and handlers

src/test/java/          # Test cases
```

## Author

Created as part of a technical assessment to demonstrate:
- Spring Boot proficiency
- REST API design
- Data structure selection
- Thread safety considerations
- Security analysis algorithms
- Clean code principles

## License

This project is created for assessment purposes.
```

- ✅ Ready for submission

Save this as `README.md` in your project root, commit it, and you're ready to push to GitHub!
