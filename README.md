
````markdown
# Log File Analyzer  

[![Java](https://img.shields.io/badge/Java-17-orange.svg)](https://www.oracle.com/java/) 
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.5-brightgreen.svg)](https://spring.io/projects/spring-boot) 
[![Maven](https://img.shields.io/badge/Maven-3.6+-blue.svg)](https://maven.apache.org/)  

A robust Spring Boot REST API application that parses system log files, performs security analysis, and provides comprehensive analytics endpoints with interactive Swagger documentation.  

---

## Overview  

This application processes log files from multiple systems, stores entries in memory, and provides analytical insights including:  

- User login success/failure statistics with IP tracking and timestamps  
- Top file uploaders identification  
- Suspicious activity detection (brute force attack patterns)  
- Complete data export functionality  
- Interactive API documentation via Swagger UI  

---

## Features  

- ✅ Multi-file log parsing with partial success handling  
- ✅ Thread-safe concurrent processing  
- ✅ Pre-aggregated statistics for O(1) query performance  
- ✅ Suspicious activity detection (>3 failures in 5-minute window)  
- ✅ RESTful API with comprehensive error handling  
- ✅ Interactive Swagger/OpenAPI documentation  
- ✅ JSON export functionality  
- ✅ Extensive unit test coverage  

---

## Requirements  

- Java 17 or higher  
- Maven 3.6+  
- No external database required (in-memory storage)  

---

## Building the Project  

```bash
# Clone the repository
git clone <your-repo-url>
cd logfile-analyzer  

# Build with Maven
mvn clean package  

# Run tests
mvn test
````

---

## Running the Application

```bash
# Using Maven
mvn spring-boot:run  

# Using the JAR file
java -jar target/ms-logfile-analyzer-2025-0.0.1-SNAPSHOT.jar  

# With custom memory settings (recommended for large files)
java -Xmx2g -Xms512m -jar target/ms-logfile-analyzer-2025-0.0.1-SNAPSHOT.jar  

# With custom port
java -jar target/ms-logfile-analyzer-2025-0.0.1-SNAPSHOT.jar --server.port=8080
```

The application will start on **[http://localhost:8181](http://localhost:8181)**

---

### Memory Configuration Options

For processing large log files, configure JVM memory settings:

| Setting | Description       | Example                    |
| ------- | ----------------- | -------------------------- |
| `-Xmx`  | Maximum heap size | `-Xmx2g` (2GB max)         |
| `-Xms`  | Initial heap size | `-Xms512m` (512MB initial) |
| `-Xss`  | Thread stack size | `-Xss1m` (1MB per thread)  |

**Recommended settings by workload:**

```bash
# Small files (<10MB)
java -jar target/ms-logfile-analyzer-2025-0.0.1-SNAPSHOT.jar  

# Medium files (10-100MB)
java -Xmx1g -Xms256m -jar target/ms-logfile-analyzer-2025-0.0.1-SNAPSHOT.jar  

# Large files (>100MB)
java -Xmx4g -Xms1g -jar target/ms-logfile-analyzer-2025-0.0.1-SNAPSHOT.jar
```

---

## API Documentation

### Swagger UI

Access the interactive API documentation at:

* **Swagger UI**: [http://localhost:8181/swagger-ui.html](http://localhost:8181/swagger-ui.html)
* **OpenAPI JSON**: [http://localhost:8181/api-docs](http://localhost:8181/api-docs)

The Swagger UI provides:

* Complete endpoint documentation
* Request/response examples
* Interactive testing capabilities (use `/upload-single` for file uploads)
* Schema definitions
* Try-it-out functionality for all endpoints

---

## Log File Format

Log entries must follow this pipe-delimited format:

```
<timestamp> | <user> | <event> | [event-specific fields]
```

### Supported Events

1. **LOGIN_SUCCESS** (requires IP)

   ```
   2025-09-15T08:00:00Z | alice | LOGIN_SUCCESS | IP=192.168.1.1
   ```

2. **LOGIN_FAILURE** (requires IP)

   ```
   2025-09-15T08:01:00Z | bob | LOGIN_FAILURE | IP=192.168.1.2
   ```

3. **FILE_UPLOAD** (requires FILE)

   ```
   2025-09-15T08:02:00Z | charlie | FILE_UPLOAD | FILE=report.pdf
   ```

4. **FILE_DOWNLOAD** (requires FILE)

   ```
   2025-09-15T08:04:00Z | eve | FILE_DOWNLOAD | FILE=document.txt
   ```

5. **LOGOUT** (no additional fields)

   ```
   2025-09-15T08:05:00Z | frank | LOGOUT
   ```

---

## API Endpoints

### Base URL

```
http://localhost:8181/api/v1/logs
```

### 1. Health Check

**Endpoint:** `GET /hello`

```bash
curl http://localhost:8181/api/v1/logs/hello
```

**Response (200 OK):**

```
Log File Analyzer Controller is active!
```

---

### 2. Upload Log Files

**Endpoints:**

* `POST /upload` – Multiple files (use with Postman/cURL)
* `POST /upload-single` – Single file (Swagger UI compatible)

**Request:**

```bash
# Single file
curl -X POST http://localhost:8181/api/v1/logs/upload \
  -F "file=@system_logs.log"

# Multiple files
curl -X POST http://localhost:8181/api/v1/logs/upload \
  -F "file=@system1.log" \
  -F "file=@system2.log"
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

---

### 3. Get Login Statistics

**Endpoint:** `GET /users/login-counts`

**Query Parameters:**

* `user` (optional) – Filter by specific username

**Examples:**

```bash
# All users
curl http://localhost:8181/api/v1/logs/users/login-counts  

# Specific user
curl http://localhost:8181/api/v1/logs/users/login-counts?user=alice
```

**Response (200 OK):**

```json
{
  "alice": {
    "user": "alice",
    "success": 15,
    "failure": 2,
    "successIps": ["192.168.1.100", "10.0.0.50"],
    "failureIps": ["192.168.1.200"],
    "lastSuccessTimestamp": "2024-01-15T10:30:00Z",
    "lastFailureTimestamp": "2024-01-15T09:15:00Z"
  }
}
```

---

### 4. Get Top Uploaders

**Endpoint:** `GET /users/top-uploaders`

**Query Parameters:**

* `limit` (optional, default: 3) – Number of top uploaders to return

**Examples:**

```bash
# Top 3 (default)
curl http://localhost:8181/api/v1/logs/users/top-uploaders  

# Top 10
curl http://localhost:8181/api/v1/logs/users/top-uploaders?limit=10
```

**Response (200 OK):**

```json
[
  { "user": "alice", "uploads": 45 },
  { "user": "bob", "uploads": 32 },
  { "user": "charlie", "uploads": 28 }
]
```

---

### 5. Get Suspicious Activity

**Endpoint:** `GET /security/suspicious`

```bash
curl http://localhost:8181/api/v1/logs/security/suspicious
```

**Response (200 OK):**

```json
[
  {
    "ip": "192.168.1.200",
    "start": "2024-01-15T10:00:00Z",
    "end": "2024-01-15T10:04:30Z",
    "failures": 5,
    "timestamps": [
      "2024-01-15T10:00:00Z",
      "2024-01-15T10:01:00Z",
      "2024-01-15T10:02:30Z",
      "2024-01-15T10:03:45Z",
      "2024-01-15T10:04:30Z"
    ],
    "users": ["alice", "bob", "alice", "charlie", "alice"]
  }
]
```

---

### 6. Export Results

**Endpoint:** `GET /export`

```bash
curl http://localhost:8181/api/v1/logs/export -o log-analysis-export.json
```

Downloads a JSON file containing all analysis results.

---

## HTTP Status Codes

| Status Code                 | Description                                       |
| --------------------------- | ------------------------------------------------- |
| `200 OK`                    | Request successful with data returned             |
| `201 Created`               | All files successfully uploaded and processed     |
| `204 No Content`            | Request successful but no data available          |
| `206 Partial Content`       | Some files uploaded successfully, others failed   |
| `400 Bad Request`           | Invalid input parameters                          |
| `413 Payload Too Large`     | File size exceeds maximum allowed (50MB per file) |
| `422 Unprocessable Entity`  | All uploaded files failed to process              |
| `500 Internal Server Error` | Unexpected server error                           |

---

## Configuration

Application configuration in `src/main/resources/application.yml`:

```yaml
server:
  port: 8181

spring:
  servlet:
    multipart:
      max-file-size: 50MB
      max-request-size: 100MB

logging:
  level:
    za.co.frei.logfile.analyzer: DEBUG

springdoc:
  swagger-ui:
    path: /swagger-ui.html
    enabled: true
```

---

## Architecture

### Technology Stack

* **Spring Boot 3.5.5** – Application framework
* **Java 17** – Programming language
* **Maven** – Build and dependency management
* **SpringDoc OpenAPI 2.7.0** – API documentation
* **Jackson** – JSON processing
* **SLF4J/Logback** – Logging

### Key Design Decisions

1. **In-Memory Storage**

   * Thread-safe `ConcurrentLinkedQueue` for log entries
   * `ConcurrentHashMap` for aggregated statistics
   * O(1) query performance for most endpoints

2. **Pre-Aggregation Strategy**

   * Statistics computed during log parsing
   * Eliminates need to scan all entries on each query
   * Optimized for read-heavy workloads

3. **Multi-File Support**

   * Aggregates data across multiple log files
   * Enables cross-system security analysis
   * Partial success handling

4. **Suspicious Activity Detection**

   * Sliding window algorithm
   * Detects >3 LOGIN_FAILURE attempts within 5-minute windows
   * Tracks both IP addresses and affected users

5. **Thread Safety**

   * Concurrent data structures throughout
   * Safe for concurrent file uploads and queries

---

## Project Structure

```
src/main/java/za/co/frei/logfile/analyzer/
├── config/
│   └── OpenApiConfig.java
├── controller/
│   └── LogFileController.java
├── service/
│   ├── LogParserService.java
│   └── LoginStatsHolder.java
├── model/
│   ├── LogEntry.java
│   ├── LoginStats.java
│   ├── TopUploader.java
│   ├── SuspiciousWindow.java
│   ├── UploadResponse.java
│   ├── ExportResponse.java
│   └── EventType.java
└── exception/
    ├── FileProcessingException.java
    ├── ExportException.java
    └── GlobalExceptionHandler.java
```

---

## Testing

```bash
mvn test
```

Test coverage includes:

* Model validation tests
* Service logic tests
* Controller integration tests
* Thread safety tests
* Suspicious activity detection algorithm tests

---

## Troubleshooting

### Port already in use

```bash
java -jar target/ms-logfile-analyzer-2025-0.0.1-SNAPSHOT.jar --server.port=8080
```

### Out of memory errors

```bash
java -Xmx4g -Xms1g -jar target/ms-logfile-analyzer-2025-0.0.1-SNAPSHOT.jar
```

### File upload fails in Swagger UI

Use the `/upload-single` endpoint in Swagger UI, or use Postman/cURL for the `/upload` endpoint.

### Parsing errors

* Verify log file format matches expected pattern
* Check application logs at `logs/logfile-analyzer.log`
* Ensure timestamps are in ISO-8601 format

---

## License

This project is created for assessment purposes.

---

**Version:** 0.0.1-SNAPSHOT
**Spring Boot:** 3.5.5
**Java:** 17+
**Maven:** 3.6+


