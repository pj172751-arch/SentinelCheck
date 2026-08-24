# SentinelCheck

**Lightweight Host-Based Security Event Monitor**

A Java console application that demonstrates host-based security monitoring
through file integrity verification, authentication log analysis, firewall
event detection, alert correlation, risk scoring, and incident reporting.

---

## Architecture

```
                         SENTINELCHECK
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
       File Integrity   Authentication    Firewall Events
          Monitor          Monitor           Monitor
              |               |               |
              v               v               v
        SHA-256 hashes    Failed logins    DROP events
              |               |               |
              +---------------+---------------+
                              |
                              v
                     Alert Engine + Risk Scorer
                              |
                              v
                       Event Correlation
                              |
                              v
                       Incident Report
```

**Pipeline:** Collect -> Hash/Parse -> Detect -> Correlate -> Score -> Report

---

## Modules

### 1. File Integrity Monitoring
- Computes SHA-256 hashes for all files in a monitored directory
- Creates a `.baseline` file storing filename-hash pairs
- Detects four states: **UNCHANGED**, **MODIFIED**, **MISSING**, **NEW**
- Reports old and new hashes for modified files (forensic evidence)

### 2. Authentication Monitoring
- Parses CSV-formatted authentication logs
- Groups `FAILED_LOGIN` events by source IP
- Alerts when failed attempts >= 3 (configurable threshold)
- Severity tiers: 3-4 = MEDIUM, 5-9 = HIGH, 10+ = CRITICAL

### 3. Firewall Event Monitoring
- Parses CSV-formatted firewall logs
- Detects and groups `FIREWALL_DROP` events by source IP
- Tracks targeted ports and protocols

### 4. Alert Engine + Risk Scoring
- Aggregates alerts from all three modules
- Transparent, rule-based scoring:

| Event                    | Score |
|--------------------------|------:|
| Failed login             |   +10 |
| 3+ failed logins (bonus) |   +30 |
| Firewall DROP            |   +15 |
| Critical file modified   |   +40 |
| New file detected        |   +20 |
| Missing file             |   +30 |

- Severity: 0-29 LOW, 30-59 MEDIUM, 60-89 HIGH, 90+ CRITICAL

### 5. Event Correlation
- Connects related events by source IP address
- When the same IP triggers alerts in multiple modules
  (e.g., brute-force + firewall DROP), a correlated incident
  is created with elevated severity

### 6. Incident Report
- Plain-text report with sections for each module
- Includes IP summary table, SHA-256 hashes, targeted ports
- Summary with counts and overall risk level

---

## Requirements

- **Java 17** or later (JDK required for compilation)

---

## Build and Run

### Compile

```bash
javac -encoding UTF-8 -d out -sourcepath src src/sentinelcheck/*.java src/sentinelcheck/**/*.java
```

### Run (Interactive Menu)

```bash
java -cp out sentinelcheck.Main
```

### Run (Full Scan, Non-Interactive)

```bash
java -cp out sentinelcheck.Main --scan
java -cp out sentinelcheck.Main --scan --dir monitored --logs sample-logs
```

---

## Interactive Menu

```
  +==========================================+
  |          SENTINELCHECK v1.0              |
  |  Host-Based Security Event Monitor      |
  +==========================================+

  [1] Create File Integrity Baseline
  [2] Verify File Integrity
  [3] Analyze Security Logs
  [4] Generate Full Incident Report
  [5] Run Complete Security Scan
  [0] Exit
```

---

## Sample Log Formats

### Authentication Log (`sample-logs/auth_log.csv`)

```
2026-08-24 10:03:22,FAILED_LOGIN,admin,192.168.1.20
2026-08-24 10:05:11,SUCCESSFUL_LOGIN,agarwal,192.168.1.30
```

Format: `timestamp,EVENT_TYPE,username,source_ip`

### Firewall Log (`sample-logs/firewall_log.csv`)

```
2026-08-24 10:15:42,FIREWALL_DROP,10.0.0.15,192.168.1.1,22,TCP
2026-08-24 10:30:10,FIREWALL_ACCEPT,192.168.1.10,192.168.1.1,443,TCP
```

Format: `timestamp,EVENT_TYPE,source_ip,dest_ip,port,protocol`

---

## Project Structure

```
SentinelCheck/
|-- src/sentinelcheck/
|   |-- Main.java
|   |-- model/
|   |   |-- FileRecord.java
|   |   |-- SecurityEvent.java
|   |   |-- Alert.java
|   |   |-- FileStatus.java
|   |   |-- EventType.java
|   |   +-- Severity.java
|   |-- integrity/
|   |   |-- HashCalculator.java
|   |   |-- BaselineManager.java
|   |   +-- IntegrityChecker.java
|   |-- logs/
|   |   |-- LogParser.java
|   |   |-- AuthenticationMonitor.java
|   |   +-- FirewallMonitor.java
|   |-- detection/
|   |   |-- AlertEngine.java
|   |   |-- RiskScorer.java
|   |   +-- EventCorrelator.java
|   +-- report/
|       +-- IncidentReportGenerator.java
|-- sample-logs/
|   |-- auth_log.csv
|   +-- firewall_log.csv
|-- monitored/
|   |-- config.txt
|   |-- users.csv
|   |-- settings.json
|   |-- server.conf
|   +-- readme.txt
+-- reports/              (generated, gitignored)
```

---

## Demonstration

### Step 1: Create Baseline
Run option [1] to hash all files in `monitored/`.

### Step 2: Tamper with Files
- Modify `monitored/config.txt`
- Delete `monitored/users.csv`
- Add a new file `monitored/malware.exe`

### Step 3: Run Security Scan
Run option [5] to detect all changes and analyze logs.

### Step 4: Review Report
Check `reports/incident_report_<timestamp>.txt` for the full report.

---

## Scope Limitations

This is a demonstration tool for educational purposes. It does NOT:
- Monitor real system logs or live network traffic
- Configure or modify actual firewalls
- Perform packet capture or deep packet inspection
- Block IP addresses or perform automatic remediation
- Scan for malware or viruses
- Use machine learning for threat detection

---

## NSM Concepts Demonstrated

- File integrity verification (SHA-256 hashing)
- Authentication failure detection (brute-force patterns)
- Firewall event monitoring (DROP analysis)
- Security event normalization and correlation
- Rule-based risk scoring
- Incident reporting and forensic evidence

---

## OOP Concepts

| Concept            | Where                                          |
|--------------------|------------------------------------------------|
| Classes & Objects  | All 16 classes                                 |
| Enums              | FileStatus, EventType, Severity                |
| Encapsulation      | Private fields + getters in all model classes  |
| Collections        | ArrayList, HashMap, LinkedHashMap              |
| Exception Handling | File I/O, parsing, hash calculation            |
| File I/O           | Baseline, log parsing, report generation       |
| Hashing            | java.security.MessageDigest (SHA-256)          |
| String Parsing     | CSV parsing, event type mapping                |
| Java Time API      | LocalDateTime, DateTimeFormatter               |
| Inner Classes      | AuthResult, FirewallResult                     |

---

## References

- [file-integrity-check](https://github.com/karsany/file-integrity-check) - SHA-256 file baselines
- [Digital-Forensics-Analyzer](https://github.com/oams84/Digital-Forensics-Analyzer) - Log analysis and reporting
- [gchecksum](https://github.com/Glavo/gchecksum) - Checksum verification behavior

---

## Author

Computer Engineering Diploma Project - Network Security Monitoring
