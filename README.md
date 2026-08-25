# SentinelCheck v2.0

**Stateful Host-Based Security Event Monitor**

SentinelCheck is a Java console application that demonstrates host-based security monitoring (HIDS) through real-time file integrity verification, authentication log analysis, firewall event auditing, sliding-window threat rules, multi-module correlation, stateful incident lifecycle management, and persistent database tracking.

---

## 🏗️ Architecture

```text
                               SENTINELCHECK 2.0
                                      |
                    +-----------------+-----------------+
                    |                                   |
                    v                                   v
             REAL-TIME MONITOR                    LOG ANALYSIS
              WatchService                       Auth / Firewall
                    |                                   |
                    +-----------------+-----------------+
                                      |
                                      v
                             SECURITY EVENT HISTORY
                               (data/events.csv)
                                      |
                                      v
                             DETECTION ENGINE
                                      |
                                      v
                                   ALERTS
                               (FILE-001...FW-001)
                                      |
                                      v
                               EVENT CORRELATOR
                                      |
                                      v
                                 RISK SCORING
                                      |
                                      v
                            INCIDENT MANAGEMENT
                             (data/incidents.csv)
                               /            \
                              v              v
                         TIMELINE        AUDIT TRAIL
                              \              /
                               v            v
                               STATEFUL REPORTS
```

---

## 🛠️ Key Capabilities & Modules

### 1. Sibling Checksum Baseline Integrity Check
- Creates a baseline (`monitored.baseline`) containing filenames and expected SHA-256 hashes.
- Generates a sibling checksum file (`monitored.baseline.sha256`) containing the baseline file's own hash.
- Validates the baseline itself on start to detect tampering attacks (`FILE-004`).

### 2. Real-Time File Watcher (NIO `WatchService`)
- Spawns a background daemon thread monitoring folder modifications.
- Implements a **500ms event debouncer** to coalesce rapid duplicate file system notify events.
- Safely handles lock errors and file disappearance exceptions without stopping monitoring services.
- Promotes file violations (`FILE-001` Modified, `FILE-002` Missing, `FILE-003` New) directly to incidents to ensure visibility.

### 3. Log Threat Intelligence Heuristics (Sliding-Window Rules)
- **AUTH-001 (Brute Force)**: Identifies failed login attempts $\ge 3$ within a sliding 5-minute window.
- **AUTH-002 (Suspicious Success)**: Identifies successful logins occurring right after failed attempts from the same source IP.
- **AUTH-003 (Multiple Account Targeting)**: Flags when logins target $\ge 3$ unique usernames from the same source IP.
- **FW-001 (Port Probing)**: Audits DROP events from the same source IP targeting $\ge 5$ *unique destination ports* (diversity scan check).

### 4. Stateful Correlation & Lifecycle Manager
- Log entries and file events are written to `data/events.csv`.
- Related alerts are grouped into an Incident based on source context (source IP or `LOCAL` scope) and temporal proximity (10-minute window).
- Automatically applies correlation alerts and score bonuses (`CORR-001`) if events span multiple security modules.
- Tracks tickets through state machine transitions: `OPEN` $\rightarrow$ `ACKNOWLEDGED` $\rightarrow$ `CLOSED`.
- Audit logs record operator actions and timestamp details inside `data/incidents.csv`.

---

## 📊 Security Rules & Risk Weights

| Rule ID | Rule Name | Category | Points | Default Severity | Description |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **FILE-001** | File Modified | File Integrity | 40 | MEDIUM | SHA-256 mismatch detected |
| **FILE-002** | File Missing | File Integrity | 30 | MEDIUM | Protected file deleted |
| **FILE-003** | New File | File Integrity | 20 | LOW | Untracked file created (exe = Suspicious Executable) |
| **FILE-004** | Baseline Tampered | Baseline Checksum | 100 | CRITICAL | Baseline file checksum mismatch |
| **AUTH-001** | Brute Force | Authentication | 30 | MEDIUM | Multiple failed logins within window |
| **AUTH-002** | Suspicious Success | Authentication | 50 | MEDIUM | Successful login after failures |
| **AUTH-003** | Multi-Account | Authentication | 40 | MEDIUM | Targeting multiple users from one IP |
| **FW-001** | Port Probing | Firewall Drop | 30 | MEDIUM | Scanning multiple unique ports |
| **CORR-001** | Multi-Module | Correlation | 20 | HIGH | Bonus for cross-module attacks |

### Severity Scale:
- `0–29`: **LOW**
- `30–59`: **MEDIUM**
- `60–99`: **HIGH**
- `100+`: **CRITICAL**

---

## ⚙️ Requirements & Execution

* **Java 17** or later (JDK required for build).

### Build Project:
```powershell
javac -encoding UTF-8 -d out -sourcepath src (Get-ChildItem -Path src -Filter *.java -Recurse | ForEach-Object { $_.FullName })
```

### Start Dashboard & Nested CLI:
```powershell
java -cp out sentinelcheck.Main
```

### Start Batch Scan (Non-interactive mode):
```powershell
java -cp out sentinelcheck.Main --scan
java -cp out sentinelcheck.Main --scan --dir monitored --logs sample-logs
```

---

## 🗂️ Project File Structure

```text
SentinelCheck/
|-- src/sentinelcheck/
|   |-- Main.java
|   |-- model/
|   |   |-- FileRecord.java
|   |   |-- SecurityEvent.java
|   |   |-- Alert.java
|   |   |-- Incident.java              [NEW]
|   |   |-- IncidentStatus.java        [NEW]
|   |   |-- FileStatus.java
|   |   |-- EventType.java
|   |   +-- Severity.java
|   |-- integrity/
|   |   |-- HashCalculator.java
|   |   |-- BaselineManager.java
|   |   |-- IntegrityChecker.java
|   |   +-- FileMonitor.java           [NEW]
|   |-- logs/
|   |   |-- LogParser.java
|   |   |-- AuthenticationMonitor.java
|   |   +-- FirewallMonitor.java
|   |-- detection/
|   |   |-- DetectionEngine.java        [NEW]
|   |   |-- EventHistory.java          [NEW]
|   |   |-- IncidentManager.java       [NEW]
|   |   |-- EventCorrelator.java
|   |   +-- RiskScorer.java
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
+-- reports/                           (gitignored)
```
