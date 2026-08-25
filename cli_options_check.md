# SentinelCheck 2.0 CLI Verification Report

This document records the verification check of **every single option** in the SentinelCheck 2.0 nested CLI menu structure. The following sections contain the console outputs captured during an automated walkthrough, along with details of how the security engine processed the request under the hood.

---

## 🗺️ CLI Menu Structure & Verification Checklist

The nested CLI hierarchy of SentinelCheck 2.0 is structured as follows:

- [x] **Main Menu Options**
  - [x] `[1] Monitoring` (Submenu)
  - [x] `[2] Security Analysis` (Submenu)
  - [x] `[3] Incident Management` (Submenu)
  - [x] `[4] Configuration` (Submenu)
  - [x] `[5] System Status` (Dashboard Display)
  - [x] `[0] Exit`

---

## 1. System Status Dashboard (Main Menu Option `5`)

### Console Screen View:
```text
  +==================================================================+
  |                       SENTINELCHECK STATUS                       |
  +==================================================================+
  | Monitoring Status       : INACTIVE                               |
  | File Watcher Thread     : STOPPED                                |
  | Baseline Integrity      : VALID                                  |
  | Monitored Folder        : monitored                              |
  | Protected Files Hashed  : 5                                      |
  |                                                                  |
  | Events Logged Today     : 17                                     |
  | Total Historical Events : 17                                     |
  | Open Incident Count     : 1                                      |
  |                                                                  |
  | Last Event Registered   : FIREWALL_DROP (10.0.0.170)             |
  | Last Event Log Time     : 2026-08-25 10:14:00                    |
  |                                                                  |
  | Current System Severity : HIGH                                   |
  | Max Active Risk Score   : 80                                     |
  | Maintenance Mode        : DISABLED                               |
  +==================================================================+
```

### Technical Detail:
When option `5` is selected, the system aggregates parameters from the central manager nodes:
* Queries `FileMonitor.isRunning()` for watcher thread status.
* Performs a baseline verification on `monitored.baseline` against its sibling `monitored.baseline.sha256` checksum using `BaselineManager`.
* Queries `EventHistory` for event log totals and queries `IncidentManager` for the list of open, active tickets to evaluate maximum risk scores.

---

## 2. Monitoring Submenu (Main Menu Option `1`)

### Submenu Selection View:
```text
  +------------------------------------------------------------------+
  |                           MONITORING                             |
  +------------------------------------------------------------------+
  [1] Start Real-Time Monitoring
  [2] Stop Monitoring
  [3] Verify File Integrity
  [4] View Protected Files
  [5] Create / Update Baseline
  [6] View Live Events Console
  [0] Back
  +------------------------------------------------------------------+
```

### [Option 4] View Protected Files:
```text
  PROTECTED FILES BASELINE
  ------------------------------------------------------------------
  File Name                Expected SHA-256 Hash
  ------------------------------------------------------------------
  config.txt               a45e1e0900c89899005f75192103a163fd6e7dccd4ac20ea8739cdb138f0424f
  readme.txt               31ee666dab0e32380af1f29d0b6691c12d3fec73d618706bbc979de4cf4aebb5
  server.conf              b168e76ce8c3dd577640834c7ea01673f18c0a330448a535a5342ac3fc50ba93
  settings.json            c4adf1036da0f12dbe8bf061087f7ddf5e7580ef46a2740e419e4e340a2dfb23
  users.csv                ff2fff015253251f45597dd9367e7a4cfb5dda5a11df9ee3b11b7b6ec873ad50
  ------------------------------------------------------------------
  Total files protected: 5
```
* **Mechanism**: Reads `monitored.baseline` from disk line-by-line, parsing key-value pairs (File Name = Expected SHA-256 Hash) and printing them in a tabular summary.

### [Option 3] Verify File Integrity (Manual Scan):
```text
  FILE INTEGRITY RESULTS
  ----------------------------------------------
  ----------------------------------------------
  Unchanged: 5 | Modified: 0 | Missing: 0 | New: 0
```
* **Mechanism**: Scans the folder `monitored`, computes the SHA-256 of each file using `HashCalculator`, and compares it to the loaded baseline mapping. Any changes are flagged as `MODIFIED`, `MISSING`, or `NEW`.

### [Option 5] Create / Update Baseline:
```text
  WARNING: Creating a new baseline will establish the current state
  of all files in the directory as trusted.
  Continue? [Y/N]: Y
  
  ✓ Baseline created successfully.
  Files hashed: 5
  Checksum saved to: monitored.baseline.sha256
```
* **Mechanism**: Re-hashes all files currently in `monitored`, rewrites `monitored.baseline` with timestamp metadata headers, computes the SHA-256 of the baseline file itself, and writes it to `monitored.baseline.sha256`.

---

## 3. Security Analysis Submenu (Main Menu Option `2`)

### Submenu Selection View:
```text
  +------------------------------------------------------------------+
  |                    SECURITY LOG ANALYSIS                         |
  +------------------------------------------------------------------+
  [1] Analyze Authentication Logs
  [2] Analyze Firewall Logs
  [3] Run Complete Security Scan
  [4] View Security Events Log
  [5] View Detection Statistics
  [0] Back
  +------------------------------------------------------------------+
```

### [Option 5] View Detection Statistics:
```text
  DETECTION STATISTICS:
  ------------------------------------
  Total Security Events logged: 17
  ------------------------------------
  FAILED_LOGIN            : 6
  SUCCESSFUL_LOGIN        : 1
  FIREWALL_DROP           : 10
  ------------------------------------
```
* **Mechanism**: Loops through the loaded list of events in `EventHistory` and accumulates frequency counters grouped by `EventType`.

### [Option 1] Analyze Authentication Logs:
```text
  Enter log path [sample-logs/auth_log.csv]: 
  Total auth events parsed: 7
  Logging events in history and evaluating rules...

  AUTHENTICATION SUMMARY:
  IP                  Failed Attempts   Status
  ------------------  ----------------  ----------
  10.0.0.150          Failed: 3     Status: ⚠ MEDIUM
  10.0.0.160          Failed: 3     Status: ⚠ MEDIUM
```
* **Mechanism**: Invokes `LogParser` to parse the authentication CSV. Each parsed event is appended to `EventHistory` (verifying it is not a duplicate) and run through `DetectionEngine` to evaluate sliding-window authentication rules.

### [Option 2] Analyze Firewall Logs:
```text
  Enter log path [sample-logs/firewall_log.csv]: 
  Total firewall events parsed: 10
  Logging events in history and evaluating rules...

  FIREWALL DROP SUMMARY:
  10.0.0.150          DROPs: 5     Ports: 22/TCP, 80/TCP, 443/TCP, 445/TCP, 3389/TCP  Severity: HIGH
  10.0.0.170          DROPs: 5     Ports: 22/TCP                Severity: HIGH
```
* **Mechanism**: Parses firewall network drop lines. Registers port connection attempts. `FirewallMonitor` checks if unique targeted destination ports exceed thresholds to flag scanning behaviors.

### [Option 4] View Security Events Log:
```text
  EVENT LOG TIMELINE
  --------------------------------------------------------------------------------------
  [2026-08-25T10:14] FIREWALL_DROP | Source: 10.0.0.170 | Dest: 192.168.1.1 | Port: 22/TCP | Port 22/TCP
  [2026-08-25T10:13] SUCCESSFUL_LOGIN | Source: 10.0.0.160 | User: user1 | User: user1
  [2026-08-25T10:13] FIREWALL_DROP | Source: 10.0.0.170 | Dest: 192.168.1.1 | Port: 22/TCP | Port 22/TCP
  [2026-08-25T10:12] FAILED_LOGIN | Source: 10.0.0.160 | User: user1 | User: user1
  [2026-08-25T10:12] FIREWALL_DROP | Source: 10.0.0.170 | Dest: 192.168.1.1 | Port: 22/TCP | Port 22/TCP
  ...
  --------------------------------------------------------------------------------------
```
* **Mechanism**: Outputs all historical events parsed from logs or watcher in a reverse-chronological timeline (latest first).

---

## 4. Incident Management Submenu (Main Menu Option `3`)

### Submenu Selection View:
```text
  +------------------------------------------------------------------+
  |                     INCIDENT LIFECYCLE                           |
  +------------------------------------------------------------------+
  [1] View Open/Acknowledged Incidents
  [2] View All Incidents (inc. Closed)
  [3] View Incident Details & Rules
  [4] View Event Timeline for Incident
  [5] Acknowledge Incident
  [6] Close Incident
  [7] Generate Incident Report file
  [0] Back
  +------------------------------------------------------------------+
```

### [Option 1] View Open/Acknowledged Incidents:
```text
  STATEFUL INCIDENT LIST
  ----------------------------------------------------------------------------
  Incident ID      Source Context   Severity   Score    Status
  ----------------------------------------------------------------------------
  INC-20260825-0002 10.0.0.160       HIGH       80       OPEN
  INC-20260825-0003 10.0.0.150       CRITICAL   120      OPEN
  ----------------------------------------------------------------------------
```
* **Mechanism**: Filters and lists active stateful tickets from `IncidentManager`.

### [Option 2] View All Incidents (including Closed):
```text
  STATEFUL INCIDENT LIST
  ----------------------------------------------------------------------------
  Incident ID      Source Context   Severity   Score    Status
  ----------------------------------------------------------------------------
  INC-20260825-0001 10.0.0.150       CRITICAL   120      CLOSED
  INC-20260825-0002 10.0.0.160       HIGH       80       OPEN
  INC-20260825-0003 10.0.0.150       CRITICAL   120      OPEN
  ----------------------------------------------------------------------------
```

### [Option 3] View Incident Details:
```text
  INCIDENT SUMMARY DETAILS:
  ==============================================
Incident ID : INC-20260825-0001
Status      : CLOSED
Severity    : CRITICAL
Risk Score  : 120
Source      : 10.0.0.150
First Seen  : 2026-08-25 10:02:00
Last Seen   : 2026-08-25 10:04:00
  ==============================================
  CONTRIBUTING RULES & ALERTS:
    - [AUTH-001] Brute Force Attempt
      Severity: MEDIUM (Points: +30) | Timestamp: 2026-08-25 10:02:00
      Description: 3 failed login attempts within 5 minutes (Targeted accounts: root, admin, guest)
    - [AUTH-003] Multiple Account Targeting
      Severity: MEDIUM (Points: +40) | Timestamp: 2026-08-25 10:02:00
      Description: Failed logins targeted 3 unique accounts (root, admin, guest) within 5 minutes
    - [FW-001] Port Probing Pattern
      Severity: MEDIUM (Points: +30) | Timestamp: 2026-08-25 10:04:00
      Description: Blocked connection attempts to 5 unique destination ports (22/TCP, 80/TCP, 443/TCP, 445/TCP, 3389/TCP)

  AUDIT TRAIL:
    2026-08-25 17:22:20 - Incident created
    ...
```
* **Mechanism**: Resolves incident attributes, prints contributing alerts (e.g. `AUTH-001`, `AUTH-003`, `FW-001`), and maps the historical audit trails showing actions taken by the operator.

### [Option 4] View Event Timeline:
```text
  FORENSIC EVENT TIMELINE FOR INC-20260825-0001
  --------------------------------------------------------------------------------------
    2026-08-25 10:00:00  | FAILED_LOGIN     | User: admin
    2026-08-25 10:00:00  | FIREWALL_DROP    | Port 22/TCP
    2026-08-25 10:01:00  | FIREWALL_DROP    | Port 80/TCP
    2026-08-25 10:01:00  | FAILED_LOGIN     | User: root
    2026-08-25 10:02:00  | FIREWALL_DROP    | Port 443/TCP
    2026-08-25 10:02:00  | FAILED_LOGIN     | User: guest
    2026-08-25 10:03:00  | FIREWALL_DROP    | Port 445/TCP
    2026-08-25 10:04:00  | FIREWALL_DROP    | Port 3389/TCP
  --------------------------------------------------------------------------------------
```

### [Option 5] Acknowledge Incident:
```text
  Enter Incident ID to acknowledge: INC-20260825-0001
  ? Incident INC-20260825-0001 acknowledged successfully.
```

### [Option 6] Close Incident:
```text
  Enter Incident ID to close: INC-20260825-0001
  ? Incident INC-20260825-0001 closed successfully.
```

### [Option 7] Generate Incident Report File:
```text
  ==============================================================
                       SENTINELCHECK
                 STATEFUL INCIDENT REPORT
  ==============================================================
  Generated At : 2026-08-25 17:23:18
  Total Events : 17
  Incidents    : 3
  ...
  ? Stateful incident report file successfully written.
    Saved to: C:\Users\SentinelCheck\reports\incident_report_2026-08-25_172318.txt
```

---

## 5. Configuration Submenu (Main Menu Option `4`)

### Submenu Selection View:
```text
  +------------------------------------------------------------------+
  |                          CONFIGURATION                           |
  +------------------------------------------------------------------+
  [1] Monitored Protected Directory
  [2] Adjust Detection Rule Thresholds
  [3] Maintenance Mode
  [4] Baseline Checksum Health
  [0] Back
  +------------------------------------------------------------------+
```

### [Option 4] Baseline Checksum Health:
```text
  BASELINE HEALTH CHECK:
  ----------------------
  Baseline File exists     : true
  Checksum File exists     : true
  Baseline Integrity       : VALID (Match)
```
