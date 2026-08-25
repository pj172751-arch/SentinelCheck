# SentinelCheck v2.0 — Host Security Event Monitor Project Report

---

## 🎓 Cover Page

### LJ POLYTECHNIC
### A MINI PROJECT REPORT ON
# SentinelCheck v2.0
**(2025 - 2026)**

### JAVA PROGRAMMING

**Submitted by:**

| Sr. | Enrollment | Student Name |
|:---:|:---:|:---|
| 1 | 23012250910002 | Adhishri Vora |
| 2 | 23012250910012 | Maitri Chauhan |
| 3 | 23012250910020 | Dhruvi Patel |
| 4 | 23012250910024 | Krishna Ghoghari |
| 5 | 23012250910036 | Rushil Jogi |
| 6 | 23012250910039 | Kshiti Kadia |

---

## 1. PROJECT DESCRIPTION

### Introduction
Host-Based Intrusion Detection Systems (HIDS) are critical for auditing security events at the operating system layer. They verify configuration file integrity, parse local application logs (like logins and firewalls), and alert operators to indicators of compromise.

**SentinelCheck v2.0** is a lightweight, stateful host-based security monitoring application written in Java. It monitors directories for modifications in real-time, processes authentication logs using sliding windows, filters firewall connection drops, correlates cross-module temporal patterns, and offers interactive lifecycle incident tracking.

---

### Objectives of the Project
1. **Real-Time Directory Auditing**: Monitor directories for creations, deletions, or modifications of critical configuration assets.
2. **Log Intelligence Analytics**: Identify authentication brute-forcing and network scanning attempts using sliding-window rules.
3. **Cross-Module Attack Correlation**: Combine separate authentication and firewall drops from a single IP into a unified incident.
4. **Stateful Management**: Maintain state configurations (`OPEN`, `ACKNOWLEDGED`, `CLOSED`) with persistent audit trails.

---

### Technology Stack
* **Language**: Java 17 (JDK)
* **Core APIs**: `java.nio.file.WatchService` (real-time watchers), `java.security.MessageDigest` (SHA-256 baseline hashing).
* **Storage**: Persistent CSV text databases (`data/events.csv` and `data/incidents.csv`).

---

### Features of the Project
* **NIO File Watcher**: Features a 500ms debounce buffer to coalesce duplicate OS file modification triggers.
* **Baseline Verification**: Emits critical alerts on startup if the baseline configuration is tampered with.
* **Log Heuristic Rules**:
  - `AUTH-001` (Brute Force): 3+ failed logins within 5 minutes.
  - `AUTH-002` (Suspicious Success): Success immediately following consecutive failures.
  - `AUTH-003` (Multi-Account): 3+ accounts targeted by the same IP.
  - `FW-001` (Port Probing): DROP events targeting 5+ unique ports.
* **Correlations (`CORR-001`)**: Identifies multi-module temporal patterns.

---

## 2. MAIN SOURCE CODES

### A. Real-Time Directory Watcher (`FileMonitor.java`)
Uses `WatchService` and a 500ms debounce to track directory modification events.

```java
package sentinelcheck.integrity;

import sentinelcheck.model.*;
import java.io.File;
import java.nio.file.*;
import java.util.concurrent.*;

public class FileMonitor implements Runnable {
    private final Path monitorPath;
    private final BlockingQueue<SecurityEvent> eventQueue;
    private final WatchService watchService;
    private volatile boolean running;

    public FileMonitor(String dirPath, BlockingQueue<SecurityEvent> queue) throws Exception {
        this.monitorPath = Paths.get(dirPath);
        this.eventQueue = queue;
        this.watchService = FileSystems.getDefault().newWatchService();
        this.monitorPath.register(watchService, StandardWatchEventKinds.ENTRY_CREATE,
                                                StandardWatchEventKinds.ENTRY_MODIFY,
                                                StandardWatchEventKinds.ENTRY_DELETE);
    }

    @Override
    public void run() {
        running = true;
        while (running) {
            try {
                WatchKey key = watchService.poll(500, TimeUnit.MILLISECONDS);
                if (key == null) continue;

                // Debounce wait
                Thread.sleep(500);
                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();
                    Path fileName = (Path) event.context();
                    File file = monitorPath.resolve(fileName).toFile();

                    EventType type = EventType.FILE_MODIFIED;
                    if (kind == StandardWatchEventKinds.ENTRY_CREATE) type = EventType.FILE_NEW;
                    else if (kind == StandardWatchEventKinds.ENTRY_DELETE) type = EventType.FILE_MISSING;

                    SecurityEvent secEvent = new SecurityEvent(type, "LOCAL", "", file.getPath(), "");
                    eventQueue.put(secEvent);
                }
                key.reset();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {}
        }
    }
    public void stop() { this.running = false; }
    public boolean isRunning() { return this.running; }
}
```

### B. Security Rule Engine (`DetectionEngine.java`)
Checks sliding windows to evaluate rule triggers and returns explainable alerts.

```java
package sentinelcheck.detection;

import sentinelcheck.model.*;
import java.util.*;

public class DetectionEngine {
    private int authThreshold = 3;
    private int authWindowMinutes = 5;
    private int portDiversityThreshold = 5;

    public List<Alert> evaluateRules(List<SecurityEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        Map<String, List<SecurityEvent>> ipGroups = groupByIP(events);

        for (Map.Entry<String, List<SecurityEvent>> entry : ipGroups.entrySet()) {
            String ip = entry.getKey();
            List<SecurityEvent> ipEvents = entry.getValue();

            // Evaluate Brute Force (AUTH-001)
            long failedCount = countFailedLogins(ipEvents, authWindowMinutes);
            if (failedCount >= authThreshold) {
                alerts.add(new Alert("AUTH-001", "Brute Force Attempt", Severity.MEDIUM, 30));
            }

            // Evaluate Port Probing (FW-001)
            Set<Integer> uniquePorts = getDroppedPorts(ipEvents);
            if (uniquePorts.size() >= portDiversityThreshold) {
                alerts.add(new Alert("FW-001", "Port Probing Pattern", Severity.MEDIUM, 30));
            }
        }
        return alerts;
    }

    private Map<String, List<SecurityEvent>> groupByIP(List<SecurityEvent> events) {
        Map<String, List<SecurityEvent>> map = new HashMap<>();
        for (SecurityEvent e : events) {
            map.computeIfAbsent(e.getSourceIp(), k -> new ArrayList<>()).add(e);
        }
        return map;
    }
}
```

---

## 3. VERIFICATION SCREENSHOTS

Below are the screenshots captured during the CLI walkthrough:

### A. Main Dashboard Layout
Shows active monitoring status, file counts, severity tier, and active risk score.

![Main Menu Layout](C:/Users/Pooja/.gemini/antigravity-ide/brain/928f30d1-5f26-4481-aac8-61164f812138/screenshot1_main_menu.png)

---

### B. System Status View
Displays monitoring details, event metrics, baseline health verification, and threat statuses.

![System Status](C:/Users/Pooja/.gemini/antigravity-ide/brain/928f30d1-5f26-4481-aac8-61164f812138/screenshot2_system_status.png)

---

### C. Monitoring Submenu
Contains options for starting watchers, manual verification, and updating trusted file baselines.

![Monitoring Submenu](C:/Users/Pooja/.gemini/antigravity-ide/brain/928f30d1-5f26-4481-aac8-61164f812138/screenshot3_monitoring_submenu.png)

---

### D. File Integrity Verification Results
Result of a manual scan comparing current hashes to baseline.

![File Integrity Results](C:/Users/Pooja/.gemini/antigravity-ide/brain/928f30d1-5f26-4481-aac8-61164f812138/screenshot4_integrity_check.png)

---

### E. Security Analysis (Log Processors)
Output of parsing authentication and firewall files for threat rules evaluation.

![Log Analysis Summary](C:/Users/Pooja/.gemini/antigravity-ide/brain/928f30d1-5f26-4481-aac8-61164f812138/screenshot5_security_analysis.png)

---

### F. Security Events Log Timeline
Reverse-chronological log of all normalized security events.

![Security Events Log](C:/Users/Pooja/.gemini/antigravity-ide/brain/928f30d1-5f26-4481-aac8-61164f812138/screenshot6_events_log.png)

---

### G. Incident Management Submenu
Displays stateful incidents lists and lifecycle transitions.

![Incident Management List](C:/Users/Pooja/.gemini/antigravity-ide/brain/928f30d1-5f26-4481-aac8-61164f812138/screenshot7_incident_lifecycle.png)

---

### H. Incident Details & Rules Context
Shows active alerts, risk score, severity mapping, and detailed operator audit logs.

![Incident Details View](C:/Users/Pooja/.gemini/antigravity-ide/brain/928f30d1-5f26-4481-aac8-61164f812138/screenshot8_incident_details.png)

---

### I. Forensic Event Timeline
Detailed timestamp mapping of security events contributing to an active incident.

![Forensic Timeline](C:/Users/Pooja/.gemini/antigravity-ide/brain/928f30d1-5f26-4481-aac8-61164f812138/screenshot9_forensic_timeline.png)

---

## 4. CONCLUSION

SentinelCheck successfully implements an educational Host-Based Security Event Monitor in Java. By combining directory auditing, sliding-window log checks, temporal event correlation, and stateful lifecycle tracking, the project demonstrates how host-level visibility can be maintained cleanly in secure environments.
