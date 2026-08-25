package sentinelcheck;

import sentinelcheck.detection.DetectionEngine;
import sentinelcheck.detection.EventCorrelator;
import sentinelcheck.detection.EventHistory;
import sentinelcheck.detection.IncidentManager;
import sentinelcheck.detection.RiskScorer;
import sentinelcheck.integrity.BaselineManager;
import sentinelcheck.integrity.FileMonitor;
import sentinelcheck.integrity.IntegrityChecker;
import sentinelcheck.logs.AuthenticationMonitor;
import sentinelcheck.logs.FirewallMonitor;
import sentinelcheck.logs.LogParser;
import sentinelcheck.model.Alert;
import sentinelcheck.model.EventType;
import sentinelcheck.model.FileRecord;
import sentinelcheck.model.FileStatus;
import sentinelcheck.model.Incident;
import sentinelcheck.model.IncidentStatus;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;
import sentinelcheck.report.IncidentReportGenerator;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

/**
 * SentinelCheck v2.0 — Stateful Host-Based Security Event Monitor
 *
 * Provides a nested CLI, real-time file monitoring, sliding window rules,
 * incident management, baseline protection, and configuration settings.
 */
public class Main {

    // Default paths
    private static String monitoredDir = "monitored";
    private static String logDir       = "sample-logs";
    private static final String BASELINE_SUFFIX = ".baseline";
    private static final String AUTH_LOG      = "auth_log.csv";
    private static final String FIREWALL_LOG  = "firewall_log.csv";
    private static final String REPORTS_DIR   = "reports";

    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter FILE_TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss");

    // Central components
    private static RiskScorer riskScorer;
    private static EventHistory eventHistory;
    private static DetectionEngine detectionEngine;
    private static IncidentManager incidentManager;
    private static FileMonitor fileMonitor;
    private static BaselineManager baselineManager;

    private static boolean liveViewActive = false;

    public static void main(String[] args) {
        // 1. Initialize core engines
        riskScorer = new RiskScorer();
        eventHistory = new EventHistory();
        detectionEngine = new DetectionEngine(riskScorer);
        incidentManager = new IncidentManager(riskScorer);
        baselineManager = new BaselineManager();

        detectionEngine.setEventHistory(eventHistory);
        detectionEngine.setIncidentManager(incidentManager);

        // 2. Load historical events and incidents (Restore state)
        eventHistory.loadEvents();
        // Regenerate alerts from history to correctly link incident references
        List<Alert> reloadedAlerts = detectionEngine.processAllEvents(eventHistory.getEvents());
        incidentManager.loadIncidents(reloadedAlerts);

        // 3. Verify Baseline Integrity on start
        checkBaselineIntegrityOnStartup();

        // 4. Check for command-line arguments (Batch non-interactive scan)
        if (args.length > 0 && args[0].equals("--scan")) {
            for (int i = 1; i < args.length; i++) {
                if (args[i].equals("--dir") && i + 1 < args.length) {
                    monitoredDir = args[++i];
                } else if (args[i].equals("--logs") && i + 1 < args.length) {
                    logDir = args[++i];
                }
            }
            runCompleteScan(monitoredDir, logDir, false);
            return;
        }

        // 5. Run interactive menu loop with standard input exhaustion handling
        try {
            Scanner scanner = new Scanner(System.in);
            runMainMenu(scanner);
            scanner.close();
        } catch (java.util.NoSuchElementException e) {
            System.out.println("\n  [INFO] Standard input exhausted. Stopping real-time services and exiting.");
            if (fileMonitor != null && fileMonitor.isRunning()) {
                fileMonitor.stop();
            }
            System.exit(0);
        }
    }

    private static void checkBaselineIntegrityOnStartup() {
        File baselineFile = new File(monitoredDir + BASELINE_SUFFIX);
        if (baselineFile.exists()) {
            boolean valid = baselineManager.verifyBaselineIntegrity(baselineFile);
            if (!valid) {
                System.out.println("\n  🚨 [CRITICAL ALERT] Sibling baseline integrity checksum mismatch!");
                System.out.println("     The baseline configuration file has been modified externally!");

                // Log a critical security event
                SecurityEvent tamperEvent = new SecurityEvent(
                        LocalDateTime.now(),
                        EventType.BASELINE_TAMPERED,
                        "LOCAL",
                        "",
                        monitoredDir + BASELINE_SUFFIX,
                        "",
                        0,
                        "",
                        "Baseline integrity checksum validation failed (TAMPERED)",
                        "UNAUTHORIZED"
                );
                eventHistory.addEvent(tamperEvent);
                detectionEngine.processNewEvent(tamperEvent);
            }
        }
    }

    // ─── Main Menu ────────────────────────────────────────────────

    private static void runMainMenu(Scanner scanner) {
        boolean running = true;
        while (running) {
            printMainMenuHeader();
            System.out.print("  Select option: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    runMonitoringMenu(scanner);
                    break;
                case "2":
                    runSecurityAnalysisMenu(scanner);
                    break;
                case "3":
                    runIncidentManagementMenu(scanner);
                    break;
                case "4":
                    runConfigurationMenu(scanner);
                    break;
                case "5":
                    viewSystemStatus();
                    System.out.println("\n  Press Enter to continue...");
                    scanner.nextLine();
                    break;
                case "0":
                    System.out.println("\n  Stopping real-time services...");
                    if (fileMonitor != null && fileMonitor.isRunning()) {
                        fileMonitor.stop();
                    }
                    System.out.println("  Exiting SentinelCheck. Stay secure.\n");
                    running = false;
                    break;
                default:
                    System.out.println("\n  Invalid option. Please try again.\n");
            }
        }
    }

    private static void printMainMenuHeader() {
        // Dynamic dashboard components
        String watcherStatus = (fileMonitor != null && fileMonitor.isRunning()) ? "ACTIVE" : "INACTIVE";
        int openIncidentsCount = 0;
        int maxRisk = 0;
        for (Incident inc : incidentManager.getIncidents()) {
            if (inc.getStatus() != IncidentStatus.CLOSED) {
                openIncidentsCount++;
                if (inc.getRiskScore() > maxRisk) {
                    maxRisk = inc.getRiskScore();
                }
            }
        }
        Severity currentRisk = riskScorer.calculateSeverity(maxRisk);
        File baselineFile = new File(monitoredDir + BASELINE_SUFFIX);
        int protectedFilesCount = 0;
        if (baselineFile.exists()) {
            try {
                protectedFilesCount = baselineManager.loadBaseline(baselineFile).size();
            } catch (IOException e) {
                // Ignore
            }
        }

        String coloredState = watcherStatus.equals("ACTIVE") ? "\u001B[32mACTIVE\u001B[0m" : "\u001B[31mINACTIVE\u001B[0m";
        String coloredRisk;
        if (currentRisk == Severity.CRITICAL) {
            coloredRisk = "\u001B[31mCRITICAL\u001B[0m";
        } else if (currentRisk == Severity.HIGH) {
            coloredRisk = "\u001B[35mHIGH\u001B[0m";
        } else if (currentRisk == Severity.MEDIUM) {
            coloredRisk = "\u001B[33mMEDIUM\u001B[0m";
        } else {
            coloredRisk = "\u001B[32mLOW\u001B[0m";
        }

        System.out.println();
        printBorder();
        printCenteredRow("SENTINELCHECK");
        printCenteredRow("HOST SECURITY MONITOR v2.0");
        printBorder();
        
        String statusRow = String.format("Status: MONITORING %s    Risk: %s    Score: %d", coloredState, coloredRisk, maxRisk);
        printRow(statusRow);
        
        String infoRow = String.format("Protected Files: %d    Open Incidents: %d", protectedFilesCount, openIncidentsCount);
        printRow(infoRow);
        
        printBorder();
        System.out.println("  [1] Monitoring");
        System.out.println("  [2] Security Analysis");
        System.out.println("  [3] Incident Management");
        System.out.println("  [4] Configuration");
        System.out.println("  [5] System Status");
        System.out.println("  [0] Exit");
        printBorder();
        System.out.println();
    }

    // ─── Submenu 1: Monitoring ────────────────────────────────────

    private static void runMonitoringMenu(Scanner scanner) {
        boolean back = false;
        while (!back) {
            System.out.println("\n  +------------------------------------------------------------------+");
            System.out.println("  |                           MONITORING                             |");
            System.out.println("  +------------------------------------------------------------------+");
            System.out.println("  [1] Start Real-Time Monitoring");
            System.out.println("  [2] Stop Monitoring");
            System.out.println("  [3] Verify File Integrity");
            System.out.println("  [4] View Protected Files");
            System.out.println("  [5] Create / Update Baseline");
            System.out.println("  [6] View Live Events Console");
            System.out.println("  [0] Back");
            System.out.println("  +------------------------------------------------------------------+");
            System.out.print("  Select option: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    startRealTimeMonitoring(scanner);
                    break;
                case "2":
                    stopRealTimeMonitoring();
                    break;
                case "3":
                    verifyFileIntegrity();
                    break;
                case "4":
                    viewProtectedFiles();
                    break;
                case "5":
                    createBaseline(scanner);
                    break;
                case "6":
                    enterLiveEventsConsole(scanner);
                    break;
                case "0":
                    back = true;
                    break;
                default:
                    System.out.println("\n  Invalid option. Please try again.");
            }
        }
    }

    private static void startRealTimeMonitoring(Scanner scanner) {
        File directory = new File(monitoredDir);
        File baselineFile = new File(monitoredDir + BASELINE_SUFFIX);

        if (!directory.isDirectory()) {
            System.out.println("  [ERROR] Protected directory not found: " + monitoredDir);
            return;
        }

        if (!baselineFile.exists()) {
            System.out.println("  [ERROR] Baseline file not found. Please create a baseline first (Option 5).");
            return;
        }

        // Verify baseline integrity before starting
        if (!baselineManager.verifyBaselineIntegrity(baselineFile)) {
            System.out.println("  [ERROR] Cannot start monitoring: Sibling baseline integrity checksum mismatch!");
            return;
        }

        try {
            if (fileMonitor == null) {
                fileMonitor = new FileMonitor(directory, baselineFile, eventHistory, detectionEngine);
            }
            fileMonitor.setMaintenanceMode(incidentManager.isMaintenanceMode());
            fileMonitor.start();
            
            System.out.println("\n  🟢 REAL-TIME MONITORING ACTIVE");
            System.out.println("  File watcher initialized on: " + directory.getAbsolutePath());
            
            enterLiveEventsConsole(scanner);
        } catch (IOException e) {
            System.out.println("  [ERROR] Failed to start watcher service: " + e.getMessage());
        }
    }

    private static void stopRealTimeMonitoring() {
        if (fileMonitor != null && fileMonitor.isRunning()) {
            fileMonitor.stop();
            System.out.println("\n  🛑 REAL-TIME MONITORING STOPPED");
        } else {
            System.out.println("\n  Watcher is not currently running.");
        }
    }

    private static void enterLiveEventsConsole(Scanner scanner) {
        if (fileMonitor == null || !fileMonitor.isRunning()) {
            System.out.println("\n  [INFO] Start Real-Time Monitoring first.");
            return;
        }

        System.out.println("\n  +------------------------------------------------------------------+");
        System.out.println("  |                    LIVE SECURITY EVENT STREAM                    |");
        System.out.println("  |                   Press [Enter] to stop view                     |");
        System.out.println("  +------------------------------------------------------------------+");
        System.out.println("  Listening for modifications in protected folder...");
        
        liveViewActive = true;
        // Start printing live alerts by hook or console
        // We will mock/spawn a small loop checking if the user pressed Enter
        // while the background thread does the printing.
        
        // We set liveViewActive in Main so the FileMonitor knows it can output alert screens.
        // We block on scanner.nextLine() to let the user view output.
        // Actually, print a prompt:
        System.out.println("  [LIVE] Streaming active events...");

        // Start checking if the user wants to escape
        scanner.nextLine();
        
        liveViewActive = false;
        System.out.println("  Returned to Menu. File watcher continues running in the background.");
    }

    public static boolean isLiveViewActive() {
        return liveViewActive;
    }

    private static void verifyFileIntegrity() {
        File directory = new File(monitoredDir);
        File baselineFile = new File(monitoredDir + BASELINE_SUFFIX);

        if (!directory.isDirectory()) {
            System.out.println("  [ERROR] Monitored directory not found: " + monitoredDir);
            return;
        }

        if (!baselineFile.exists()) {
            System.out.println("  [ERROR] Baseline not found. Please create one first.");
            return;
        }

        // Verify baseline file itself
        if (!baselineManager.verifyBaselineIntegrity(baselineFile)) {
            System.out.println("  🚨 [ALERT] Baseline file integrity checksum mismatch! The baseline file has been modified.");
            SecurityEvent tamperEvent = new SecurityEvent(
                    LocalDateTime.now(), EventType.BASELINE_TAMPERED, "LOCAL",
                    "", baselineFile.getName(), "", 0, "", 
                    "Baseline integrity checksum validation failed (TAMPERED)", "UNAUTHORIZED"
            );
            eventHistory.addEvent(tamperEvent);
            detectionEngine.processNewEvent(tamperEvent);
            return;
        }

        try {
            IntegrityChecker checker = new IntegrityChecker();
            List<FileRecord> records = checker.verifyIntegrity(directory, baselineFile);

            System.out.println("\n  FILE INTEGRITY RESULTS");
            System.out.println("  " + "-".repeat(46));

            int unchanged = 0, modified = 0, missing = 0, newFiles = 0;
            LocalDateTime now = LocalDateTime.now();

            for (FileRecord record : records) {
                String authContext = incidentManager.isMaintenanceMode() ? "MAINTENANCE" : "UNAUTHORIZED";
                
                switch (record.getStatus()) {
                    case UNCHANGED:
                        unchanged++;
                        break;
                    case MODIFIED:
                        modified++;
                        System.out.println("  [MODIFIED] " + record.getFilePath());
                        SecurityEvent modEvent = new SecurityEvent(now, EventType.FILE_MODIFIED, 
                                record.getFilePath(), record.getNewHash(), "Modified: " + record.getFilePath(), authContext);
                        eventHistory.addEvent(modEvent);
                        detectionEngine.processNewEvent(modEvent);
                        break;
                    case MISSING:
                        missing++;
                        System.out.println("  [MISSING]  " + record.getFilePath());
                        SecurityEvent missEvent = new SecurityEvent(now, EventType.FILE_MISSING, 
                                record.getFilePath(), record.getOldHash(), "Missing: " + record.getFilePath(), authContext);
                        eventHistory.addEvent(missEvent);
                        detectionEngine.processNewEvent(missEvent);
                        break;
                    case NEW:
                        newFiles++;
                        System.out.println("  [NEW]      " + record.getFilePath());
                        SecurityEvent newEvent = new SecurityEvent(now, EventType.FILE_NEW, 
                                record.getFilePath(), record.getNewHash(), "New untracked: " + record.getFilePath(), authContext);
                        eventHistory.addEvent(newEvent);
                        detectionEngine.processNewEvent(newEvent);
                        break;
                }
            }

            System.out.println("  " + "-".repeat(46));
            System.out.printf("  Unchanged: %d | Modified: %d | Missing: %d | New: %d%n",
                    unchanged, modified, missing, newFiles);

        } catch (IOException e) {
            System.out.println("  [ERROR] Verification failed: " + e.getMessage());
        }
    }

    private static void viewProtectedFiles() {
        File baselineFile = new File(monitoredDir + BASELINE_SUFFIX);
        if (!baselineFile.exists()) {
            System.out.println("\n  [INFO] Baseline not found. No protected files.");
            return;
        }

        try {
            Map<String, String> baseline = baselineManager.loadBaseline(baselineFile);
            System.out.println("\n  PROTECTED FILES BASELINE");
            System.out.println("  " + "-".repeat(66));
            System.out.printf("  %-24s %s\n", "File Name", "Expected SHA-256 Hash");
            System.out.println("  " + "-".repeat(66));
            for (Map.Entry<String, String> entry : baseline.entrySet()) {
                System.out.printf("  %-24s %s\n", entry.getKey(), entry.getValue());
            }
            System.out.println("  " + "-".repeat(66));
            System.out.println("  Total files protected: " + baseline.size());
        } catch (IOException e) {
            System.out.println("  [ERROR] Failed to load baseline: " + e.getMessage());
        }
    }

    private static void createBaseline(Scanner scanner) {
        System.out.println("\n  +------------------------------------------------------------------+");
        System.out.println("  |                       BASELINE MANAGER                           |");
        System.out.println("  +------------------------------------------------------------------+");
        System.out.println("  WARNING: Creating a new baseline will establish the current state");
        System.out.println("  of all files in the directory as trusted.");
        System.out.print("  Continue? [Y/N]: ");
        String confirm = scanner.nextLine().trim();

        if (!confirm.equalsIgnoreCase("Y")) {
            System.out.println("  Baseline creation cancelled.");
            return;
        }

        File directory = new File(monitoredDir);
        File baselineFile = new File(monitoredDir + BASELINE_SUFFIX);

        if (!directory.isDirectory()) {
            System.out.println("  [ERROR] Monitored directory not found: " + monitoredDir);
            return;
        }

        try {
            int fileCount = baselineManager.createBaseline(directory, baselineFile);
            System.out.println("\n  ✓ Baseline created successfully.");
            System.out.println("  Files hashed: " + fileCount);
            System.out.println("  Checksum saved to: " + baselineFile.getName() + ".sha256");
        } catch (IOException e) {
            System.out.println("  [ERROR] Failed to create baseline: " + e.getMessage());
        }
    }

    // ─── Submenu 2: Security Analysis ──────────────────────────────

    private static void runSecurityAnalysisMenu(Scanner scanner) {
        boolean back = false;
        while (!back) {
            System.out.println("\n  +------------------------------------------------------------------+");
            System.out.println("  |                    SECURITY LOG ANALYSIS                         |");
            System.out.println("  +------------------------------------------------------------------+");
            System.out.println("  [1] Analyze Authentication Logs");
            System.out.println("  [2] Analyze Firewall Logs");
            System.out.println("  [3] Run Complete Security Scan");
            System.out.println("  [4] View Security Events Log");
            System.out.println("  [5] View Detection Statistics");
            System.out.println("  [0] Back");
            System.out.println("  +------------------------------------------------------------------+");
            System.out.print("  Select option: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    analyzeAuthLogs(scanner);
                    break;
                case "2":
                    analyzeFirewallLogs(scanner);
                    break;
                case "3":
                    runCompleteScan(monitoredDir, logDir, true);
                    break;
                case "4":
                    viewSecurityEvents(scanner);
                    break;
                case "5":
                    viewDetectionStatistics();
                    break;
                case "0":
                    back = true;
                    break;
                default:
                    System.out.println("\n  Invalid option. Please try again.");
            }
        }
    }

    private static void analyzeAuthLogs(Scanner scanner) {
        System.out.print("\n  Enter log path [" + logDir + "/" + AUTH_LOG + "]: ");
        String pathInput = scanner.nextLine().trim();
        File logFile = pathInput.isEmpty() ? new File(logDir, AUTH_LOG) : new File(pathInput);

        if (!logFile.exists()) {
            System.out.println("  [ERROR] File not found: " + logFile.getPath());
            return;
        }

        try {
            LogParser parser = new LogParser();
            List<SecurityEvent> events = parser.parseAuthLog(logFile);

            System.out.println("\n  Total auth events parsed: " + events.size());
            System.out.println("  Logging events in history and evaluating rules...");

            for (SecurityEvent e : events) {
                eventHistory.addEvent(e);
                detectionEngine.processNewEvent(e);
            }

            // Print legacy summary table
            List<AuthenticationMonitor.AuthResult> authResults = detectionEngine.getAuthMonitor().analyzeAuthentication(events);
            System.out.println("\n  AUTHENTICATION SUMMARY:");
            System.out.printf("  %-18s  %-16s  %s%n", "IP", "Failed Attempts", "Status");
            System.out.printf("  %-18s  %-16s  %s%n", "-".repeat(18), "-".repeat(16), "-".repeat(10));
            for (AuthenticationMonitor.AuthResult result : authResults) {
                System.out.println("  " + result);
            }

        } catch (IOException e) {
            System.out.println("  [ERROR] Failed to analyze auth log: " + e.getMessage());
        }
    }

    private static void analyzeFirewallLogs(Scanner scanner) {
        System.out.print("\n  Enter log path [" + logDir + "/" + FIREWALL_LOG + "]: ");
        String pathInput = scanner.nextLine().trim();
        File logFile = pathInput.isEmpty() ? new File(logDir, FIREWALL_LOG) : new File(pathInput);

        if (!logFile.exists()) {
            System.out.println("  [ERROR] File not found: " + logFile.getPath());
            return;
        }

        try {
            LogParser parser = new LogParser();
            List<SecurityEvent> events = parser.parseFirewallLog(logFile);

            System.out.println("\n  Total firewall events parsed: " + events.size());
            System.out.println("  Logging events in history and evaluating rules...");

            for (SecurityEvent e : events) {
                eventHistory.addEvent(e);
                detectionEngine.processNewEvent(e);
            }

            // Print legacy summary
            List<FirewallMonitor.FirewallResult> fwResults = detectionEngine.getFirewallMonitor().analyzeFirewall(events);
            System.out.println("\n  FIREWALL DROP SUMMARY:");
            for (FirewallMonitor.FirewallResult result : fwResults) {
                System.out.println("  " + result);
            }

        } catch (IOException e) {
            System.out.println("  [ERROR] Failed to analyze firewall log: " + e.getMessage());
        }
    }

    private static void viewSecurityEvents(Scanner scanner) {
        List<SecurityEvent> allEvents = eventHistory.getEvents();
        if (allEvents.isEmpty()) {
            System.out.println("\n  [INFO] No events registered in history.");
            return;
        }

        System.out.println("\n  FILTER SECURITY EVENTS:");
        System.out.println("  [1] View All Events (Latest First)");
        System.out.println("  [2] Filter by Event Type");
        System.out.println("  [3] Filter by IP");
        System.out.print("  Select option: ");
        String choice = scanner.nextLine().trim();

        List<SecurityEvent> filtered = new ArrayList<>(allEvents);
        filtered.sort((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()));

        if (choice.equals("2")) {
            System.out.print("  Enter event type (e.g. FAILED_LOGIN, FILE_MODIFIED): ");
            String typeStr = scanner.nextLine().trim().toUpperCase();
            filtered.removeIf(e -> !e.getEventType().name().equals(typeStr));
        } else if (choice.equals("3")) {
            System.out.print("  Enter source IP (or LOCAL): ");
            String ipStr = scanner.nextLine().trim();
            filtered.removeIf(e -> !e.getSourceIP().equalsIgnoreCase(ipStr));
        }

        System.out.println("\n  EVENT LOG TIMELINE");
        System.out.println("  " + "-".repeat(86));
        for (SecurityEvent e : filtered) {
            System.out.println("  " + e);
        }
        System.out.println("  " + "-".repeat(86));
        System.out.println("  Total matching events: " + filtered.size());
    }

    private static void viewDetectionStatistics() {
        List<SecurityEvent> allEvents = eventHistory.getEvents();
        int totalEvents = allEvents.size();

        Map<EventType, Integer> typeCounts = new HashMap<>();
        for (SecurityEvent e : allEvents) {
            typeCounts.put(e.getEventType(), typeCounts.getOrDefault(e.getEventType(), 0) + 1);
        }

        System.out.println("\n  DETECTION STATISTICS:");
        System.out.println("  " + "-".repeat(36));
        System.out.println("  Total Security Events logged: " + totalEvents);
        System.out.println("  " + "-".repeat(36));
        for (Map.Entry<EventType, Integer> entry : typeCounts.entrySet()) {
            System.out.printf("  %-24s: %d\n", entry.getKey(), entry.getValue());
        }
        System.out.println("  " + "-".repeat(36));
    }

    // ─── Submenu 3: Incident Management ────────────────────────────

    private static void runIncidentManagementMenu(Scanner scanner) {
        boolean back = false;
        while (!back) {
            System.out.println("\n  +------------------------------------------------------------------+");
            System.out.println("  |                     INCIDENT LIFECYCLE                           |");
            System.out.println("  +------------------------------------------------------------------+");
            System.out.println("  [1] View Open/Acknowledged Incidents");
            System.out.println("  [2] View All Incidents (inc. Closed)");
            System.out.println("  [3] View Incident Details & Rules");
            System.out.println("  [4] View Event Timeline for Incident");
            System.out.println("  [5] Acknowledge Incident");
            System.out.println("  [6] Close Incident");
            System.out.println("  [7] Generate Incident Report file");
            System.out.println("  [0] Back");
            System.out.println("  +------------------------------------------------------------------+");
            System.out.print("  Select option: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    listIncidents(false);
                    break;
                case "2":
                    listIncidents(true);
                    break;
                case "3":
                    viewIncidentDetails(scanner);
                    break;
                case "4":
                    viewIncidentTimeline(scanner);
                    break;
                case "5":
                    acknowledgeIncident(scanner);
                    break;
                case "6":
                    closeIncident(scanner);
                    break;
                case "7":
                    generateIncidentReportFile(scanner);
                    break;
                case "0":
                    back = true;
                    break;
                default:
                    System.out.println("\n  Invalid option. Please try again.");
            }
        }
    }

    private static void listIncidents(boolean includeClosed) {
        List<Incident> list = incidentManager.getIncidents();
        System.out.println("\n  STATEFUL INCIDENT LIST");
        System.out.println("  " + "-".repeat(76));
        System.out.printf("  %-16s %-16s %-10s %-8s %s\n", "Incident ID", "Source Context", "Severity", "Score", "Status");
        System.out.println("  " + "-".repeat(76));
        
        int count = 0;
        for (Incident inc : list) {
            if (!includeClosed && inc.getStatus() == IncidentStatus.CLOSED) {
                continue;
            }
            count++;
            System.out.printf("  %-16s %-16s %-10s %-8d %s\n",
                    inc.getId(), inc.getSourceIP(), inc.getSeverity(), inc.getRiskScore(), inc.getStatus());
        }
        System.out.println("  " + "-".repeat(76));
        System.out.println("  Total matching incidents: " + count);
    }

    private static void viewIncidentDetails(Scanner scanner) {
        System.out.print("\n  Enter Incident ID (e.g. INC-20260825-0001): ");
        String idStr = scanner.nextLine().trim();
        Incident inc = incidentManager.findIncidentById(idStr);

        if (inc == null) {
            System.out.println("  [ERROR] Incident ID not found: " + idStr);
            return;
        }

        System.out.println("\n  INCIDENT SUMMARY DETAILS:");
        System.out.println("  " + "=".repeat(46));
        System.out.print(inc);
        System.out.println("  " + "=".repeat(46));
        
        System.out.println("  CONTRIBUTING RULES & ALERTS:");
        for (Alert a : inc.getAlerts()) {
            System.out.printf("    - [%s] %s\n      Severity: %s (Points: +%d) | Timestamp: %s\n      Description: %s\n",
                    a.getRuleId(), a.getRuleName(), a.getSeverity(), a.getRiskScore(), 
                    a.getTimestamp().format(TIME_FORMAT), a.getDescription());
        }
        System.out.println();
        System.out.println("  AUDIT TRAIL:");
        for (String log : inc.getAuditTrail()) {
            System.out.println("    " + log);
        }
    }

    private static void viewIncidentTimeline(Scanner scanner) {
        System.out.print("\n  Enter Incident ID: ");
        String idStr = scanner.nextLine().trim();
        Incident inc = incidentManager.findIncidentById(idStr);

        if (inc == null) {
            System.out.println("  [ERROR] Incident ID not found: " + idStr);
            return;
        }

        // Get chronological list of events belonging to this incident
        List<SecurityEvent> timeline = new ArrayList<>();
        for (Alert alert : inc.getAlerts()) {
            timeline.addAll(alert.getRelatedEvents());
        }
        // Deduplicate and sort
        Set<SecurityEvent> dedup = new HashSet<>(timeline);
        List<SecurityEvent> sorted = new ArrayList<>(dedup);
        sorted.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp()));

        System.out.println("\n  FORENSIC EVENT TIMELINE FOR " + inc.getId());
        System.out.println("  " + "-".repeat(86));
        if (sorted.isEmpty()) {
            System.out.println("    No detailed raw events linked (e.g. correlation rules only).");
        } else {
            for (SecurityEvent e : sorted) {
                System.out.printf("    %-20s | %-16s | %s\n",
                        e.getTimestamp().format(TIME_FORMAT), e.getEventType(), e.getDetails());
            }
        }
        System.out.println("  " + "-".repeat(86));
    }

    private static void acknowledgeIncident(Scanner scanner) {
        System.out.print("\n  Enter Incident ID to acknowledge: ");
        String idStr = scanner.nextLine().trim();
        Incident inc = incidentManager.findIncidentById(idStr);

        if (inc == null) {
            System.out.println("  [ERROR] Incident ID not found.");
            return;
        }

        inc.setStatus(IncidentStatus.ACKNOWLEDGED);
        incidentManager.saveIncidents();
        System.out.println("  ✓ Incident " + idStr + " acknowledged successfully.");
    }

    private static void closeIncident(Scanner scanner) {
        System.out.print("\n  Enter Incident ID to close: ");
        String idStr = scanner.nextLine().trim();
        Incident inc = incidentManager.findIncidentById(idStr);

        if (inc == null) {
            System.out.println("  [ERROR] Incident ID not found.");
            return;
        }

        inc.setStatus(IncidentStatus.CLOSED);
        incidentManager.saveIncidents();
        System.out.println("  ✓ Incident " + idStr + " closed successfully.");
    }

    private static void generateIncidentReportFile(Scanner scanner) {
        String timestamp = LocalDateTime.now().format(FILE_TIMESTAMP);
        String reportFileName = "incident_report_" + timestamp + ".txt";
        File reportFile = new File(REPORTS_DIR, reportFileName);

        try {
            IncidentReportGenerator reportGen = new IncidentReportGenerator();
            reportGen.generateStatefulReport(
                    incidentManager.getIncidents(), 
                    eventHistory.getEvents(), 
                    incidentManager.getMaintenanceAuditTrail(), 
                    reportFile
            );
            System.out.println("\n  ✓ Stateful incident report file successfully written.");
            System.out.println("    Saved to: " + reportFile.getAbsolutePath());
        } catch (IOException e) {
            System.out.println("  [ERROR] Failed to write report file: " + e.getMessage());
        }
    }

    // ─── Submenu 4: Configuration ──────────────────────────────────

    private static void runConfigurationMenu(Scanner scanner) {
        boolean back = false;
        while (!back) {
            System.out.println("\n  +------------------------------------------------------------------+");
            System.out.println("  |                          CONFIGURATION                           |");
            System.out.println("  +------------------------------------------------------------------+");
            System.out.println("  [1] Monitored Protected Directory");
            System.out.println("  [2] Adjust Detection Rule Thresholds");
            System.out.println("  [3] Maintenance Mode");
            System.out.println("  [4] Baseline Checksum Health");
            System.out.println("  [0] Back");
            System.out.println("  +------------------------------------------------------------------+");
            System.out.print("  Select option: ");
            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    configureDirectory(scanner);
                    break;
                case "2":
                    configureThresholds(scanner);
                    break;
                case "3":
                    configureMaintenanceMode(scanner);
                    break;
                case "4":
                    verifyBaselineSettings();
                    break;
                case "0":
                    back = true;
                    break;
                default:
                    System.out.println("\n  Invalid option. Please try again.");
            }
        }
    }

    private static void configureDirectory(Scanner scanner) {
        System.out.println("\n  CURRENT Monitored Protected Folder: " + monitoredDir);
        System.out.print("  Enter new directory path [or press Enter to keep current]: ");
        String input = scanner.nextLine().trim();
        if (!input.isEmpty()) {
            File dir = new File(input);
            if (dir.isDirectory()) {
                monitoredDir = input;
                System.out.println("  Monitored folder updated successfully.");
            } else {
                System.out.println("  [ERROR] Path is not a valid directory.");
            }
        }
    }

    private static void configureThresholds(Scanner scanner) {
        System.out.println("\n  CURRENT DETECTION CONFIGURATION:");
        System.out.println("  ---------------------------------");
        System.out.println("  [1] Authentication Failed Threshold       : " + detectionEngine.getAuthThreshold());
        System.out.println("  [2] Authentication Sliding Window (min)    : " + detectionEngine.getAuthWindowMinutes());
        System.out.println("  [3] Multiple-Account User Threshold       : " + detectionEngine.getMultiAccountThreshold());
        System.out.println("  [4] Port Diversity Scanning Threshold      : " + detectionEngine.getPortDiversityThreshold());
        System.out.println("  [0] Back");
        System.out.print("  Select option to edit: ");
        String choice = scanner.nextLine().trim();

        try {
            switch (choice) {
                case "1":
                    System.out.print("  Enter new failed login count threshold: ");
                    detectionEngine.setAuthThreshold(Integer.parseInt(scanner.nextLine().trim()));
                    break;
                case "2":
                    System.out.print("  Enter new sliding window size (minutes): ");
                    detectionEngine.setAuthWindowMinutes(Integer.parseInt(scanner.nextLine().trim()));
                    break;
                case "3":
                    System.out.print("  Enter new multi-account count threshold: ");
                    detectionEngine.setMultiAccountThreshold(Integer.parseInt(scanner.nextLine().trim()));
                    break;
                case "4":
                    System.out.print("  Enter new port probing count threshold: ");
                    detectionEngine.setPortDiversityThreshold(Integer.parseInt(scanner.nextLine().trim()));
                    break;
            }
        } catch (NumberFormatException e) {
            System.out.println("  [ERROR] Invalid number format.");
        }
    }

    private static void configureMaintenanceMode(Scanner scanner) {
        String state = incidentManager.isMaintenanceMode() ? "ENABLED" : "DISABLED";
        System.out.println("\n  MAINTENANCE MODE");
        System.out.println("  ----------------");
        System.out.println("  Status: " + state);
        System.out.println("\n  [1] Enter Maintenance Mode");
        System.out.println("  [2] Exit Maintenance Mode");
        System.out.println("  [0] Back");
        System.out.print("  Select option: ");
        String choice = scanner.nextLine().trim();

        if (choice.equals("1")) {
            if (incidentManager.isMaintenanceMode()) {
                System.out.println("  Maintenance Mode is already active.");
                return;
            }
            System.out.print("  Enter maintenance task details (reason): ");
            String reason = scanner.nextLine().trim();
            incidentManager.setMaintenanceMode(true);
            if (fileMonitor != null) {
                fileMonitor.setMaintenanceMode(true);
            }
            incidentManager.addMaintenanceEventAudit(new SecurityEvent(LocalDateTime.now(), EventType.FILE_MODIFIED, "", "", "Maintenance Started: " + reason, "MAINTENANCE"));
            System.out.println("\n  🟢 MAINTENANCE MODE ACTIVATED");
            System.out.println("     Protected file changes will be authorized and logged, suppressing alerts.");
        } else if (choice.equals("2")) {
            if (!incidentManager.isMaintenanceMode()) {
                System.out.println("  Maintenance Mode is not active.");
                return;
            }
            incidentManager.setMaintenanceMode(false);
            if (fileMonitor != null) {
                fileMonitor.setMaintenanceMode(false);
            }
            incidentManager.addMaintenanceEventAudit(new SecurityEvent(LocalDateTime.now(), EventType.FILE_MODIFIED, "", "", "Maintenance Ended", "UNAUTHORIZED"));
            System.out.println("\n  🛑 MAINTENANCE MODE DEACTIVATED");
            
            // Re-baseline prompt
            System.out.print("  Would you like to accept maintenance modifications and commit a new baseline? [Y/N]: ");
            String rebase = scanner.nextLine().trim();
            if (rebase.equalsIgnoreCase("Y")) {
                File directory = new File(monitoredDir);
                File baselineFile = new File(monitoredDir + BASELINE_SUFFIX);
                try {
                    int fileCount = baselineManager.createBaseline(directory, baselineFile);
                    System.out.println("  ✓ New baseline established. " + fileCount + " files hashed and trusted.");
                } catch (IOException e) {
                    System.out.println("  [ERROR] Failed to rebuild baseline: " + e.getMessage());
                }
            }
        }
    }

    private static void verifyBaselineSettings() {
        File baselineFile = new File(monitoredDir + BASELINE_SUFFIX);
        File shaFile = new File(monitoredDir + BASELINE_SUFFIX + ".sha256");

        System.out.println("\n  BASELINE HEALTH CHECK:");
        System.out.println("  ----------------------");
        System.out.println("  Baseline File exists     : " + baselineFile.exists());
        System.out.println("  Checksum File exists     : " + shaFile.exists());
        
        if (baselineFile.exists() && shaFile.exists()) {
            boolean valid = baselineManager.verifyBaselineIntegrity(baselineFile);
            System.out.println("  Baseline Integrity       : " + (valid ? "VALID (Match)" : "TAMPERED (Mismatch)"));
        } else {
            System.out.println("  Baseline Integrity       : UNKNOWN (Baseline files incomplete)");
        }
    }

    // ─── Submenu 5: System Status Dashboard ────────────────────────

    private static void viewSystemStatus() {
        // Gathering dashboard details
        String monitorState = (fileMonitor != null && fileMonitor.isRunning()) ? "ACTIVE" : "INACTIVE";
        File baselineFile = new File(monitoredDir + BASELINE_SUFFIX);
        boolean baselineValid = baselineManager.verifyBaselineIntegrity(baselineFile);
        String baselineState = baselineFile.exists() ? (baselineValid ? "VALID" : "TAMPERED") : "MISSING";
        
        int protectedFilesCount = 0;
        if (baselineFile.exists()) {
            try {
                protectedFilesCount = baselineManager.loadBaseline(baselineFile).size();
            } catch (IOException e) {
                // Squelch
            }
        }

        int openIncidentsCount = 0;
        int maxRisk = 0;
        for (Incident inc : incidentManager.getIncidents()) {
            if (inc.getStatus() != IncidentStatus.CLOSED) {
                openIncidentsCount++;
                if (inc.getRiskScore() > maxRisk) {
                    maxRisk = inc.getRiskScore();
                }
            }
        }
        Severity currentRisk = riskScorer.calculateSeverity(maxRisk);
        int eventsToday = eventHistory.getEventsTodayCount();
        int totalEvents = eventHistory.getEvents().size();
        
        // Find last event
        List<SecurityEvent> eventsList = eventHistory.getEvents();
        String lastEventStr = "None";
        String lastEventTime = "N/A";
        if (!eventsList.isEmpty()) {
            SecurityEvent last = eventsList.get(eventsList.size() - 1);
            lastEventStr = last.getEventType().toString() + " (" + last.getSourceIP() + ")";
            lastEventTime = last.getTimestamp().format(TIME_FORMAT);
        }

        String coloredMonitor = monitorState.equals("ACTIVE") ? "\u001B[32mACTIVE\u001B[0m" : "\u001B[31mINACTIVE\u001B[0m";
        String coloredWatcher = monitorState.equals("ACTIVE") ? "\u001B[32mRUNNING\u001B[0m" : "\u001B[31mSTOPPED\u001B[0m";
        
        String coloredBaseline;
        if (baselineState.equals("VALID")) {
            coloredBaseline = "\u001B[32mVALID\u001B[0m";
        } else if (baselineState.equals("TAMPERED")) {
            coloredBaseline = "\u001B[31mTAMPERED\u001B[0m";
        } else {
            coloredBaseline = "\u001B[33mMISSING\u001B[0m";
        }

        String coloredRisk;
        if (currentRisk == Severity.CRITICAL) {
            coloredRisk = "\u001B[31mCRITICAL\u001B[0m";
        } else if (currentRisk == Severity.HIGH) {
            coloredRisk = "\u001B[35mHIGH\u001B[0m";
        } else if (currentRisk == Severity.MEDIUM) {
            coloredRisk = "\u001B[33mMEDIUM\u001B[0m";
        } else {
            coloredRisk = "\u001B[32mLOW\u001B[0m";
        }

        String coloredMaint = incidentManager.isMaintenanceMode() ? "\u001B[33mENABLED\u001B[0m" : "\u001B[32mDISABLED\u001B[0m";

        System.out.println();
        printBorder();
        printCenteredRow("SENTINELCHECK STATUS");
        printBorder();
        
        printFieldRow("Monitoring Status       : ", coloredMonitor);
        printFieldRow("File Watcher Thread     : ", coloredWatcher);
        printFieldRow("Baseline Integrity      : ", coloredBaseline);
        printFieldRow("Monitored Folder        : ", monitoredDir);
        printFieldRow("Protected Files Hashed  : ", String.valueOf(protectedFilesCount));
        printCenteredRow("");
        printFieldRow("Events Logged Today     : ", String.valueOf(eventsToday));
        printFieldRow("Total Historical Events : ", String.valueOf(totalEvents));
        printFieldRow("Open Incident Count     : ", String.valueOf(openIncidentsCount));
        printCenteredRow("");
        printFieldRow("Last Event Registered   : ", lastEventStr);
        printFieldRow("Last Event Log Time     : ", lastEventTime);
        printCenteredRow("");
        printFieldRow("Current System Severity : ", coloredRisk);
        printFieldRow("Max Active Risk Score   : ", String.valueOf(maxRisk));
        printFieldRow("Maintenance Mode        : ", coloredMaint);
        
        printBorder();
    }

    private static void printBorder() {
        System.out.println("  +==================================================================+");
    }

    private static void printCenteredRow(String text) {
        String stripped = text.replaceAll("\u001B\\[[;\\d]*m", "");
        int dataWidth = 66;
        int paddingLeft = (dataWidth - stripped.length()) / 2;
        int paddingRight = dataWidth - stripped.length() - paddingLeft;
        
        System.out.print("  | ");
        for (int i = 0; i < paddingLeft; i++) {
            System.out.print(" ");
        }
        System.out.print(text);
        for (int i = 0; i < paddingRight; i++) {
            System.out.print(" ");
        }
        System.out.println(" |");
    }

    private static void printRow(String content) {
        String stripped = content.replaceAll("\u001B\\[[;\\d]*m", "");
        int dataWidth = 66;
        int padding = dataWidth - stripped.length();
        System.out.print("  | " + content);
        for (int i = 0; i < padding; i++) {
            System.out.print(" ");
        }
        System.out.println(" |");
    }

    private static void printFieldRow(String label, String value) {
        String strippedLabel = label.replaceAll("\u001B\\[[;\\d]*m", "");
        String strippedValue = value.replaceAll("\u001B\\[[;\\d]*m", "");
        int dataWidth = 66;
        int padding = dataWidth - strippedLabel.length() - strippedValue.length();
        
        System.out.print("  | " + label + value);
        for (int i = 0; i < padding; i++) {
            System.out.print(" ");
        }
        System.out.println(" |");
    }

    // ─── Non-interactive Scan (Batch execution pipeline) ──────────

    private static void runCompleteScan(String dirPath, String logDirPath, boolean interactiveMode) {
        if (!interactiveMode) {
            System.out.println("\n  ╔══════════════════════════════════════╗");
            System.out.println("  ║    RUNNING COMPLETE SECURITY SCAN    ║");
            System.out.println("  ╚══════════════════════════════════════╝\n");
        }

        File directory = new File(dirPath);
        File baselineFile = new File(dirPath + BASELINE_SUFFIX);
        File authFile = new File(logDirPath, AUTH_LOG);
        File fwFile = new File(logDirPath, FIREWALL_LOG);

        // 1. Baseline Integrity validation
        if (baselineFile.exists()) {
            boolean valid = baselineManager.verifyBaselineIntegrity(baselineFile);
            if (!valid) {
                System.out.println("  [1/4] Baseline Tamper Check...");
                System.out.println("        🚨 [CRITICAL ALERT] Sibling baseline integrity checksum mismatch!");
                SecurityEvent tamperEvent = new SecurityEvent(
                        LocalDateTime.now(), EventType.BASELINE_TAMPERED, "LOCAL",
                        "", baselineFile.getName(), "", 0, "", 
                        "Baseline integrity checksum validation failed (TAMPERED)", "UNAUTHORIZED"
                );
                eventHistory.addEvent(tamperEvent);
                detectionEngine.processNewEvent(tamperEvent);
            }
        }

        // 2. Scan File Integrity Modifications
        System.out.println("  [1/4] File Integrity Check...");
        if (directory.isDirectory() && baselineFile.exists()) {
            try {
                IntegrityChecker checker = new IntegrityChecker();
                List<FileRecord> fileRecords = checker.verifyIntegrity(directory, baselineFile);
                int modCount = 0;
                LocalDateTime now = LocalDateTime.now();

                for (FileRecord r : fileRecords) {
                    if (r.getStatus() != FileStatus.UNCHANGED) {
                        modCount++;
                        EventType type = r.getStatus() == FileStatus.MODIFIED ? EventType.FILE_MODIFIED :
                                         r.getStatus() == FileStatus.MISSING  ? EventType.FILE_MISSING : EventType.FILE_NEW;
                        String hash = r.getStatus() == FileStatus.MODIFIED ? r.getNewHash() :
                                      r.getStatus() == FileStatus.MISSING  ? r.getOldHash() : r.getNewHash();
                        
                        SecurityEvent fileEvent = new SecurityEvent(now, type, r.getFilePath(), hash, r.toString(), "UNAUTHORIZED");
                        eventHistory.addEvent(fileEvent);
                        detectionEngine.processNewEvent(fileEvent);
                    }
                }
                System.out.println("        ✓ " + fileRecords.size() + " files checked. Modifications found: " + modCount);
            } catch (IOException e) {
                System.out.println("        ✗ Error: " + e.getMessage());
            }
        } else if (directory.isDirectory()) {
            System.out.println("        ⓘ No baseline found. Creating initial baseline...");
            try {
                int count = baselineManager.createBaseline(directory, baselineFile);
                System.out.println("        ✓ Baseline created with " + count + " files.");
            } catch (IOException e) {
                System.out.println("        ✗ Error: " + e.getMessage());
            }
        } else {
            System.out.println("        ⓘ Directory not found: " + dirPath);
        }

        // 3. Scan Authentication Logs
        System.out.println("  [2/4] Authentication Log Analysis...");
        if (authFile.exists()) {
            try {
                LogParser parser = new LogParser();
                List<SecurityEvent> events = parser.parseAuthLog(authFile);
                for (SecurityEvent e : events) {
                    eventHistory.addEvent(e);
                    detectionEngine.processNewEvent(e);
                }
                System.out.println("        ✓ " + events.size() + " log entries analyzed.");
            } catch (IOException e) {
                System.out.println("        ✗ Error: " + e.getMessage());
            }
        } else {
            System.out.println("        ⓘ Auth log not found: " + authFile.getPath());
        }

        // 4. Scan Firewall Logs
        System.out.println("  [3/4] Firewall Log Analysis...");
        if (fwFile.exists()) {
            try {
                LogParser parser = new LogParser();
                List<SecurityEvent> events = parser.parseFirewallLog(fwFile);
                for (SecurityEvent e : events) {
                    eventHistory.addEvent(e);
                    detectionEngine.processNewEvent(e);
                }
                System.out.println("        ✓ " + events.size() + " log entries analyzed.");
            } catch (IOException e) {
                System.out.println("        ✗ Error: " + e.getMessage());
            }
        } else {
            System.out.println("        ⓘ Firewall log not found: " + fwFile.getPath());
        }

        // 5. Correlation & Report
        System.out.println("  [4/4] Stateful Correlation & Report Generation...");
        
        List<Incident> openIncidents = new ArrayList<>();
        int maxRisk = 0;
        for (Incident inc : incidentManager.getIncidents()) {
            if (inc.getStatus() != IncidentStatus.CLOSED) {
                openIncidents.add(inc);
                if (inc.getRiskScore() > maxRisk) {
                    maxRisk = inc.getRiskScore();
                }
            }
        }
        Severity overallRisk = riskScorer.calculateSeverity(maxRisk);

        String reportFileName = "incident_report_" + LocalDateTime.now().format(FILE_TIMESTAMP) + ".txt";
        File reportFile = new File(REPORTS_DIR, reportFileName);

        try {
            IncidentReportGenerator reportGen = new IncidentReportGenerator();
            System.out.println("\n");
            reportGen.generateStatefulReport(
                    incidentManager.getIncidents(), 
                    eventHistory.getEvents(), 
                    incidentManager.getMaintenanceAuditTrail(), 
                    reportFile
            );
            System.out.println("\n  Report saved to: " + reportFile.getAbsolutePath());
        } catch (IOException e) {
            System.out.println("  [ERROR] Failed to write report: " + e.getMessage());
        }
    }
}
