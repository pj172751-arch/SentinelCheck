package sentinelcheck;

import sentinelcheck.detection.AlertEngine;
import sentinelcheck.detection.EventCorrelator;
import sentinelcheck.detection.RiskScorer;
import sentinelcheck.integrity.BaselineManager;
import sentinelcheck.integrity.IntegrityChecker;
import sentinelcheck.logs.AuthenticationMonitor;
import sentinelcheck.logs.FirewallMonitor;
import sentinelcheck.logs.LogParser;
import sentinelcheck.model.Alert;
import sentinelcheck.model.FileRecord;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;
import sentinelcheck.report.IncidentReportGenerator;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * SentinelCheck — Lightweight Host-Based Security Event Monitor
 *
 * Entry point with an interactive menu for demonstrating each module,
 * plus command-line argument support for non-interactive execution.
 *
 * Usage:
 *   Interactive:  java sentinelcheck.Main
 *   Full scan:    java sentinelcheck.Main --scan --dir monitored --logs sample-logs
 */
public class Main {

    // Default paths
    private static final String DEFAULT_MONITORED_DIR = "monitored";
    private static final String DEFAULT_LOG_DIR       = "sample-logs";
    private static final String DEFAULT_BASELINE_FILE = "monitored.baseline";
    private static final String DEFAULT_AUTH_LOG      = "auth_log.csv";
    private static final String DEFAULT_FIREWALL_LOG  = "firewall_log.csv";
    private static final String REPORTS_DIR           = "reports";

    private static final DateTimeFormatter FILE_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmmss");

    public static void main(String[] args) {

        // Check for command-line arguments
        if (args.length > 0 && args[0].equals("--scan")) {
            String dir = DEFAULT_MONITORED_DIR;
            String logDir = DEFAULT_LOG_DIR;

            for (int i = 1; i < args.length; i++) {
                if (args[i].equals("--dir") && i + 1 < args.length) {
                    dir = args[++i];
                } else if (args[i].equals("--logs") && i + 1 < args.length) {
                    logDir = args[++i];
                }
            }

            runCompleteScan(dir, logDir);
            return;
        }

        // Interactive menu
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        while (running) {
            printMenu();
            System.out.print("  Select option: ");

            String choice = scanner.nextLine().trim();

            switch (choice) {
                case "1":
                    createBaseline(scanner);
                    break;
                case "2":
                    verifyIntegrity(scanner);
                    break;
                case "3":
                    analyzeSecurityLogs(scanner);
                    break;
                case "4":
                    generateIncidentReport(scanner);
                    break;
                case "5":
                    runCompleteScan(DEFAULT_MONITORED_DIR, DEFAULT_LOG_DIR);
                    break;
                case "0":
                    System.out.println("\n  Exiting SentinelCheck. Stay secure.\n");
                    running = false;
                    break;
                default:
                    System.out.println("\n  Invalid option. Please try again.\n");
            }
        }

        scanner.close();
    }

    // ─── Menu ────────────────────────────────────────────────────

    private static void printMenu() {
        System.out.println();
        System.out.println("  +==========================================+");
        System.out.println("  |          SENTINELCHECK v1.0              |");
        System.out.println("  |  Host-Based Security Event Monitor      |");
        System.out.println("  +==========================================+");
        System.out.println();
        System.out.println("  [1] Create File Integrity Baseline");
        System.out.println("  [2] Verify File Integrity");
        System.out.println("  [3] Analyze Security Logs");
        System.out.println("  [4] Generate Full Incident Report");
        System.out.println("  [5] Run Complete Security Scan");
        System.out.println("  [0] Exit");
        System.out.println();
    }

    // ─── Option 1: Create Baseline ───────────────────────────────

    private static void createBaseline(Scanner scanner) {
        System.out.print("\n  Enter directory to monitor [" + DEFAULT_MONITORED_DIR + "]: ");
        String dirPath = scanner.nextLine().trim();
        if (dirPath.isEmpty()) {
            dirPath = DEFAULT_MONITORED_DIR;
        }

        File directory = new File(dirPath);
        File baselineFile = new File(dirPath + ".baseline");

        if (!directory.isDirectory()) {
            System.out.println("  [ERROR] Directory not found: " + dirPath);
            return;
        }

        try {
            BaselineManager manager = new BaselineManager();
            int fileCount = manager.createBaseline(directory, baselineFile);

            System.out.println("\n  ✓ Baseline created successfully.");
            System.out.println("  Files hashed: " + fileCount);
            System.out.println("  Baseline saved to: " + baselineFile.getAbsolutePath());
        } catch (IOException e) {
            System.out.println("  [ERROR] Failed to create baseline: " + e.getMessage());
        }
    }

    // ─── Option 2: Verify Integrity ──────────────────────────────

    private static void verifyIntegrity(Scanner scanner) {
        System.out.print("\n  Enter directory to verify [" + DEFAULT_MONITORED_DIR + "]: ");
        String dirPath = scanner.nextLine().trim();
        if (dirPath.isEmpty()) {
            dirPath = DEFAULT_MONITORED_DIR;
        }

        File directory = new File(dirPath);
        File baselineFile = new File(dirPath + ".baseline");

        if (!directory.isDirectory()) {
            System.out.println("  [ERROR] Directory not found: " + dirPath);
            return;
        }
        if (!baselineFile.exists()) {
            System.out.println("  [ERROR] Baseline file not found: " + baselineFile.getName());
            System.out.println("  Please create a baseline first (Option 1).");
            return;
        }

        try {
            IntegrityChecker checker = new IntegrityChecker();
            List<FileRecord> results = checker.verifyIntegrity(directory, baselineFile);

            System.out.println("\n  FILE INTEGRITY RESULTS");
            System.out.println("  " + "-".repeat(46));

            int unchanged = 0, modified = 0, missing = 0, newFiles = 0;

            for (FileRecord record : results) {
                switch (record.getStatus()) {
                    case UNCHANGED:
                        unchanged++;
                        System.out.println("  [OK]       " + record.getFilePath());
                        break;
                    case MODIFIED:
                        modified++;
                        System.out.println("  [MODIFIED] " + record.getFilePath());
                        System.out.println("             Old: " + record.getOldHash().substring(0, 16) + "...");
                        System.out.println("             New: " + record.getNewHash().substring(0, 16) + "...");
                        break;
                    case MISSING:
                        missing++;
                        System.out.println("  [MISSING]  " + record.getFilePath());
                        break;
                    case NEW:
                        newFiles++;
                        System.out.println("  [NEW]      " + record.getFilePath());
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

    // ─── Option 3: Analyze Security Logs ─────────────────────────

    private static void analyzeSecurityLogs(Scanner scanner) {
        System.out.print("\n  Enter log directory [" + DEFAULT_LOG_DIR + "]: ");
        String logDir = scanner.nextLine().trim();
        if (logDir.isEmpty()) {
            logDir = DEFAULT_LOG_DIR;
        }

        File authFile = new File(logDir, DEFAULT_AUTH_LOG);
        File fwFile = new File(logDir, DEFAULT_FIREWALL_LOG);

        LogParser parser = new LogParser();

        // Parse and analyze authentication log
        if (authFile.exists()) {
            try {
                List<SecurityEvent> authEvents = parser.parseAuthLog(authFile);
                AuthenticationMonitor authMonitor = new AuthenticationMonitor();
                List<AuthenticationMonitor.AuthResult> authResults =
                        authMonitor.analyzeAuthentication(authEvents);

                System.out.println("\n  AUTHENTICATION ANALYSIS");
                System.out.println("  " + "-".repeat(46));
                System.out.println("  Total events parsed: " + authEvents.size());
                System.out.println();
                System.out.printf("  %-18s  %-16s  %s%n",
                        "IP", "Failed Attempts", "Status");
                System.out.printf("  %-18s  %-16s  %s%n",
                        "-".repeat(18), "-".repeat(16), "-".repeat(10));

                for (AuthenticationMonitor.AuthResult result : authResults) {
                    System.out.println("  " + result);
                }
            } catch (IOException e) {
                System.out.println("  [ERROR] Failed to parse auth log: " + e.getMessage());
            }
        } else {
            System.out.println("\n  [INFO] Auth log not found: " + authFile.getPath());
        }

        // Parse and analyze firewall log
        if (fwFile.exists()) {
            try {
                List<SecurityEvent> fwEvents = parser.parseFirewallLog(fwFile);
                FirewallMonitor fwMonitor = new FirewallMonitor();
                List<FirewallMonitor.FirewallResult> fwResults =
                        fwMonitor.analyzeFirewall(fwEvents);

                System.out.println("\n  FIREWALL ANALYSIS");
                System.out.println("  " + "-".repeat(46));
                System.out.println("  Total events parsed: " + fwEvents.size());
                System.out.println();

                for (FirewallMonitor.FirewallResult result : fwResults) {
                    System.out.println("  " + result);
                }
            } catch (IOException e) {
                System.out.println("  [ERROR] Failed to parse firewall log: " + e.getMessage());
            }
        } else {
            System.out.println("\n  [INFO] Firewall log not found: " + fwFile.getPath());
        }
    }

    // ─── Option 4: Generate Incident Report ──────────────────────

    private static void generateIncidentReport(Scanner scanner) {
        System.out.print("\n  Enter monitored directory [" + DEFAULT_MONITORED_DIR + "]: ");
        String dirPath = scanner.nextLine().trim();
        if (dirPath.isEmpty()) dirPath = DEFAULT_MONITORED_DIR;

        System.out.print("  Enter log directory [" + DEFAULT_LOG_DIR + "]: ");
        String logDir = scanner.nextLine().trim();
        if (logDir.isEmpty()) logDir = DEFAULT_LOG_DIR;

        runCompleteScan(dirPath, logDir);
    }

    // ─── Option 5 / --scan: Complete Security Scan ───────────────

    private static void runCompleteScan(String dirPath, String logDir) {
        System.out.println("\n  ╔══════════════════════════════════════╗");
        System.out.println("  ║    RUNNING COMPLETE SECURITY SCAN    ║");
        System.out.println("  ╚══════════════════════════════════════╝\n");

        File directory = new File(dirPath);
        File baselineFile = new File(dirPath + ".baseline");
        File authFile = new File(logDir, DEFAULT_AUTH_LOG);
        File fwFile = new File(logDir, DEFAULT_FIREWALL_LOG);

        LogParser parser = new LogParser();
        AlertEngine alertEngine = new AlertEngine();
        EventCorrelator correlator = new EventCorrelator();
        RiskScorer riskScorer = new RiskScorer();
        IncidentReportGenerator reportGen = new IncidentReportGenerator();

        // ─── Step 1: File Integrity ──────────────────────────────
        List<FileRecord> fileRecords = null;
        System.out.println("  [1/4] File Integrity Check...");

        if (directory.isDirectory() && baselineFile.exists()) {
            try {
                IntegrityChecker checker = new IntegrityChecker();
                fileRecords = checker.verifyIntegrity(directory, baselineFile);
                System.out.println("        ✓ " + fileRecords.size() + " files checked.");
            } catch (IOException e) {
                System.out.println("        ✗ Error: " + e.getMessage());
            }
        } else if (directory.isDirectory()) {
            System.out.println("        ⓘ No baseline found. Creating initial baseline...");
            try {
                BaselineManager manager = new BaselineManager();
                int count = manager.createBaseline(directory, baselineFile);
                System.out.println("        ✓ Baseline created with " + count + " files.");
                System.out.println("        ⓘ Run scan again to detect changes.");
            } catch (IOException e) {
                System.out.println("        ✗ Error: " + e.getMessage());
            }
        } else {
            System.out.println("        ⓘ Directory not found: " + dirPath);
        }

        // ─── Step 2: Authentication Log Analysis ─────────────────
        List<SecurityEvent> authEvents = null;
        List<AuthenticationMonitor.AuthResult> authResults = null;
        System.out.println("  [2/4] Authentication Log Analysis...");

        if (authFile.exists()) {
            try {
                authEvents = parser.parseAuthLog(authFile);
                authResults = alertEngine.getAuthMonitor()
                        .analyzeAuthentication(authEvents);
                long alertCount = authResults.stream()
                        .filter(AuthenticationMonitor.AuthResult::isAlert)
                        .count();
                System.out.println("        ✓ " + authEvents.size()
                        + " events parsed, " + alertCount + " alerts.");
            } catch (IOException e) {
                System.out.println("        ✗ Error: " + e.getMessage());
            }
        } else {
            System.out.println("        ⓘ Auth log not found: " + authFile.getPath());
        }

        // ─── Step 3: Firewall Log Analysis ───────────────────────
        List<SecurityEvent> fwEvents = null;
        List<FirewallMonitor.FirewallResult> fwResults = null;
        System.out.println("  [3/4] Firewall Log Analysis...");

        if (fwFile.exists()) {
            try {
                fwEvents = parser.parseFirewallLog(fwFile);
                fwResults = alertEngine.getFirewallMonitor()
                        .analyzeFirewall(fwEvents);
                System.out.println("        ✓ " + fwEvents.size()
                        + " events parsed, " + fwResults.size() + " source IPs with DROPs.");
            } catch (IOException e) {
                System.out.println("        ✗ Error: " + e.getMessage());
            }
        } else {
            System.out.println("        ⓘ Firewall log not found: " + fwFile.getPath());
        }

        // ─── Step 4: Alert Correlation & Report ──────────────────
        System.out.println("  [4/4] Alert Correlation & Report Generation...");

        List<Alert> allAlerts = alertEngine.processAllEvents(
                fileRecords, authEvents, fwEvents);
        List<Alert> correlatedAlerts = correlator.correlateEvents(allAlerts);

        // Calculate overall risk
        int totalScore = 0;
        for (Alert alert : allAlerts) {
            totalScore += alert.getRiskScore();
        }
        for (Alert correlated : correlatedAlerts) {
            totalScore += 20; // Correlation bonus already included in score
        }
        Severity overallRisk = riskScorer.calculateSeverity(totalScore);

        System.out.println("        ✓ " + allAlerts.size() + " alerts, "
                + correlatedAlerts.size() + " correlated incidents.");
        System.out.println("        Overall Risk Score: " + totalScore
                + " (" + overallRisk + ")");

        // Generate report file
        String reportFileName = "incident_report_"
                + LocalDateTime.now().format(FILE_TIMESTAMP) + ".txt";
        File reportFile = new File(REPORTS_DIR, reportFileName);

        try {
            System.out.println("\n");
            reportGen.generateReport(fileRecords, authResults, fwResults,
                    allAlerts, correlatedAlerts, overallRisk, reportFile);
            System.out.println("\n  Report saved to: " + reportFile.getAbsolutePath());
        } catch (IOException e) {
            System.out.println("  [ERROR] Failed to write report: " + e.getMessage());
        }
    }
}
