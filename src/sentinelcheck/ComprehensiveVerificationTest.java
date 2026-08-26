package sentinelcheck;

import sentinelcheck.detection.DetectionEngine;
import sentinelcheck.detection.EventCorrelator;
import sentinelcheck.detection.EventHistory;
import sentinelcheck.detection.IncidentManager;
import sentinelcheck.detection.RiskScorer;
import sentinelcheck.integrity.BaselineManager;
import sentinelcheck.integrity.HashCalculator;
import sentinelcheck.integrity.IntegrityChecker;
import sentinelcheck.logs.AuthenticationMonitor;
import sentinelcheck.logs.FirewallMonitor;
import sentinelcheck.logs.LogParser;
import sentinelcheck.model.*;
import sentinelcheck.report.IncidentReportGenerator;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

public class ComprehensiveVerificationTest {

    private static int testsPassed = 0;
    private static int testsFailed = 0;

    public static void main(String[] args) {
        System.out.println("=================================================");
        System.out.println("   SENTINELCHECK COMPREHENSIVE REGRESSION SUITE  ");
        System.out.println("=================================================");

        testHashCalculator();
        testBaselineManager();
        testIntegrityChecker();
        testLogParser();
        testAuthenticationDetection();
        testFirewallDetection();
        testEventCorrelator();
        testIncidentManagerAndPersistence();
        testMaintenanceMode();
        testIncidentReportGenerator();
        testSecurityHardeningAndResilience();
        testAttackSimulator();

        System.out.println("\n=================================================");
        System.out.printf("   TEST SUMMARY: %d PASSED, %d FAILED%n", testsPassed, testsFailed);
        System.out.println("=================================================");

        if (testsFailed > 0) {
            System.exit(1);
        }
    }

    private static void assertTrue(String testName, boolean condition) {
        if (condition) {
            System.out.println("  [PASS] " + testName);
            testsPassed++;
        } else {
            System.err.println("  [FAIL] " + testName);
            testsFailed++;
        }
    }

    private static void assertEquals(String testName, Object expected, Object actual) {
        if (expected == null && actual == null) {
            assertTrue(testName, true);
        } else if (expected != null && expected.equals(actual)) {
            assertTrue(testName, true);
        } else {
            System.err.printf("  [FAIL] %s - Expected: %s, Actual: %s%n", testName, expected, actual);
            testsFailed++;
        }
    }

    private static void testHashCalculator() {
        System.out.println("\n--- [1/10] Testing HashCalculator ---");
        try {
            HashCalculator calc = new HashCalculator();
            Path temp = Files.createTempFile("test_hash", ".txt");
            Files.writeString(temp, "SentinelCheck2026");
            
            String hash = calc.calculateSHA256(temp.toFile());
            assertTrue("SHA-256 calculation produces 64-hex lowercase characters",
                    hash != null && hash.length() == 64 && hash.matches("^[a-f0-9]{64}$"));

            String hash2 = calc.calculateSHA256(temp.toFile());
            assertEquals("SHA-256 hash is deterministic", hash, hash2);

            Files.deleteIfExists(temp);
        } catch (Exception e) {
            assertTrue("HashCalculator test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testBaselineManager() {
        System.out.println("\n--- [2/10] Testing BaselineManager ---");
        try {
            Path testDir = Files.createTempDirectory("sentinel_baseline_test");
            Path file1 = testDir.resolve("file1.txt");
            Path file2 = testDir.resolve("file2.txt");
            Files.writeString(file1, "Hello World 1");
            Files.writeString(file2, "Hello World 2");

            BaselineManager bm = new BaselineManager();
            File baselineFile = testDir.resolve("test.baseline").toFile();

            int count = bm.createBaseline(testDir.toFile(), baselineFile);
            assertEquals("Baseline recorded 2 files", 2, count);
            assertTrue("Baseline file created", baselineFile.exists());
            assertTrue("Sibling .sha256 file created", new File(baselineFile.getAbsolutePath() + ".sha256").exists());

            assertTrue("Baseline integrity initially VALID", bm.verifyBaselineIntegrity(baselineFile));

            Map<String, String> loaded = bm.loadBaseline(baselineFile);
            assertEquals("Loaded baseline contains 2 files", 2, loaded.size());
            assertTrue("Contains file1.txt", loaded.containsKey("file1.txt"));
            assertTrue("Contains file2.txt", loaded.containsKey("file2.txt"));

            Files.writeString(baselineFile.toPath(), "TAMPERED CONTENT");
            assertTrue("Baseline integrity reports TAMPERED when content altered", !bm.verifyBaselineIntegrity(baselineFile));

            Files.walk(testDir).sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
        } catch (Exception e) {
            assertTrue("BaselineManager test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testIntegrityChecker() {
        System.out.println("\n--- [3/10] Testing IntegrityChecker ---");
        try {
            Path testDir = Files.createTempDirectory("sentinel_fim_test");
            Path unchanged = testDir.resolve("unchanged.txt");
            Path modified = testDir.resolve("modified.txt");
            Path deleted = testDir.resolve("deleted.txt");

            Files.writeString(unchanged, "Same content");
            Files.writeString(modified, "Original content");
            Files.writeString(deleted, "To be deleted");

            BaselineManager bm = new BaselineManager();
            File baselineFile = testDir.resolve("fim.baseline").toFile();
            bm.createBaseline(testDir.toFile(), baselineFile);

            Files.writeString(modified, "Modified content!");
            Files.delete(deleted);
            Path newFile = testDir.resolve("newfile.txt");
            Files.writeString(newFile, "Untracked new file");

            IntegrityChecker checker = new IntegrityChecker();
            List<FileRecord> records = checker.verifyIntegrity(testDir.toFile(), baselineFile);

            assertEquals("Records count is 4", 4, records.size());

            boolean foundUnchanged = false, foundModified = false, foundMissing = false, foundNew = false;
            for (FileRecord r : records) {
                if (r.getFilePath().equals("unchanged.txt") && r.getStatus() == FileStatus.UNCHANGED) foundUnchanged = true;
                if (r.getFilePath().equals("modified.txt") && r.getStatus() == FileStatus.MODIFIED) foundModified = true;
                if (r.getFilePath().equals("deleted.txt") && r.getStatus() == FileStatus.MISSING) foundMissing = true;
                if (r.getFilePath().equals("newfile.txt") && r.getStatus() == FileStatus.NEW) foundNew = true;
            }

            assertTrue("UNCHANGED file correctly identified", foundUnchanged);
            assertTrue("MODIFIED file correctly identified", foundModified);
            assertTrue("MISSING file correctly identified", foundMissing);
            assertTrue("NEW file correctly identified", foundNew);

            Files.walk(testDir).sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
        } catch (Exception e) {
            assertTrue("IntegrityChecker test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testLogParser() {
        System.out.println("\n--- [4/10] Testing LogParser ---");
        try {
            LogParser parser = new LogParser();
            File authLog = new File("sample-logs/auth_log.csv");
            File fwLog = new File("sample-logs/firewall_log.csv");

            List<SecurityEvent> authEvents = parser.parseAuthLog(authLog);
            List<SecurityEvent> fwEvents = parser.parseFirewallLog(fwLog);

            assertEquals("Auth events parsed count matches sample data (7)", 7, authEvents.size());
            assertEquals("Firewall events parsed count matches sample data (10)", 10, fwEvents.size());

            SecurityEvent firstAuth = authEvents.get(0);
            assertEquals("First auth event user", "admin", firstAuth.getUsername());
            assertEquals("First auth event IP", "10.0.0.150", firstAuth.getSourceIP());
            assertEquals("First auth event type", EventType.FAILED_LOGIN, firstAuth.getEventType());

            SecurityEvent firstFw = fwEvents.get(0);
            assertEquals("First fw event IP", "10.0.0.150", firstFw.getSourceIP());
            assertEquals("First fw event port", 22, firstFw.getPort());
            assertEquals("First fw event protocol", "TCP", firstFw.getProtocol());
            assertEquals("First fw event type", EventType.FIREWALL_DROP, firstFw.getEventType());
        } catch (Exception e) {
            assertTrue("LogParser test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testAuthenticationDetection() {
        System.out.println("\n--- [5/10] Testing AuthenticationMonitor ---");
        try {
            AuthenticationMonitor monitor = new AuthenticationMonitor();
            RiskScorer scorer = new RiskScorer();
            LocalDateTime now = LocalDateTime.now();

            List<SecurityEvent> bruteForceEvents = List.of(
                    new SecurityEvent(now.minusMinutes(4), EventType.FAILED_LOGIN, "192.168.1.50", "admin", "details"),
                    new SecurityEvent(now.minusMinutes(2), EventType.FAILED_LOGIN, "192.168.1.50", "admin", "details"),
                    new SecurityEvent(now, EventType.FAILED_LOGIN, "192.168.1.50", "admin", "details")
            );

            List<Alert> alerts1 = monitor.detectAuthAlerts(bruteForceEvents, 3, 5, 3, scorer);
            assertTrue("AUTH-001 Brute Force triggered", alerts1.stream().anyMatch(a -> a.getRuleId().equals("AUTH-001")));

            List<SecurityEvent> suspiciousSuccessEvents = List.of(
                    new SecurityEvent(now.minusMinutes(4), EventType.FAILED_LOGIN, "192.168.1.60", "user1", "details"),
                    new SecurityEvent(now.minusMinutes(3), EventType.FAILED_LOGIN, "192.168.1.60", "user1", "details"),
                    new SecurityEvent(now.minusMinutes(2), EventType.FAILED_LOGIN, "192.168.1.60", "user1", "details"),
                    new SecurityEvent(now, EventType.SUCCESSFUL_LOGIN, "192.168.1.60", "user1", "details")
            );
            List<Alert> alerts2 = monitor.detectAuthAlerts(suspiciousSuccessEvents, 3, 5, 3, scorer);
            assertTrue("AUTH-002 Suspicious Success triggered", alerts2.stream().anyMatch(a -> a.getRuleId().equals("AUTH-002")));

            List<SecurityEvent> multiAccountEvents = List.of(
                    new SecurityEvent(now.minusMinutes(4), EventType.FAILED_LOGIN, "192.168.1.70", "root", "details"),
                    new SecurityEvent(now.minusMinutes(3), EventType.FAILED_LOGIN, "192.168.1.70", "admin", "details"),
                    new SecurityEvent(now.minusMinutes(2), EventType.FAILED_LOGIN, "192.168.1.70", "guest", "details")
            );
            List<Alert> alerts3 = monitor.detectAuthAlerts(multiAccountEvents, 3, 5, 3, scorer);
            assertTrue("AUTH-003 Multi-Account triggered", alerts3.stream().anyMatch(a -> a.getRuleId().equals("AUTH-003")));
        } catch (Exception e) {
            assertTrue("AuthenticationMonitor test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testFirewallDetection() {
        System.out.println("\n--- [6/10] Testing FirewallMonitor ---");
        try {
            FirewallMonitor monitor = new FirewallMonitor();
            RiskScorer scorer = new RiskScorer();
            LocalDateTime now = LocalDateTime.now();

            List<SecurityEvent> scanEvents = List.of(
                    new SecurityEvent(now.minusMinutes(4), EventType.FIREWALL_DROP, "192.168.1.100", "10.0.0.1", 22, "TCP", "drop"),
                    new SecurityEvent(now.minusMinutes(3), EventType.FIREWALL_DROP, "192.168.1.100", "10.0.0.1", 80, "TCP", "drop"),
                    new SecurityEvent(now.minusMinutes(2), EventType.FIREWALL_DROP, "192.168.1.100", "10.0.0.1", 443, "TCP", "drop"),
                    new SecurityEvent(now.minusMinutes(1), EventType.FIREWALL_DROP, "192.168.1.100", "10.0.0.1", 445, "TCP", "drop"),
                    new SecurityEvent(now, EventType.FIREWALL_DROP, "192.168.1.100", "10.0.0.1", 3389, "TCP", "drop")
            );

            List<Alert> fwAlerts = monitor.detectFirewallAlerts(scanEvents, 5, scorer);
            assertTrue("FW-001 Port Probing triggered for 5 unique destination ports",
                    fwAlerts.stream().anyMatch(a -> a.getRuleId().equals("FW-001")));
        } catch (Exception e) {
            assertTrue("FirewallMonitor test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testEventCorrelator() {
        System.out.println("\n--- [7/10] Testing EventCorrelator ---");
        try {
            EventCorrelator correlator = new EventCorrelator();
            RiskScorer scorer = new RiskScorer();
            LocalDateTime now = LocalDateTime.now();

            Incident inc = new Incident("INC-TEST-0001", "10.0.0.150", Severity.MEDIUM, 60, IncidentStatus.OPEN, now.minusMinutes(5), now);
            Alert authAlert = new Alert("AUTH-001", "Brute Force", "desc", Severity.MEDIUM, "details", List.of(), "10.0.0.150", 30, now.minusMinutes(3));
            Alert fwAlert = new Alert("FW-001", "Port Probing", "desc", Severity.MEDIUM, "details", List.of(), "10.0.0.150", 30, now.minusMinutes(1));
            inc.addAlert(authAlert);
            inc.addAlert(fwAlert);

            Alert corr = correlator.checkCorrelation(inc, 10, scorer);
            assertTrue("CORR-001 Multi-Module Correlation generated when spanning Auth + Firewall",
                    corr != null && corr.getRuleId().equals("CORR-001"));
            assertEquals("Correlation rule bonus score is +20", 20, corr.getRiskScore());
        } catch (Exception e) {
            assertTrue("EventCorrelator test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testIncidentManagerAndPersistence() {
        System.out.println("\n--- [8/10] Testing IncidentManager & Persistence ---");
        try {
            RiskScorer scorer = new RiskScorer();
            IncidentManager manager = new IncidentManager(scorer);
            manager.clear();

            LocalDateTime now = LocalDateTime.now();
            Alert alert1 = new Alert("AUTH-001", "Brute Force", "desc", Severity.MEDIUM, "details", List.of(), "192.168.1.99", 30, now);
            Alert alert2 = new Alert("AUTH-003", "Multi-Account", "desc", Severity.MEDIUM, "details", List.of(), "192.168.1.99", 40, now);

            manager.addAlert(alert1);
            manager.addAlert(alert2);

            List<Incident> incidents = manager.getIncidents();
            assertEquals("One incident promoted for 192.168.1.99", 1, incidents.size());
            Incident inc = incidents.get(0);
            assertEquals("Incident status is OPEN", IncidentStatus.OPEN, inc.getStatus());
            assertTrue("Incident score is sum of alerts (30+40=70)", inc.getRiskScore() >= 70);

            inc.setStatus(IncidentStatus.ACKNOWLEDGED);
            inc.addAuditLog("Analyst acknowledged");
            assertEquals("Status transitioned to ACKNOWLEDGED", IncidentStatus.ACKNOWLEDGED, inc.getStatus());
            manager.saveIncidents();

            IncidentManager manager2 = new IncidentManager(scorer);
            manager2.loadIncidents(List.of(alert1, alert2));
            assertEquals("Reloaded 1 incident from CSV", 1, manager2.getIncidents().size());
            Incident reloaded = manager2.getIncidents().get(0);
            assertEquals("Reloaded incident preserves ACKNOWLEDGED status", IncidentStatus.ACKNOWLEDGED, reloaded.getStatus());
            assertEquals("Reloaded incident preserves source IP", "192.168.1.99", reloaded.getSourceIP());

            reloaded.setStatus(IncidentStatus.CLOSED);
            reloaded.addAuditLog("Threat resolved");
            assertEquals("Status transitioned to CLOSED", IncidentStatus.CLOSED, reloaded.getStatus());

            manager2.clear();
        } catch (Exception e) {
            assertTrue("IncidentManager test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testMaintenanceMode() {
        System.out.println("\n--- [9/10] Testing Maintenance Mode ---");
        try {
            RiskScorer scorer = new RiskScorer();
            IncidentManager manager = new IncidentManager(scorer);
            DetectionEngine engine = new DetectionEngine(scorer);
            EventHistory history = new EventHistory();
            history.clear();
            engine.setEventHistory(history);
            engine.setIncidentManager(manager);

            manager.setMaintenanceMode(true);
            assertTrue("Maintenance mode is enabled", manager.isMaintenanceMode());

            SecurityEvent maintEvent = new SecurityEvent(
                    LocalDateTime.now(), EventType.FILE_MODIFIED, "LOCAL", "", "",
                    "config.txt", "abc123hash", 0, "", "Modified during maintenance", "MAINTENANCE"
            );
            history.addEvent(maintEvent);
            engine.processNewEvent(maintEvent);

            assertEquals("No incidents created for authorized maintenance events", 0, manager.getIncidents().size());
            assertEquals("1 event recorded in maintenance audit trail", 1, manager.getMaintenanceAuditTrail().size());

            history.clear();
            manager.clear();
        } catch (Exception e) {
            assertTrue("MaintenanceMode test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testIncidentReportGenerator() {
        System.out.println("\n--- [10/10] Testing IncidentReportGenerator ---");
        try {
            RiskScorer scorer = new RiskScorer();
            IncidentManager manager = new IncidentManager(scorer);
            EventHistory history = new EventHistory();
            LocalDateTime now = LocalDateTime.now();

            SecurityEvent ev = new SecurityEvent(now, EventType.FAILED_LOGIN, "10.0.0.200", "admin", "Failed pass");
            history.addEvent(ev);

            Incident inc = new Incident("INC-TEST-0099", "10.0.0.200", Severity.HIGH, 80, IncidentStatus.OPEN, now, now);
            Alert alert = new Alert("AUTH-001", "Brute Force", "desc", Severity.MEDIUM, "3 fails", List.of(), "10.0.0.200", 30, now);
            inc.addAlert(alert);

            IncidentReportGenerator gen = new IncidentReportGenerator();
            File reportFile = new File("reports/incident_test_report.txt");
            gen.generateStatefulReport(List.of(inc), List.of(ev), new ArrayList<>(), reportFile);

            assertTrue("Report file created on disk", reportFile.exists());
            String content = Files.readString(reportFile.toPath());
            assertTrue("Report contains Incident ID", content.contains("INC-TEST-0099"));
            assertTrue("Report contains Source IP", content.contains("10.0.0.200"));
            assertTrue("Report contains Triggered Rules", content.contains("AUTH-001"));

        Files.deleteIfExists(reportFile.toPath());
            history.clear();
            manager.clear();
        } catch (Exception e) {
            assertTrue("IncidentReportGenerator test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testSecurityHardeningAndResilience() {
        System.out.println("\n--- [11/11] Testing Security Hardening & Delimiter Injection Resilience ---");
        try {
            LocalDateTime now = LocalDateTime.now();

            // 1. Test pipe and newline injection in SecurityEvent fields
            SecurityEvent maliciousEvent = new SecurityEvent(
                    now, EventType.FAILED_LOGIN, "10.0.0.99|admin|extra", "dest|ip",
                    "admin\nattacker", "file|path\r\n.txt", "hash|value",
                    22, "TCP|UDP", "Details with | and \n and \r", "UNAUTHORIZED|ATTACK"
            );
            String csvLine = maliciousEvent.toCSVLine();
            assertTrue("CSV line contains exactly 10 pipe delimiters (11 columns)",
                    csvLine.chars().filter(ch -> ch == '|').count() == 10);
            assertTrue("CSV line does not contain unescaped newlines", !csvLine.contains("\n") && !csvLine.contains("\r"));

            SecurityEvent parsed = SecurityEvent.fromCSVLine(csvLine);
            assertEquals("Parsed event source IP sanitized correctly", "10.0.0.99/admin/extra", parsed.getSourceIP());
            assertEquals("Parsed event username sanitized correctly", "admin attacker", parsed.getUsername());

            // 2. Test delimiter injection in Incident audit log
            Incident inc = new Incident("INC-SEC-0001", "10.0.0.99", Severity.HIGH, 90, IncidentStatus.OPEN, now, now);
            inc.addAuditLog("Action with | pipes and ; semicolons and \n newlines");
            String incCsv = inc.toCSVLine();
            assertTrue("Incident CSV line contains exactly 8 pipe delimiters (9 columns)",
                    incCsv.chars().filter(ch -> ch == '|').count() == 8);

            // 3. Constant-time baseline checksum check
            BaselineManager bm = new BaselineManager();
            Path tempBase = Files.createTempFile("sec_baseline", ".baseline");
            Path tempSha = Path.of(tempBase.toString() + ".sha256");
            Files.writeString(tempBase, "# baseline content");
            Files.writeString(tempSha, new HashCalculator().calculateSHA256(tempBase.toFile()));

            assertTrue("Constant-time checksum comparison validates authentic baseline",
                    bm.verifyBaselineIntegrity(tempBase.toFile()));

            Files.deleteIfExists(tempBase);
            Files.deleteIfExists(tempSha);
        } catch (Exception e) {
            assertTrue("Security hardening test threw exception: " + e.getMessage(), false);
        }
    }

    private static void testAttackSimulator() {
        System.out.println("\n--- [12/12] Testing AttackSimulator Engine ---");
        try {
            RiskScorer scorer = new RiskScorer();
            IncidentManager manager = new IncidentManager(scorer);
            DetectionEngine engine = new DetectionEngine(scorer);
            EventHistory history = new EventHistory();
            history.clear();
            manager.clear();

            engine.setEventHistory(history);
            engine.setIncidentManager(manager);

            sentinelcheck.simulation.AttackSimulator simulator =
                    new sentinelcheck.simulation.AttackSimulator(engine, manager, history);

            // Run simulation stages
            simulator.simulatePortProbing("192.168.1.250");
            simulator.simulateBruteForce("192.168.1.250");
            simulator.simulateSuspiciousSuccess("192.168.1.250");
            simulator.simulateFileTampering();

            List<Incident> incidents = manager.getIncidents();
            assertTrue("Attack simulation generated active incidents", incidents.size() >= 2);

            boolean hasFwRule = false, hasAuth1 = false, hasAuth2 = false, hasAuth3 = false, hasCorr = false, hasFileMod = false, hasFileTamper = false;
            for (Incident inc : incidents) {
                for (Alert a : inc.getAlerts()) {
                    if (a.getRuleId().equals("FW-001")) hasFwRule = true;
                    if (a.getRuleId().equals("AUTH-001")) hasAuth1 = true;
                    if (a.getRuleId().equals("AUTH-002")) hasAuth2 = true;
                    if (a.getRuleId().equals("AUTH-003")) hasAuth3 = true;
                    if (a.getRuleId().equals("CORR-001")) hasCorr = true;
                    if (a.getRuleId().equals("FILE-001")) hasFileMod = true;
                    if (a.getRuleId().equals("FILE-004")) hasFileTamper = true;
                }
            }

            assertTrue("Simulator triggered FW-001", hasFwRule);
            assertTrue("Simulator triggered AUTH-001", hasAuth1);
            assertTrue("Simulator triggered AUTH-002", hasAuth2);
            assertTrue("Simulator triggered AUTH-003", hasAuth3);
            assertTrue("Simulator triggered CORR-001", hasCorr);
            assertTrue("Simulator triggered FILE-001", hasFileMod);
            assertTrue("Simulator triggered FILE-004", hasFileTamper);

            history.clear();
            manager.clear();
        } catch (Exception e) {
            assertTrue("AttackSimulator test threw exception: " + e.getMessage(), false);
        }
    }
}
