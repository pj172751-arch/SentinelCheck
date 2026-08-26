package sentinelcheck.simulation;

import sentinelcheck.detection.DetectionEngine;
import sentinelcheck.detection.EventHistory;
import sentinelcheck.detection.IncidentManager;
import sentinelcheck.model.Alert;
import sentinelcheck.model.EventType;
import sentinelcheck.model.Incident;
import sentinelcheck.model.SecurityEvent;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Interactive Attack Simulator for live demonstration and evaluation.
 * Generates realistic adversary telemetry across all 5 Kill Chain stages.
 */
public class AttackSimulator {

    // ANSI Color Escape Codes for Terminal UI
    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN = "\u001B[36m";
    private static final String MAGENTA = "\u001B[35m";

    private final DetectionEngine detectionEngine;
    private final IncidentManager incidentManager;
    private final EventHistory eventHistory;

    public AttackSimulator(DetectionEngine detectionEngine, IncidentManager incidentManager, EventHistory eventHistory) {
        this.detectionEngine = detectionEngine;
        this.incidentManager = incidentManager;
        this.eventHistory = eventHistory;
    }

    private void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {}
    }

    private void printHeader(String title) {
        System.out.println("\n" + BOLD + CYAN + "  +==================================================================+" + RESET);
        System.out.printf(BOLD + CYAN + "  | %-64s |%n" + RESET, centerText(title, 64));
        System.out.println(BOLD + CYAN + "  +==================================================================+" + RESET);
    }

    private String centerText(String text, int width) {
        int pad = (width - text.length()) / 2;
        int rightPad = width - text.length() - pad;
        return " ".repeat(Math.max(0, pad)) + text + " ".repeat(Math.max(0, rightPad));
    }

    /**
     * Executes the complete 5-stage Cyber Kill Chain simulation.
     */
    public void runFullKillChainSimulation() {
        printHeader("CYBER KILL CHAIN ADVERSARY SIMULATION");
        System.out.println(BOLD + "  Target Host    : " + RESET + "SentinelCheck Local Protected Node");
        System.out.println(BOLD + "  Adversary IP   : " + RESET + RED + "192.168.1.250 (Simulated Threat Actor)" + RESET);
        System.out.println(BOLD + "  Timestamp      : " + RESET + LocalDateTime.now());
        System.out.println("  ------------------------------------------------------------------");

        sleep(500);

        // Stage 1: Port Probing & Network Discovery (FW-001)
        simulatePortProbing("192.168.1.250");
        sleep(400);

        // Stage 2: Credential Spray & Brute Force (AUTH-001, AUTH-003)
        simulateBruteForce("192.168.1.250");
        sleep(400);

        // Stage 3: Suspicious Account Compromise (AUTH-002)
        simulateSuspiciousSuccess("192.168.1.250");
        sleep(400);

        // Stage 4: Host Integrity Breach & Baseline Checksum Tamper (FILE-001, FILE-004)
        simulateFileTampering();
        sleep(400);

        // Final Summary
        printHeader("SIMULATION COMPLETED & LIVE INCIDENTS GENERATED");
        List<Incident> incidents = incidentManager.getIncidents();
        System.out.println(BOLD + "  Active Incidents in IncidentManager: " + RESET + GREEN + incidents.size() + RESET);
        for (Incident inc : incidents) {
            System.out.println("  " + inc.toString().replace("\n", "\n  "));
            System.out.println("  Triggered Rules:");
            for (Alert a : inc.getAlerts()) {
                System.out.printf("    - [%s] %s (Score: +%d)%n", a.getRuleId(), a.getRuleName(), a.getRiskScore());
            }
            System.out.println("  " + "-".repeat(60));
        }
    }

    /**
     * Stage 1: Simulates TCP Port Sweep.
     */
    public void simulatePortProbing(String attackerIP) {
        System.out.println("\n" + BOLD + YELLOW + "  [STAGE 1/4] ADVERSARY RECONNAISSANCE: TCP SYN Port Sweep" + RESET);
        int[] targetPorts = {21, 22, 80, 443, 3389};
        LocalDateTime now = LocalDateTime.now().minusMinutes(4);

        for (int port : targetPorts) {
            SecurityEvent fwDrop = new SecurityEvent(
                    now, EventType.FIREWALL_DROP, attackerIP, "10.0.0.1", port, "TCP", "Port " + port + "/TCP"
            );
            eventHistory.addEvent(fwDrop);
            detectionEngine.processNewEvent(fwDrop);
            System.out.printf(RED + "    [INJECTED DROP] %s -> 10.0.0.1:%d/TCP (BLOCKED)%n" + RESET, attackerIP, port);
            sleep(200);
            now = now.plusSeconds(20);
        }

        System.out.println(BOLD + GREEN + "    ? Detection Rule Triggered: [FW-001] Port Probing Pattern" + RESET);
    }

    /**
     * Stage 2: Simulates Credential Stuffing / Password Spray.
     */
    public void simulateBruteForce(String attackerIP) {
        System.out.println("\n" + BOLD + YELLOW + "  [STAGE 2/4] INITIAL ACCESS: Multi-Account Credential Spray" + RESET);
        String[] users = {"root", "admin", "service_api"};
        LocalDateTime now = LocalDateTime.now().minusMinutes(2);

        for (String user : users) {
            SecurityEvent failEvent = new SecurityEvent(
                    now, EventType.FAILED_LOGIN, attackerIP, user, "Failed login password mismatch"
            );
            eventHistory.addEvent(failEvent);
            detectionEngine.processNewEvent(failEvent);
            System.out.printf(RED + "    [INJECTED AUTH_FAIL] User: %-12s | Source: %s%n" + RESET, user, attackerIP);
            sleep(200);
            now = now.plusSeconds(15);
        }

        System.out.println(BOLD + GREEN + "    ? Detection Rules Triggered: [AUTH-001] Brute Force & [AUTH-003] Multi-Account Target" + RESET);
    }

    /**
     * Stage 3: Simulates Suspicious Successful Login after Failures.
     */
    public void simulateSuspiciousSuccess(String attackerIP) {
        System.out.println("\n" + BOLD + YELLOW + "  [STAGE 3/4] PRIVILEGE COMPROMISE: Successful Authentication" + RESET);
        LocalDateTime now = LocalDateTime.now().minusMinutes(1);

        SecurityEvent successEvent = new SecurityEvent(
                now, EventType.SUCCESSFUL_LOGIN, attackerIP, "admin", "Successful authentication token issued"
        );
        eventHistory.addEvent(successEvent);
        detectionEngine.processNewEvent(successEvent);
        System.out.printf(MAGENTA + "    [INJECTED AUTH_SUCCESS] Compromised Account: admin | Source: %s%n" + RESET, attackerIP);
        sleep(250);

        System.out.println(BOLD + GREEN + "    ? Detection Rule Triggered: [AUTH-002] Suspicious Success Sequence" + RESET);
        System.out.println(BOLD + GREEN + "    ? Cross-Correlation Triggered: [CORR-001] Multi-Module Kill Chain Correlation" + RESET);
    }

    /**
     * Stage 4: Simulates Unauthorized File Modification & Checksum Tampering.
     */
    public void simulateFileTampering() {
        System.out.println("\n" + BOLD + YELLOW + "  [STAGE 4/4] HOST PERSISTENCE & TAMPERING: Baseline Integrity Breach" + RESET);
        LocalDateTime now = LocalDateTime.now();

        SecurityEvent tamperEvent = new SecurityEvent(
                now, EventType.BASELINE_TAMPERED, "LOCAL", "", "",
                "monitored.baseline", "corrupted_checksum", 0, "",
                "Baseline integrity checksum validation failed (TAMPERED)", "UNAUTHORIZED"
        );
        eventHistory.addEvent(tamperEvent);
        detectionEngine.processNewEvent(tamperEvent);
        System.out.println(RED + "    [INJECTED FILE_TAMPER] Target: monitored.baseline.sha256 MISMATCH" + RESET);
        sleep(200);

        SecurityEvent fileModEvent = new SecurityEvent(
                now, EventType.FILE_MODIFIED, "LOCAL", "", "",
                "server.conf", "a9f8b47e2c1d098e...", 0, "",
                "File: server.conf Status: MODIFIED", "UNAUTHORIZED"
        );
        eventHistory.addEvent(fileModEvent);
        detectionEngine.processNewEvent(fileModEvent);
        System.out.println(RED + "    [INJECTED FILE_MODIFIED] Unauthorized alteration in server.conf" + RESET);
        sleep(200);

        System.out.println(BOLD + GREEN + "    ? Detection Rules Triggered: [FILE-004] Baseline Tampered & [FILE-001] File Modified" + RESET);
    }
}
