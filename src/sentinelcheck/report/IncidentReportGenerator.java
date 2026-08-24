package sentinelcheck.report;

import sentinelcheck.logs.AuthenticationMonitor;
import sentinelcheck.logs.FirewallMonitor;
import sentinelcheck.model.Alert;
import sentinelcheck.model.FileRecord;
import sentinelcheck.model.FileStatus;
import sentinelcheck.model.Severity;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Generates the plain-text SentinelCheck Incident Report.
 *
 * Report sections:
 *   1. Header with scan timestamp
 *   2. File Integrity Events
 *   3. Authentication Events
 *   4. Firewall Events
 *   5. Correlated Incidents
 *   6. Summary with counts and overall risk level
 */
public class IncidentReportGenerator {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String SEPARATOR =
            "==================================================";
    private static final String SECTION_LINE =
            "--------------------------------------------------";

    /**
     * Generates the full incident report and writes it to a file.
     *
     * @param fileRecords        integrity check results (may be null)
     * @param authResults        authentication analysis results (may be null)
     * @param firewallResults    firewall analysis results (may be null)
     * @param alerts             all generated alerts (may be null)
     * @param correlatedAlerts   correlated incident alerts (may be null)
     * @param overallRisk        the overall risk severity
     * @param reportFile         where to write the report
     * @throws IOException if the report cannot be written
     */
    public void generateReport(List<FileRecord> fileRecords,
                                List<AuthenticationMonitor.AuthResult> authResults,
                                List<FirewallMonitor.FirewallResult> firewallResults,
                                List<Alert> alerts,
                                List<Alert> correlatedAlerts,
                                Severity overallRisk,
                                File reportFile) throws IOException {

        // Ensure the reports directory exists
        File parentDir = reportFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        StringBuilder report = new StringBuilder();

        // ─── Header ──────────────────────────────────────────────
        report.append(SEPARATOR).append("\n");
        report.append("              SENTINELCHECK\n");
        report.append("           SECURITY INCIDENT REPORT\n");
        report.append(SEPARATOR).append("\n\n");
        report.append("Scan Time: ").append(LocalDateTime.now().format(TIMESTAMP_FORMAT));
        report.append("\n\n");

        // ─── File Integrity Events ───────────────────────────────
        report.append("FILE INTEGRITY EVENTS\n");
        report.append(SECTION_LINE).append("\n");

        if (fileRecords != null && !fileRecords.isEmpty()) {
            int modifiedCount = 0, missingCount = 0, newCount = 0, unchangedCount = 0;

            for (FileRecord record : fileRecords) {
                switch (record.getStatus()) {
                    case MODIFIED:
                        modifiedCount++;
                        report.append("[MODIFIED]\n");
                        report.append("  File: ").append(record.getFilePath()).append("\n");
                        report.append("  Old SHA-256: ").append(record.getOldHash()).append("\n");
                        report.append("  New SHA-256: ").append(record.getNewHash()).append("\n\n");
                        break;
                    case NEW:
                        newCount++;
                        report.append("[NEW]\n");
                        report.append("  File: ").append(record.getFilePath()).append("\n");
                        report.append("  SHA-256: ").append(record.getNewHash()).append("\n\n");
                        break;
                    case MISSING:
                        missingCount++;
                        report.append("[MISSING]\n");
                        report.append("  File: ").append(record.getFilePath()).append("\n");
                        report.append("  Last known SHA-256: ").append(record.getOldHash()).append("\n\n");
                        break;
                    case UNCHANGED:
                        unchangedCount++;
                        break;
                }
            }

            if (modifiedCount == 0 && missingCount == 0 && newCount == 0) {
                report.append("  All ").append(unchangedCount)
                        .append(" files passed integrity check.\n\n");
            }
        } else {
            report.append("  No file integrity scan was performed.\n\n");
        }

        // ─── Authentication Events ───────────────────────────────
        report.append("AUTHENTICATION EVENTS\n");
        report.append(SECTION_LINE).append("\n");

        if (authResults != null && !authResults.isEmpty()) {
            boolean hasAlerts = false;
            for (AuthenticationMonitor.AuthResult result : authResults) {
                if (result.isAlert()) {
                    hasAlerts = true;
                    report.append("[ALERT]\n");
                    report.append("  IP: ").append(result.getIpAddress()).append("\n");
                    report.append("  Failed Login Attempts: ")
                            .append(result.getFailedAttempts()).append("\n");
                    report.append("  Severity: ").append(result.getSeverity()).append("\n\n");
                }
            }

            if (!hasAlerts) {
                report.append("  No authentication alerts triggered.\n\n");
            }

            // Also show the full IP table
            report.append("  IP Summary Table:\n");
            report.append("  ").append(String.format("%-18s  %-16s  %s\n",
                    "IP", "Failed Attempts", "Status"));
            report.append("  ").append(String.format("%-18s  %-16s  %s\n",
                    "──────────────────", "────────────────", "──────────"));
            for (AuthenticationMonitor.AuthResult result : authResults) {
                String status = result.isAlert()
                        ? "⚠ " + result.getSeverity()
                        : "Normal";
                report.append("  ").append(String.format("%-18s  %-16d  %s\n",
                        result.getIpAddress(), result.getFailedAttempts(), status));
            }
            report.append("\n");
        } else {
            report.append("  No authentication log was analyzed.\n\n");
        }

        // ─── Firewall Events ─────────────────────────────────────
        report.append("FIREWALL EVENTS\n");
        report.append(SECTION_LINE).append("\n");

        if (firewallResults != null && !firewallResults.isEmpty()) {
            for (FirewallMonitor.FirewallResult result : firewallResults) {
                report.append("[DROP]\n");
                report.append("  Source IP: ").append(result.getSourceIP()).append("\n");
                report.append("  DROP Count: ").append(result.getDropCount()).append("\n");
                report.append("  Targeted Ports: ")
                        .append(String.join(", ", result.getTargetedPorts())).append("\n");
                report.append("  Severity: ").append(result.getSeverity()).append("\n\n");
            }
        } else {
            report.append("  No firewall log was analyzed.\n\n");
        }

        // ─── Correlated Incidents ────────────────────────────────
        report.append("CORRELATED INCIDENTS\n");
        report.append(SECTION_LINE).append("\n");

        if (correlatedAlerts != null && !correlatedAlerts.isEmpty()) {
            for (Alert correlated : correlatedAlerts) {
                report.append("[").append(correlated.getSeverity()).append("]\n");
                report.append("  Source: ").append(correlated.getSourceIP()).append("\n");
                report.append("  Combined Risk Score: ")
                        .append(correlated.getRiskScore()).append("\n");
                report.append("  ").append(correlated.getDescription()
                        .replace("\n", "\n  ")).append("\n\n");
            }
        } else {
            report.append("  No correlated incidents detected.\n\n");
        }

        // ─── Summary ────────────────────────────────────────────
        report.append(SEPARATOR).append("\n");
        report.append("SUMMARY\n");
        report.append(SEPARATOR).append("\n\n");

        // Count file events
        int filesModified = 0, filesMissing = 0, filesAdded = 0;
        if (fileRecords != null) {
            for (FileRecord r : fileRecords) {
                switch (r.getStatus()) {
                    case MODIFIED: filesModified++; break;
                    case MISSING:  filesMissing++;  break;
                    case NEW:      filesAdded++;    break;
                }
            }
        }

        int authAlertCount = 0;
        if (authResults != null) {
            for (AuthenticationMonitor.AuthResult r : authResults) {
                if (r.isAlert()) authAlertCount++;
            }
        }

        int fwDropCount = firewallResults != null ? firewallResults.size() : 0;
        int correlatedCount = correlatedAlerts != null ? correlatedAlerts.size() : 0;

        report.append(String.format("  Files Modified:        %d\n", filesModified));
        report.append(String.format("  Files Missing:         %d\n", filesMissing));
        report.append(String.format("  Files Added:           %d\n", filesAdded));
        report.append(String.format("  Authentication Alerts: %d\n", authAlertCount));
        report.append(String.format("  Firewall DROP Sources: %d\n", fwDropCount));
        report.append(String.format("  Correlated Incidents:  %d\n", correlatedCount));
        report.append("\n");
        report.append("  Overall Risk: ").append(overallRisk).append("\n");
        report.append("\n").append(SEPARATOR).append("\n");

        // Write to file
        String reportContent = report.toString();
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(reportFile))) {
            writer.write(reportContent);
        }

        // Also print to console
        System.out.println(reportContent);
    }
}
