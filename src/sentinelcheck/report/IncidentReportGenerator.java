package sentinelcheck.report;

import sentinelcheck.model.Alert;
import sentinelcheck.model.Incident;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Generates the plain-text SentinelCheck Incident Report detailing stateful incidents,
 * timelines, audit logs, and event histories.
 */
public class IncidentReportGenerator {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String SEPARATOR =
            "==============================================================";
    private static final String SECTION_LINE =
            "--------------------------------------------------------------";

    /**
     * Generates a stateful security monitoring report.
     */
    public void generateStatefulReport(List<Incident> incidents, List<SecurityEvent> events, 
                                       List<String> maintenanceAudit, File reportFile) throws IOException {

        // Ensure directories exist
        File parentDir = reportFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        StringBuilder sb = new StringBuilder();

        // ─── Header ──────────────────────────────────────────────
        sb.append(SEPARATOR).append("\n");
        sb.append("                       SENTINELCHECK\n");
        sb.append("                 STATEFUL INCIDENT REPORT\n");
        sb.append(SEPARATOR).append("\n\n");
        sb.append("Generated At : ").append(LocalDateTime.now().format(TIMESTAMP_FORMAT)).append("\n");
        sb.append("Total Events : ").append(events.size()).append("\n");
        sb.append("Incidents    : ").append(incidents.size()).append("\n\n");

        // ─── Active/Open Incidents ───────────────────────────────
        sb.append("INCIDENTS SUMMARY\n");
        sb.append(SECTION_LINE).append("\n");
        if (incidents.isEmpty()) {
            sb.append("  No security incidents recorded.\n\n");
        } else {
            for (Incident inc : incidents) {
                sb.append(String.format("ID         : %s\n", inc.getId()));
                sb.append(String.format("Status     : %s\n", inc.getStatus()));
                sb.append(String.format("Severity   : %s (Score: %d)\n", inc.getSeverity(), inc.getRiskScore()));
                sb.append(String.format("Source     : %s\n", inc.getSourceIP()));
                sb.append(String.format("First Seen : %s\n", inc.getFirstSeen().format(TIMESTAMP_FORMAT)));
                sb.append(String.format("Last Seen  : %s\n", inc.getLastSeen().format(TIMESTAMP_FORMAT)));
                
                sb.append("\n  TRIGGERED RULES:\n");
                for (Alert alert : inc.getAlerts()) {
                    sb.append(String.format("    - [%s] %s: %s (Points: +%d)\n", 
                            alert.getRuleId(), alert.getRuleName(), alert.getDescription(), alert.getRiskScore()));
                }

                sb.append("\n  AUDIT TRAIL:\n");
                for (String log : inc.getAuditTrail()) {
                    sb.append(String.format("    %s\n", log));
                }
                sb.append("\n").append(SECTION_LINE).append("\n");
            }
        }
        sb.append("\n");

        // ─── Maintenance Activity ───────────────────────────────
        sb.append("AUTHORIZED MAINTENANCE EVENTS\n");
        sb.append(SECTION_LINE).append("\n");
        if (maintenanceAudit.isEmpty()) {
            sb.append("  No maintenance activities logged.\n\n");
        } else {
            for (String log : maintenanceAudit) {
                sb.append("  ").append(log).append("\n");
            }
            sb.append("\n");
        }

        // ─── Timeline of Events ──────────────────────────────────
        sb.append("RAW EVENT HISTORY LOG (LATEST FIRST)\n");
        sb.append(SECTION_LINE).append("\n");
        if (events.isEmpty()) {
            sb.append("  No raw events recorded in history.\n\n");
        } else {
            List<SecurityEvent> sortedEvents = new ArrayList<>(events);
            sortedEvents.sort((a, b) -> b.getTimestamp().compareTo(a.getTimestamp())); // latest first
            
            for (SecurityEvent e : sortedEvents) {
                sb.append(String.format("  [%s] %-15s | Source: %-15s | Details: %s\n",
                        e.getTimestamp().format(TIMESTAMP_FORMAT),
                        e.getEventType(),
                        e.getSourceIP(),
                        e.getDetails()));
            }
            sb.append("\n");
        }

        sb.append(SEPARATOR).append("\n");
        sb.append("                       END OF REPORT\n");
        sb.append(SEPARATOR).append("\n");

        // Write to file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(reportFile))) {
            writer.write(sb.toString());
        }

        // Also print to console
        System.out.println(sb.toString());
    }

    /**
     * Legacy method skeleton kept for build safety, calling the upgraded stateful reporter.
     */
    public void generateReport(Object fileRecords, Object authResults, Object firewallResults,
                               Object alerts, Object correlatedAlerts, Severity overallRisk,
                               File reportFile) throws IOException {
        // Fallback or legacy wrapper (unused in 2.0 flow but compiles)
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(reportFile))) {
            writer.write("SentinelCheck 1.0 legacy report wrapper. Please run stateful scan instead.");
        }
    }
}
