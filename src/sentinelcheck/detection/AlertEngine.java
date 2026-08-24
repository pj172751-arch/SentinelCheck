package sentinelcheck.detection;

import sentinelcheck.logs.AuthenticationMonitor;
import sentinelcheck.logs.FirewallMonitor;
import sentinelcheck.model.Alert;
import sentinelcheck.model.EventType;
import sentinelcheck.model.FileRecord;
import sentinelcheck.model.FileStatus;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Central alert engine that aggregates detections from all
 * three monitoring modules into a unified list of Alerts.
 *
 * Pipeline:
 *   File integrity results  → file alerts
 *   Auth log analysis       → brute-force alerts
 *   Firewall log analysis   → DROP alerts
 *   All alerts              → sorted by severity, then timestamp
 */
public class AlertEngine {

    private final AuthenticationMonitor authMonitor;
    private final FirewallMonitor firewallMonitor;
    private final RiskScorer riskScorer;

    public AlertEngine() {
        this.authMonitor = new AuthenticationMonitor();
        this.firewallMonitor = new FirewallMonitor();
        this.riskScorer = new RiskScorer();
    }

    /**
     * Processes all inputs and produces a unified, sorted alert list.
     *
     * @param fileRecords  results from the integrity checker (may be null)
     * @param authEvents   parsed authentication log events (may be null)
     * @param fwEvents     parsed firewall log events (may be null)
     * @return all generated alerts, sorted by severity (highest first)
     */
    public List<Alert> processAllEvents(List<FileRecord> fileRecords,
                                         List<SecurityEvent> authEvents,
                                         List<SecurityEvent> fwEvents) {
        List<Alert> allAlerts = new ArrayList<>();

        // ─── File integrity alerts ───────────────────────────────
        if (fileRecords != null) {
            for (FileRecord record : fileRecords) {
                Alert alert = createFileAlert(record);
                if (alert != null) {
                    allAlerts.add(alert);
                }
            }
        }

        // ─── Authentication alerts ───────────────────────────────
        if (authEvents != null) {
            List<AuthenticationMonitor.AuthResult> authResults =
                    authMonitor.analyzeAuthentication(authEvents);

            for (AuthenticationMonitor.AuthResult result : authResults) {
                if (result.isAlert()) {
                    int score = riskScorer.scoreAuthAlert(result.getFailedAttempts());
                    Severity severity = riskScorer.calculateSeverity(score);

                    allAlerts.add(new Alert(
                            "BRUTE_FORCE_ATTEMPT",
                            severity,
                            result.getFailedAttempts() + " failed login attempts "
                                    + "(threshold: " + authMonitor.getThreshold() + ")",
                            result.getEvents(),
                            result.getIpAddress(),
                            score,
                            result.getEvents().get(0).getTimestamp()));
                }
            }
        }

        // ─── Firewall alerts ─────────────────────────────────────
        if (fwEvents != null) {
            List<FirewallMonitor.FirewallResult> fwResults =
                    firewallMonitor.analyzeFirewall(fwEvents);

            for (FirewallMonitor.FirewallResult result : fwResults) {
                int score = riskScorer.scoreFirewallAlert(result.getDropCount());
                Severity severity = riskScorer.calculateSeverity(score);

                allAlerts.add(new Alert(
                        "FIREWALL_DROP",
                        severity,
                        result.getDropCount() + " blocked connection attempts. "
                                + "Targeted ports: "
                                + String.join(", ", result.getTargetedPorts()),
                        result.getEvents(),
                        result.getSourceIP(),
                        score,
                        result.getEvents().get(0).getTimestamp()));
            }
        }

        // ─── Sort: highest severity first, then by timestamp ─────
        allAlerts.sort((a, b) -> {
            int sevCompare = b.getSeverity().compareTo(a.getSeverity());
            if (sevCompare != 0) return sevCompare;
            return a.getTimestamp().compareTo(b.getTimestamp());
        });

        return allAlerts;
    }

    /**
     * Creates an alert from a file integrity record, if it represents a change.
     * UNCHANGED files do not produce alerts.
     */
    private Alert createFileAlert(FileRecord record) {
        if (record.getStatus() == FileStatus.UNCHANGED) {
            return null;
        }

        int score;
        String alertType;
        EventType eventType;

        switch (record.getStatus()) {
            case MODIFIED:
                score = RiskScorer.SCORE_FILE_MODIFIED;
                alertType = "FILE_MODIFIED";
                eventType = EventType.FILE_MODIFIED;
                break;
            case MISSING:
                score = RiskScorer.SCORE_FILE_MISSING;
                alertType = "FILE_MISSING";
                eventType = EventType.FILE_MISSING;
                break;
            case NEW:
                score = RiskScorer.SCORE_FILE_NEW;
                alertType = "FILE_NEW";
                eventType = EventType.FILE_NEW;
                break;
            default:
                return null;
        }

        Severity severity = riskScorer.calculateSeverity(score);

        // Create a SecurityEvent for the file change (for correlation)
        SecurityEvent fileEvent = new SecurityEvent(
                record.getTimestamp(), eventType,
                "", record.toString());

        List<SecurityEvent> relatedEvents = new ArrayList<>();
        relatedEvents.add(fileEvent);

        String description;
        if (record.getStatus() == FileStatus.MODIFIED) {
            description = "File: " + record.getFilePath()
                    + " | Old hash: " + record.getOldHash()
                    + " | New hash: " + record.getNewHash();
        } else {
            description = "File: " + record.getFilePath();
        }

        return new Alert(alertType, severity, description,
                relatedEvents, "", score, record.getTimestamp());
    }

    public AuthenticationMonitor getAuthMonitor() {
        return authMonitor;
    }

    public FirewallMonitor getFirewallMonitor() {
        return firewallMonitor;
    }

    public RiskScorer getRiskScorer() {
        return riskScorer;
    }
}
