package sentinelcheck.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents an stateful security incident in SentinelCheck.
 * An incident aggregates multiple related security alerts.
 */
public class Incident {
    private final String id;
    private final String sourceIP; // "LOCAL" or an IP address
    private Severity severity;
    private int riskScore;
    private IncidentStatus status;
    private final LocalDateTime firstSeen;
    private LocalDateTime lastSeen;
    private final List<Alert> alerts;
    private final List<String> auditTrail;

    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public Incident(String id, String sourceIP, Severity severity, int riskScore, 
                    IncidentStatus status, LocalDateTime firstSeen, LocalDateTime lastSeen) {
        this.id = id;
        this.sourceIP = sourceIP;
        this.severity = severity;
        this.riskScore = riskScore;
        this.status = status;
        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
        this.alerts = new ArrayList<>();
        this.auditTrail = new ArrayList<>();
        addAuditLog("Incident created");
    }

    public String getId() {
        return id;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public IncidentStatus getStatus() {
        return status;
    }

    public void setStatus(IncidentStatus status) {
        if (this.status != status) {
            IncidentStatus oldStatus = this.status;
            this.status = status;
            addAuditLog("Status changed from " + oldStatus + " to " + status);
        }
    }

    public LocalDateTime getFirstSeen() {
        return firstSeen;
    }

    public LocalDateTime getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(LocalDateTime lastSeen) {
        this.lastSeen = lastSeen;
    }

    public List<Alert> getAlerts() {
        return alerts;
    }

    public void addAlert(Alert alert) {
        if (!alerts.contains(alert)) {
            alerts.add(alert);
            addAuditLog("Alert attached: " + alert.getRuleId() + " (" + alert.getRuleName() + ")");
            if (alert.getTimestamp().isAfter(lastSeen)) {
                lastSeen = alert.getTimestamp();
            }
        }
    }

    public List<String> getAuditTrail() {
        return auditTrail;
    }

    public void addAuditLog(String action) {
        String logEntry = LocalDateTime.now().format(TIME_FORMAT) + " - " + action;
        auditTrail.add(logEntry);
    }

    public void loadAuditLogEntry(String logEntry) {
        auditTrail.add(logEntry);
    }

    /**
     * Serializes this incident to a CSV line.
     * Format: id|sourceIP|severity|riskScore|status|firstSeen|lastSeen|alertIds|auditTrail
     */
    public String toCSVLine() {
        List<String> alertIds = new ArrayList<>();
        for (Alert a : alerts) {
            alertIds.add(a.getAlertId());
        }
        String alertIdsStr = String.join(",", alertIds);
        String auditTrailStr = String.join(";", auditTrail);

        return String.join("|", 
            id, 
            sourceIP, 
            severity.name(), 
            String.valueOf(riskScore), 
            status.name(), 
            firstSeen.toString(), 
            lastSeen.toString(), 
            alertIdsStr, 
            auditTrailStr
        );
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Incident ID : ").append(id).append("\n");
        sb.append("Status      : ").append(status).append("\n");
        sb.append("Severity    : ").append(severity).append("\n");
        sb.append("Risk Score  : ").append(riskScore).append("\n");
        sb.append("Source      : ").append(sourceIP).append("\n");
        sb.append("First Seen  : ").append(firstSeen.format(TIME_FORMAT)).append("\n");
        sb.append("Last Seen   : ").append(lastSeen.format(TIME_FORMAT)).append("\n");
        return sb.toString();
    }
}
