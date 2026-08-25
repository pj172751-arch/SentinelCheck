package sentinelcheck.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a security alert produced by the detection engine.
 *
 * An alert aggregates one or more related SecurityEvents,
 * carries a severity level, rule information, and a risk score.
 */
public class Alert {

    private final String alertId; // Deterministic ID for persistence
    private final String ruleId;  // e.g. "AUTH-001"
    private final String ruleName; // e.g. "Brute Force Attempt"
    private final String alertType; // Backwards compatibility for SentinelCheck 1.0
    private final Severity severity;
    private final String description;
    private final List<SecurityEvent> relatedEvents;
    private final String sourceIP;
    private final int riskScore;
    private final LocalDateTime timestamp;

    public Alert(String ruleId, String ruleName, String alertType, Severity severity, 
                 String description, List<SecurityEvent> relatedEvents, String sourceIP,
                 int riskScore, LocalDateTime timestamp) {
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.alertType = alertType;
        this.severity = severity;
        this.description = description;
        this.relatedEvents = relatedEvents != null ? new ArrayList<>(relatedEvents) : new ArrayList<>();
        this.sourceIP = sourceIP == null || sourceIP.isEmpty() ? "LOCAL" : sourceIP;
        this.riskScore = riskScore;
        this.timestamp = timestamp;

        // Generate a deterministic Alert ID based on properties to resolve links after restart
        String cleanIP = this.sourceIP.replace(".", "_").replace(":", "_");
        String timeStr = timestamp.format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        int descHash = Math.abs(description.hashCode() % 10000);
        this.alertId = ruleId + "_" + cleanIP + "_" + timeStr + "_" + descHash;
    }

    public String getAlertId() {
        return alertId;
    }

    public String getRuleId() {
        return ruleId;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getAlertType() {
        return alertType;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getDescription() {
        return description;
    }

    public List<SecurityEvent> getRelatedEvents() {
        return relatedEvents;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Alert other = (Alert) obj;
        return alertId.equals(other.alertId);
    }

    @Override
    public int hashCode() {
        return alertId.hashCode();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(severity).append("] ").append(ruleId).append(" - ").append(ruleName);
        if (!sourceIP.equals("LOCAL")) {
            sb.append(" | Source IP: ").append(sourceIP);
        } else {
            sb.append(" | Scope: LOCAL");
        }
        sb.append(" | Score: ").append(riskScore);
        sb.append("\n  ").append(description);
        return sb.toString();
    }
}
