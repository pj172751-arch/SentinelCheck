package sentinelcheck.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a security alert produced by the detection engine.
 *
 * An alert aggregates one or more related SecurityEvents,
 * carries a severity level and a numeric risk score,
 * and provides a human-readable description for the report.
 */
public class Alert {

    private final String alertType;
    private final Severity severity;
    private final String description;
    private final List<SecurityEvent> relatedEvents;
    private final String sourceIP;
    private final int riskScore;
    private final LocalDateTime timestamp;

    public Alert(String alertType, Severity severity, String description,
                 List<SecurityEvent> relatedEvents, String sourceIP,
                 int riskScore, LocalDateTime timestamp) {
        this.alertType = alertType;
        this.severity = severity;
        this.description = description;
        this.relatedEvents = relatedEvents != null
                ? new ArrayList<>(relatedEvents)
                : new ArrayList<>();
        this.sourceIP = sourceIP;
        this.riskScore = riskScore;
        this.timestamp = timestamp;
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
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(severity).append("] ").append(alertType);
        if (!sourceIP.isEmpty()) {
            sb.append(" | IP: ").append(sourceIP);
        }
        sb.append(" | Score: ").append(riskScore);
        sb.append("\n  ").append(description);
        return sb.toString();
    }
}
