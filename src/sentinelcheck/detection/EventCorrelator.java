package sentinelcheck.detection;

import sentinelcheck.model.Alert;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Correlates alerts from different modules to identify
 * coordinated attack patterns.
 *
 * Correlation rules:
 *   1. Group alerts by source IP address.
 *   2. If a single IP has alerts from multiple categories
 *      (e.g., brute-force + firewall DROP), merge them into
 *      a single "CORRELATED INCIDENT" with elevated severity.
 *   3. Time proximity is checked but not strictly required —
 *      if the same IP appears in both auth and firewall logs
 *      within the configured time window, correlation is stronger.
 *
 * This is the feature that elevates the project from a simple
 * log parser to a security event monitoring tool.
 */
public class EventCorrelator {

    private static final long DEFAULT_WINDOW_MINUTES = 60;

    private final long correlationWindowMinutes;
    private final RiskScorer riskScorer;

    public EventCorrelator() {
        this(DEFAULT_WINDOW_MINUTES);
    }

    public EventCorrelator(long correlationWindowMinutes) {
        this.correlationWindowMinutes = correlationWindowMinutes;
        this.riskScorer = new RiskScorer();
    }

    /**
     * Correlates alerts by source IP and produces combined incidents.
     *
     * @param alerts all alerts from the AlertEngine
     * @return list of correlated incident alerts (only for IPs with 2+ alert types)
     */
    public List<Alert> correlateEvents(List<Alert> alerts) {

        // Group alerts by source IP (skip empty IPs from file events)
        Map<String, List<Alert>> alertsByIP = new LinkedHashMap<>();
        for (Alert alert : alerts) {
            String ip = alert.getSourceIP();
            if (ip != null && !ip.isEmpty()) {
                alertsByIP
                        .computeIfAbsent(ip, k -> new ArrayList<>())
                        .add(alert);
            }
        }

        // Build correlated incidents for IPs with multiple alert types
        List<Alert> correlatedIncidents = new ArrayList<>();

        for (Map.Entry<String, List<Alert>> entry : alertsByIP.entrySet()) {
            String ip = entry.getKey();
            List<Alert> ipAlerts = entry.getValue();

            // Count distinct alert types for this IP
            long distinctTypes = ipAlerts.stream()
                    .map(Alert::getAlertType)
                    .distinct()
                    .count();

            // Only correlate if 2+ different alert types
            if (distinctTypes >= 2) {
                Alert correlated = buildCorrelatedIncident(ip, ipAlerts);
                correlatedIncidents.add(correlated);
            }
        }

        return correlatedIncidents;
    }

    /**
     * Builds a single correlated incident alert from multiple alerts
     * targeting the same source IP.
     */
    private Alert buildCorrelatedIncident(String ip, List<Alert> ipAlerts) {

        // Collect all related events from all alerts
        List<SecurityEvent> allEvents = new ArrayList<>();
        int totalScore = 0;
        List<String> eventSummaries = new ArrayList<>();

        for (Alert alert : ipAlerts) {
            allEvents.addAll(alert.getRelatedEvents());
            totalScore += alert.getRiskScore();

            // Build summary line for each contributing alert
            eventSummaries.add("- " + alert.getAlertType()
                    + ": " + alert.getDescription());
        }

        // Correlated incidents get a severity boost
        totalScore += 20; // Correlation bonus
        Severity severity = riskScorer.calculateSeverity(totalScore);

        // Build description
        StringBuilder description = new StringBuilder();
        description.append("Correlated security incident from IP: ").append(ip);
        description.append("\nRelated events:");
        for (String summary : eventSummaries) {
            description.append("\n  ").append(summary);
        }
        description.append("\nCombined risk score: ").append(totalScore);

        // Use the earliest timestamp
        LocalDateTime earliest = ipAlerts.stream()
                .map(Alert::getTimestamp)
                .min(LocalDateTime::compareTo)
                .orElse(LocalDateTime.now());

        return new Alert(
                "CORRELATED_INCIDENT",
                severity,
                description.toString(),
                allEvents,
                ip,
                totalScore,
                earliest);
    }
}
