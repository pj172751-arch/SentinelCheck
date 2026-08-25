package sentinelcheck.detection;

import sentinelcheck.model.Alert;
import sentinelcheck.model.Incident;
import sentinelcheck.model.Severity;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Correlates alerts inside an incident to find cross-module coordinates.
 */
public class EventCorrelator {

    /**
     * Checks if the alerts within an incident span multiple security modules within the window.
     * If matched, returns a CORR-001 correlation Alert.
     */
    public Alert checkCorrelation(Incident incident, int windowMinutes, RiskScorer riskScorer) {
        List<Alert> alerts = new ArrayList<>();
        for (Alert a : incident.getAlerts()) {
            if (!a.getRuleId().equals("CORR-001")) {
                alerts.add(a);
            }
        }

        if (alerts.size() < 2) {
            return null;
        }

        boolean hasFile = false;
        boolean hasAuth = false;
        boolean hasFw = false;

        for (Alert a : alerts) {
            String ruleId = a.getRuleId();
            if (ruleId.startsWith("FILE")) hasFile = true;
            if (ruleId.startsWith("AUTH")) hasAuth = true;
            if (ruleId.startsWith("FW")) hasFw = true;
        }

        int moduleCount = 0;
        if (hasFile) moduleCount++;
        if (hasAuth) moduleCount++;
        if (hasFw) moduleCount++;

        // Only correlate if spanning 2 or more modules
        if (moduleCount < 2) {
            return null;
        }

        // Verify temporal proximity: find if at least two alerts occurred within windowMinutes of each other
        boolean temporalProximity = false;
        for (int i = 0; i < alerts.size(); i++) {
            LocalDateTime t1 = alerts.get(i).getTimestamp();
            for (int j = i + 1; j < alerts.size(); j++) {
                LocalDateTime t2 = alerts.get(j).getTimestamp();
                long diff = Math.abs(Duration.between(t1, t2).toMinutes());
                if (diff <= windowMinutes) {
                    temporalProximity = true;
                    break;
                }
            }
            if (temporalProximity) {
                break;
            }
        }

        if (!temporalProximity) {
            return null; // Alerts are too far apart in time
        }

        // Build list of rule IDs involved
        List<String> rulesInvolved = new ArrayList<>();
        for (Alert a : alerts) {
            rulesInvolved.add(a.getRuleId());
        }

        int bonus = riskScorer.scoreRule("CORR-001");
        Severity severity = riskScorer.calculateSeverity(bonus);

        String description = String.format("Correlated security activity across multiple modules (Rules: %s) within a %d-minute window.",
                String.join(", ", rulesInvolved), windowMinutes);

        return new Alert(
                "CORR-001",
                "Multi-Module Correlation",
                "CORRELATED_INCIDENT",
                severity,
                description,
                new ArrayList<>(),
                incident.getSourceIP(),
                bonus,
                LocalDateTime.now()
        );
    }

    /**
     * Legacy method for compatibility with SentinelCheck 1.0.
     */
    public List<Alert> correlateEvents(List<Alert> alerts) {
        return new ArrayList<>(); // Legacy logic is no longer needed but kept for compilation safety
    }
}
