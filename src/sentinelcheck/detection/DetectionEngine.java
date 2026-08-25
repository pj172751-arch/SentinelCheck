package sentinelcheck.detection;

import sentinelcheck.logs.AuthenticationMonitor;
import sentinelcheck.logs.FirewallMonitor;
import sentinelcheck.model.Alert;
import sentinelcheck.model.EventType;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;

import java.io.File;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Executes detection rules over security events and routes alerts to the IncidentManager.
 */
public class DetectionEngine {

    private final AuthenticationMonitor authMonitor;
    private final FirewallMonitor firewallMonitor;
    private final RiskScorer riskScorer;
    private EventHistory eventHistory;
    private IncidentManager incidentManager;

    // Configuration thresholds
    private int authThreshold = 3;
    private int authWindowMinutes = 5;
    private int multiAccountThreshold = 3;
    private int portDiversityThreshold = 5;

    public DetectionEngine(RiskScorer riskScorer) {
        this.authMonitor = new AuthenticationMonitor();
        this.firewallMonitor = new FirewallMonitor();
        this.riskScorer = riskScorer;
    }

    public void setEventHistory(EventHistory eventHistory) {
        this.eventHistory = eventHistory;
    }

    public void setIncidentManager(IncidentManager incidentManager) {
        this.incidentManager = incidentManager;
    }

    /**
     * Processes a single incoming SecurityEvent in real-time.
     */
    public void processNewEvent(SecurityEvent event) {
        if (eventHistory == null || incidentManager == null) {
            return;
        }

        // Suppress alerts if event occurred during maintenance mode
        if (event.getAuthorizationContext().equalsIgnoreCase("MAINTENANCE")) {
            incidentManager.addMaintenanceEventAudit(event);
            return;
        }

        EventType type = event.getEventType();

        if (type == EventType.FILE_MODIFIED || type == EventType.FILE_MISSING || 
            type == EventType.FILE_NEW || type == EventType.BASELINE_TAMPERED) {
            
            Alert alert = createFileAlert(event);
            if (alert != null) {
                incidentManager.addAlert(alert);
            }
            
        } else if (type == EventType.FAILED_LOGIN || type == EventType.SUCCESSFUL_LOGIN) {
            // Find all historic auth events for this IP
            List<SecurityEvent> ipAuthEvents = getEventsByIP(event.getSourceIP());
            List<Alert> authAlerts = authMonitor.detectAuthAlerts(
                    ipAuthEvents, authThreshold, authWindowMinutes, multiAccountThreshold, riskScorer);
            
            for (Alert alert : authAlerts) {
                incidentManager.addAlert(alert);
            }
            
        } else if (type == EventType.FIREWALL_DROP) {
            // Find all historic drops for this IP
            List<SecurityEvent> ipDropEvents = getEventsByIP(event.getSourceIP());
            List<Alert> fwAlerts = firewallMonitor.detectFirewallAlerts(
                    ipDropEvents, portDiversityThreshold, riskScorer);
            
            for (Alert alert : fwAlerts) {
                incidentManager.addAlert(alert);
            }
        }
    }

    /**
     * Helper to retrieve all events matching a source IP from history.
     */
    private List<SecurityEvent> getEventsByIP(String ip) {
        if (ip == null || ip.isEmpty() || ip.equals("LOCAL")) {
            return Collections.emptyList();
        }
        List<SecurityEvent> result = new ArrayList<>();
        for (SecurityEvent e : eventHistory.getEvents()) {
            if (ip.equals(e.getSourceIP())) {
                result.add(e);
            }
        }
        return result;
    }

    /**
     * Generates a standalone alert for file integrity events.
     */
    private Alert createFileAlert(SecurityEvent event) {
        String ruleId;
        String ruleName;
        String description;

        switch (event.getEventType()) {
            case FILE_MODIFIED:
                ruleId = "FILE-001";
                ruleName = "File Modified";
                description = "Integrity check failed: " + event.getDetails();
                break;
            case FILE_MISSING:
                ruleId = "FILE-002";
                ruleName = "File Missing";
                description = "Expected baseline file removed: " + event.getDetails();
                break;
            case FILE_NEW:
                ruleId = "FILE-003";
                ruleName = "New File Detected";
                String name = event.getFilePath();
                if (isSuspiciousExtension(name)) {
                    ruleName = "Suspicious New Executable";
                    description = "Suspicious executable file written in protected directory: " + name;
                } else {
                    description = "Untracked file added: " + name;
                }
                break;
            case BASELINE_TAMPERED:
                ruleId = "FILE-004";
                ruleName = "Baseline Tampered";
                description = "CRITICAL: Sibling baseline integrity checksum mismatch! The baseline file has been modified.";
                break;
            default:
                return null;
        }

        int score = riskScorer.scoreRule(ruleId);
        Severity severity = riskScorer.calculateSeverity(score);

        return new Alert(
                ruleId,
                ruleName,
                event.getEventType().name(),
                severity,
                description,
                Collections.singletonList(event),
                "LOCAL",
                score,
                event.getTimestamp()
        );
    }

    private boolean isSuspiciousExtension(String filename) {
        String lower = filename.toLowerCase();
        return lower.endsWith(".exe") || lower.endsWith(".bat") || lower.endsWith(".cmd") ||
               lower.endsWith(".sh")  || lower.endsWith(".bin") || lower.endsWith(".msi") ||
               lower.endsWith(".vbs") || lower.endsWith(".ps1");
    }

    /**
     * Processes a batch of events and returns all detected alerts.
     */
    public List<Alert> processAllEvents(List<SecurityEvent> batchEvents) {
        List<Alert> alerts = new ArrayList<>();

        // 1. Process File events individually
        List<SecurityEvent> fileEvents = new ArrayList<>();
        List<SecurityEvent> authEvents = new ArrayList<>();
        List<SecurityEvent> fwEvents = new ArrayList<>();

        for (SecurityEvent e : batchEvents) {
            if (e.getEventType() == EventType.FILE_MODIFIED || e.getEventType() == EventType.FILE_MISSING || 
                e.getEventType() == EventType.FILE_NEW || e.getEventType() == EventType.BASELINE_TAMPERED) {
                fileEvents.add(e);
            } else if (e.getEventType() == EventType.FAILED_LOGIN || e.getEventType() == EventType.SUCCESSFUL_LOGIN) {
                authEvents.add(e);
            } else if (e.getEventType() == EventType.FIREWALL_DROP) {
                fwEvents.add(e);
            }
        }

        // Add file alerts
        for (SecurityEvent fe : fileEvents) {
            if (fe.getAuthorizationContext().equalsIgnoreCase("MAINTENANCE")) {
                continue;
            }
            Alert fa = createFileAlert(fe);
            if (fa != null) {
                alerts.add(fa);
            }
        }

        // Run batch auth rules
        alerts.addAll(authMonitor.detectAuthAlerts(authEvents, authThreshold, authWindowMinutes, multiAccountThreshold, riskScorer));

        // Run batch firewall rules
        alerts.addAll(firewallMonitor.detectFirewallAlerts(fwEvents, portDiversityThreshold, riskScorer));

        return alerts;
    }

    // Getters and Setters for thresholds
    public int getAuthThreshold() {
        return authThreshold;
    }

    public void setAuthThreshold(int authThreshold) {
        this.authThreshold = authThreshold;
    }

    public int getAuthWindowMinutes() {
        return authWindowMinutes;
    }

    public void setAuthWindowMinutes(int authWindowMinutes) {
        this.authWindowMinutes = authWindowMinutes;
    }

    public int getMultiAccountThreshold() {
        return multiAccountThreshold;
    }

    public void setMultiAccountThreshold(int multiAccountThreshold) {
        this.multiAccountThreshold = multiAccountThreshold;
    }

    public int getPortDiversityThreshold() {
        return portDiversityThreshold;
    }

    public void setPortDiversityThreshold(int portDiversityThreshold) {
        this.portDiversityThreshold = portDiversityThreshold;
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
