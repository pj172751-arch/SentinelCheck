package sentinelcheck.detection;

import sentinelcheck.model.Alert;
import sentinelcheck.model.Incident;
import sentinelcheck.model.IncidentStatus;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages the list of active security incidents, status transitions,
 * audit trails, and file-based persistence using data/incidents.csv.
 */
public class IncidentManager {

    private static final String INCIDENTS_FILE = "data/incidents.csv";
    private final List<Incident> incidents;
    private final List<Alert> unpromotedAlerts; // Caches standalone alerts that haven't triggered an incident
    private final List<String> maintenanceAuditTrail;
    private final RiskScorer riskScorer;

    private int incidentCounter = 1;
    private boolean maintenanceMode = false;
    private int promotionThreshold = 50;
    private int correlationWindowMinutes = 10;

    public IncidentManager(RiskScorer riskScorer) {
        this.incidents = new ArrayList<>();
        this.unpromotedAlerts = new ArrayList<>();
        this.maintenanceAuditTrail = new ArrayList<>();
        this.riskScorer = riskScorer;
        ensureDataDirExists();
    }

    private void ensureDataDirExists() {
        File dataDir = new File("data");
        if (!dataDir.exists()) {
            dataDir.mkdirs();
        }
    }

    public synchronized boolean isMaintenanceMode() {
        return maintenanceMode;
    }

    public synchronized void setMaintenanceMode(boolean active) {
        this.maintenanceMode = active;
    }

    public synchronized List<String> getMaintenanceAuditTrail() {
        return new ArrayList<>(maintenanceAuditTrail);
    }

    public synchronized void addMaintenanceEventAudit(SecurityEvent event) {
        String log = String.format("%s - AUTHORIZED_MAINTENANCE: File %s %s (Hash: %s)",
                event.getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                event.getFilePath(),
                event.getEventType(),
                event.getFileHash().isEmpty() ? "N/A" : event.getFileHash().substring(0, 8));
        maintenanceAuditTrail.add(log);
    }

    public synchronized List<Incident> getIncidents() {
        return new ArrayList<>(incidents);
    }

    public synchronized List<Alert> getUnpromotedAlerts() {
        return new ArrayList<>(unpromotedAlerts);
    }

    /**
     * Attempts to route a new Alert to an active incident or evaluate its promotion status.
     */
    public synchronized void addAlert(Alert alert) {
        // 1. Try to find an active (OPEN or ACKNOWLEDGED) incident from the same source
        Incident activeIncident = findActiveIncidentForSource(alert.getSourceIP(), alert.getTimestamp());
        
        if (activeIncident != null) {
            activeIncident.addAlert(alert);
            recalculateIncidentRisk(activeIncident);
            saveIncidents();
            return;
        }

        // 2. Check if there are other unpromoted alerts from the same source in the window
        Alert matchingUnpromoted = findUnpromotedAlertForSource(alert.getSourceIP(), alert.getTimestamp());
        
        if (matchingUnpromoted != null) {
            // Promote both to a new Incident
            unpromotedAlerts.remove(matchingUnpromoted);
            Incident incident = createNewIncident(alert.getSourceIP(), alert.getTimestamp());
            incident.addAlert(matchingUnpromoted);
            incident.addAlert(alert);
            recalculateIncidentRisk(incident);
            incidents.add(incident);
            saveIncidents();
            return;
        }

        // 3. Apply promotion policy for standalone alerts
        if (shouldPromoteStandalone(alert)) {
            Incident incident = createNewIncident(alert.getSourceIP(), alert.getTimestamp());
            incident.addAlert(alert);
            recalculateIncidentRisk(incident);
            incidents.add(incident);
            saveIncidents();
        } else {
            // Cache as unpromoted alert
            if (!unpromotedAlerts.contains(alert)) {
                unpromotedAlerts.add(alert);
            }
        }
    }

    private boolean shouldPromoteStandalone(Alert alert) {
        String ruleId = alert.getRuleId();
        // 1. Baseline tampered is critical -> Promote immediately
        if (ruleId.equals("FILE-004")) {
            return true;
        }
        // 2. Any protected-file integrity violation -> Promote immediately
        if (ruleId.equals("FILE-001") || ruleId.equals("FILE-002") || ruleId.equals("FILE-003")) {
            return true;
        }
        // 3. Triggered other standalone alerts only if risk score reaches promotionThreshold
        return alert.getRiskScore() >= promotionThreshold;
    }

    private Incident findActiveIncidentForSource(String source, LocalDateTime timestamp) {
        for (Incident inc : incidents) {
            if (inc.getStatus() != IncidentStatus.CLOSED && inc.getSourceIP().equalsIgnoreCase(source)) {
                long minutes = Duration.between(inc.getLastSeen(), timestamp).toMinutes();
                if (Math.abs(minutes) <= correlationWindowMinutes) {
                    return inc;
                }
            }
        }
        return null;
    }

    private Alert findUnpromotedAlertForSource(String source, LocalDateTime timestamp) {
        for (Alert a : unpromotedAlerts) {
            if (a.getSourceIP().equalsIgnoreCase(source)) {
                long minutes = Duration.between(a.getTimestamp(), timestamp).toMinutes();
                if (Math.abs(minutes) <= correlationWindowMinutes) {
                    return a;
                }
            }
        }
        return null;
    }

    private Incident createNewIncident(String source, LocalDateTime timestamp) {
        String dateStr = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String id = String.format("INC-%s-%04d", dateStr, incidentCounter++);
        return new Incident(id, source, Severity.LOW, 0, IncidentStatus.OPEN, timestamp, timestamp);
    }

    /**
     * Recalculates an incident's overall risk score and severity based on contributing alerts.
     */
    public synchronized void recalculateIncidentRisk(Incident incident) {
        int baseScore = 0;
        boolean hasFile = false;
        boolean hasAuth = false;
        boolean hasFw = false;

        List<Alert> alertList = incident.getAlerts();

        // Detect module representation
        for (Alert a : alertList) {
            if (a.getRuleId().equals("CORR-001")) {
                continue; // Correlation bonus is managed dynamically below
            }
            baseScore += a.getRiskScore();
            
            String id = a.getRuleId();
            if (id.startsWith("FILE")) hasFile = true;
            if (id.startsWith("AUTH")) hasAuth = true;
            if (id.startsWith("FW")) hasFw = true;
        }

        // Delegate cross-module correlation check to EventCorrelator
        EventCorrelator correlator = new EventCorrelator();
        Alert corrAlert = correlator.checkCorrelation(incident, correlationWindowMinutes, riskScorer);

        // Remove any existing correlation alert
        Alert existingCorr = null;
        for (Alert a : alertList) {
            if (a.getRuleId().equals("CORR-001")) {
                existingCorr = a;
                break;
            }
        }
        if (existingCorr != null) {
            incident.getAlerts().remove(existingCorr);
        }

        // Add correlation alert if rules matched
        if (corrAlert != null) {
            incident.getAlerts().add(corrAlert);
        }

        // Recalculate total score including new correlation state
        int finalScore = 0;
        for (Alert a : incident.getAlerts()) {
            finalScore += a.getRiskScore();
        }

        incident.setRiskScore(finalScore);
        incident.setSeverity(riskScorer.calculateSeverity(finalScore));
    }

    /**
     * Persists all stateful incidents to data/incidents.csv.
     */
    public synchronized void saveIncidents() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(INCIDENTS_FILE))) {
            for (Incident inc : incidents) {
                writer.write(inc.toCSVLine());
                writer.newLine();
            }
        } catch (IOException e) {
            System.err.println("  [ERROR] Failed to save incidents: " + e.getMessage());
        }
    }

    /**
     * Loads stateful incidents and binds them back to the list of regenerated Alerts.
     */
    public synchronized void loadIncidents(List<Alert> allAlerts) {
        incidents.clear();
        File file = new File(INCIDENTS_FILE);
        if (!file.exists()) {
            return;
        }

        int maxCounter = 0;
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }

                try {
                    String[] parts = line.split("\\|", -1);
                    String id = parts[0];
                    String sourceIP = parts[1];
                    Severity severity = Severity.valueOf(parts[2]);
                    int riskScore = Integer.parseInt(parts[3]);
                    IncidentStatus status = IncidentStatus.valueOf(parts[4]);
                    LocalDateTime firstSeen = LocalDateTime.parse(parts[5]);
                    LocalDateTime lastSeen = LocalDateTime.parse(parts[6]);
                    String alertIdsStr = parts[7];
                    String auditTrailStr = parts[8];

                    // Track highest counter to avoid ID overlap
                    String[] idParts = id.split("-");
                    if (idParts.length == 3) {
                        int serial = Integer.parseInt(idParts[2]);
                        if (serial > maxCounter) {
                            maxCounter = serial;
                        }
                    }

                    Incident incident = new Incident(id, sourceIP, severity, riskScore, status, firstSeen, lastSeen);
                    
                    // Re-bind alerts
                    if (!alertIdsStr.isEmpty()) {
                        String[] alertIds = alertIdsStr.split(",");
                        for (String aid : alertIds) {
                            Alert matchedAlert = findAlertById(aid, allAlerts);
                            if (matchedAlert != null) {
                                incident.addAlert(matchedAlert);
                            }
                        }
                    }

                    // Re-bind audit trail (clear the auto-generated log from constructor first)
                    incident.getAuditTrail().clear();
                    if (!auditTrailStr.isEmpty()) {
                        String[] auditLogs = auditTrailStr.split(";");
                        for (String auditLog : auditLogs) {
                            incident.loadAuditLogEntry(auditLog);
                        }
                    }

                    incidents.add(incident);

                } catch (Exception e) {
                    System.err.println("  [WARN] Skipping malformed incident entry: " + e.getMessage());
                }
            }

            this.incidentCounter = maxCounter + 1;

        } catch (IOException e) {
            System.err.println("  [ERROR] Failed to load incidents: " + e.getMessage());
        }
    }

    private Alert findAlertById(String alertId, List<Alert> allAlerts) {
        for (Alert a : allAlerts) {
            if (a.getAlertId().equals(alertId)) {
                return a;
            }
        }
        return null;
    }

    public synchronized Incident findIncidentById(String id) {
        for (Incident inc : incidents) {
            if (inc.getId().equalsIgnoreCase(id)) {
                return inc;
            }
        }
        return null;
    }

    public synchronized void clear() {
        incidents.clear();
        unpromotedAlerts.clear();
        maintenanceAuditTrail.clear();
        incidentCounter = 1;
        File file = new File(INCIDENTS_FILE);
        if (file.exists()) {
            file.delete();
        }
    }
}
