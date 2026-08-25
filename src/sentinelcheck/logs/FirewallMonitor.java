package sentinelcheck.logs;

import sentinelcheck.model.Alert;
import sentinelcheck.model.EventType;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;
import sentinelcheck.detection.RiskScorer;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Analyzes firewall log events to detect and summarize DROP activity.
 */
public class FirewallMonitor {

    /**
     * Legacy analysis method used for batch summary reports (SentinelCheck 1.0).
     */
    public List<FirewallResult> analyzeFirewall(List<SecurityEvent> events) {
        Map<String, List<SecurityEvent>> dropsByIP = new LinkedHashMap<>();

        for (SecurityEvent event : events) {
            if (event.getEventType() == EventType.FIREWALL_DROP) {
                dropsByIP
                        .computeIfAbsent(event.getSourceIP(), k -> new ArrayList<>())
                        .add(event);
            }
        }

        List<FirewallResult> results = new ArrayList<>();
        for (Map.Entry<String, List<SecurityEvent>> entry : dropsByIP.entrySet()) {
            String ip = entry.getKey();
            List<SecurityEvent> drops = entry.getValue();
            Severity severity = determineSeverity(drops.size());

            List<String> targetedPorts = new ArrayList<>();
            for (SecurityEvent drop : drops) {
                String portInfo = drop.getPort() + "/" + drop.getProtocol();
                if (!targetedPorts.contains(portInfo)) {
                    targetedPorts.add(portInfo);
                }
            }

            results.add(new FirewallResult(ip, drops.size(), severity, targetedPorts, drops));
        }

        return results;
    }

    private Severity determineSeverity(int dropCount) {
        if (dropCount >= 5) {
            return Severity.HIGH;
        } else if (dropCount >= 3) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }

    /**
     * V2.0 port-probing rule detection (FW-001).
     * Triggers when a source IP attempts connections to a threshold of *unique* destination ports.
     */
    public List<Alert> detectFirewallAlerts(List<SecurityEvent> events, int portDiversityThreshold, RiskScorer riskScorer) {
        List<Alert> alerts = new ArrayList<>();

        // Group firewall DROP events by source IP
        Map<String, List<SecurityEvent>> dropsByIP = new HashMap<>();
        for (SecurityEvent event : events) {
            if (event.getEventType() == EventType.FIREWALL_DROP) {
                dropsByIP.computeIfAbsent(event.getSourceIP(), k -> new ArrayList<>()).add(event);
            }
        }

        for (Map.Entry<String, List<SecurityEvent>> entry : dropsByIP.entrySet()) {
            String ip = entry.getKey();
            if (ip.equals("LOCAL")) {
                continue;
            }

            List<SecurityEvent> drops = entry.getValue();
            Set<Integer> uniquePorts = new HashSet<>();
            List<String> portStrings = new ArrayList<>();
            for (SecurityEvent drop : drops) {
                uniquePorts.add(drop.getPort());
                String portStr = drop.getPort() + "/" + drop.getProtocol();
                if (!portStrings.contains(portStr)) {
                    portStrings.add(portStr);
                }
            }

            if (uniquePorts.size() >= portDiversityThreshold) {
                // Trigger FW-001: Port Probing Pattern
                // Use the latest drop timestamp
                LocalDateTime lastTimestamp = drops.stream()
                        .map(SecurityEvent::getTimestamp)
                        .max(LocalDateTime::compareTo)
                        .orElse(LocalDateTime.now());

                String description = String.format("Blocked connection attempts to %d unique destination ports (%s)",
                        uniquePorts.size(), String.join(", ", portStrings));

                int score = riskScorer.scoreRule("FW-001");
                Severity severity = riskScorer.calculateSeverity(score);

                alerts.add(new Alert(
                        "FW-001",
                        "Port Probing Pattern",
                        "PORT_PROBING_PATTERN",
                        severity,
                        description,
                        drops,
                        ip,
                        score,
                        lastTimestamp
                ));
            }
        }

        return alerts;
    }

    // ─── Inner result class ──────────────────────────────────────

    public static class FirewallResult {
        private final String sourceIP;
        private final int dropCount;
        private final Severity severity;
        private final List<String> targetedPorts;
        private final List<SecurityEvent> events;

        public FirewallResult(String sourceIP, int dropCount, Severity severity,
                               List<String> targetedPorts, List<SecurityEvent> events) {
            this.sourceIP = sourceIP;
            this.dropCount = dropCount;
            this.severity = severity;
            this.targetedPorts = targetedPorts;
            this.events = events;
        }

        public String getSourceIP() {
            return sourceIP;
        }

        public int getDropCount() {
            return dropCount;
        }

        public Severity getSeverity() {
            return severity;
        }

        public List<String> getTargetedPorts() {
            return targetedPorts;
        }

        public List<SecurityEvent> getEvents() {
            return events;
        }

        @Override
        public String toString() {
            return String.format("%-18s  DROPs: %-4d  Ports: %-20s  Severity: %s",
                    sourceIP, dropCount, String.join(", ", targetedPorts), severity);
        }
    }
}
