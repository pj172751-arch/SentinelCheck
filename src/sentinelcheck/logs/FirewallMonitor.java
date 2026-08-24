package sentinelcheck.logs;

import sentinelcheck.model.EventType;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Analyzes firewall log events to detect and summarize DROP activity.
 *
 * Groups FIREWALL_DROP events by source IP and produces
 * a summary of blocked connection attempts, including
 * targeted ports and protocols.
 */
public class FirewallMonitor {

    /**
     * Analyzes security events for firewall DROP patterns.
     *
     * @param events all parsed security events (will filter for FIREWALL_DROP)
     * @return summary of DROP events per source IP
     */
    public List<FirewallResult> analyzeFirewall(List<SecurityEvent> events) {

        // Group DROP events by source IP
        Map<String, List<SecurityEvent>> dropsByIP = new LinkedHashMap<>();

        for (SecurityEvent event : events) {
            if (event.getEventType() == EventType.FIREWALL_DROP) {
                dropsByIP
                        .computeIfAbsent(event.getSourceIP(), k -> new ArrayList<>())
                        .add(event);
            }
        }

        // Build results
        List<FirewallResult> results = new ArrayList<>();

        for (Map.Entry<String, List<SecurityEvent>> entry : dropsByIP.entrySet()) {
            String ip = entry.getKey();
            List<SecurityEvent> drops = entry.getValue();
            Severity severity = determineSeverity(drops.size());

            // Collect unique targeted ports
            List<String> targetedPorts = new ArrayList<>();
            for (SecurityEvent drop : drops) {
                String portInfo = drop.getPort() + "/" + drop.getProtocol();
                if (!targetedPorts.contains(portInfo)) {
                    targetedPorts.add(portInfo);
                }
            }

            results.add(new FirewallResult(ip, drops.size(), severity,
                    targetedPorts, drops));
        }

        return results;
    }

    /**
     * Determines severity based on the number of DROP events from one IP.
     */
    private Severity determineSeverity(int dropCount) {
        if (dropCount >= 5) {
            return Severity.HIGH;
        } else if (dropCount >= 3) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }

    // ─── Inner result class ──────────────────────────────────────

    /**
     * Holds the analysis result for firewall DROP events from a single IP.
     */
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
