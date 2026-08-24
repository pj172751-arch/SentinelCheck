package sentinelcheck.logs;

import sentinelcheck.model.EventType;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Analyzes authentication events to detect brute-force login attempts.
 *
 * Groups FAILED_LOGIN events by source IP address and flags
 * an alert when the count reaches or exceeds the threshold.
 *
 * Alert severity by failed attempt count:
 *   3–4 attempts  → MEDIUM
 *   5–9 attempts  → HIGH
 *   10+ attempts  → CRITICAL
 */
public class AuthenticationMonitor {

    private static final int DEFAULT_THRESHOLD = 3;

    private final int threshold;

    public AuthenticationMonitor() {
        this(DEFAULT_THRESHOLD);
    }

    public AuthenticationMonitor(int threshold) {
        this.threshold = threshold;
    }

    /**
     * Analyzes a list of security events for brute-force patterns.
     *
     * @param events all parsed security events (will filter for FAILED_LOGIN)
     * @return summary of failed login attempts per IP with alert status
     */
    public List<AuthResult> analyzeAuthentication(List<SecurityEvent> events) {

        // Count failed logins per IP
        Map<String, List<SecurityEvent>> failedByIP = new LinkedHashMap<>();

        for (SecurityEvent event : events) {
            if (event.getEventType() == EventType.FAILED_LOGIN) {
                failedByIP
                        .computeIfAbsent(event.getSourceIP(), k -> new ArrayList<>())
                        .add(event);
            }
        }

        // Build results with alert status
        List<AuthResult> results = new ArrayList<>();

        for (Map.Entry<String, List<SecurityEvent>> entry : failedByIP.entrySet()) {
            String ip = entry.getKey();
            List<SecurityEvent> attempts = entry.getValue();
            int count = attempts.size();
            boolean isAlert = count >= threshold;
            Severity severity = determineSeverity(count);

            results.add(new AuthResult(ip, count, isAlert, severity, attempts));
        }

        return results;
    }

    /**
     * Determines alert severity based on the number of failed attempts.
     */
    private Severity determineSeverity(int failedCount) {
        if (failedCount >= 10) {
            return Severity.CRITICAL;
        } else if (failedCount >= 5) {
            return Severity.HIGH;
        } else if (failedCount >= threshold) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }

    public int getThreshold() {
        return threshold;
    }

    // ─── Inner result class ──────────────────────────────────────

    /**
     * Holds the analysis result for a single IP address.
     */
    public static class AuthResult {

        private final String ipAddress;
        private final int failedAttempts;
        private final boolean alert;
        private final Severity severity;
        private final List<SecurityEvent> events;

        public AuthResult(String ipAddress, int failedAttempts, boolean alert,
                          Severity severity, List<SecurityEvent> events) {
            this.ipAddress = ipAddress;
            this.failedAttempts = failedAttempts;
            this.alert = alert;
            this.severity = severity;
            this.events = events;
        }

        public String getIpAddress() {
            return ipAddress;
        }

        public int getFailedAttempts() {
            return failedAttempts;
        }

        public boolean isAlert() {
            return alert;
        }

        public Severity getSeverity() {
            return severity;
        }

        public List<SecurityEvent> getEvents() {
            return events;
        }

        @Override
        public String toString() {
            String status = alert
                    ? "⚠ " + severity
                    : "Normal";
            return String.format("%-18s  Failed: %-4d  Status: %s",
                    ipAddress, failedAttempts, status);
        }
    }
}
