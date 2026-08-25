package sentinelcheck.logs;

import sentinelcheck.model.Alert;
import sentinelcheck.model.EventType;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.model.Severity;
import sentinelcheck.detection.RiskScorer;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Analyzes authentication events to detect brute-force and suspicious login attempts.
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

    public int getThreshold() {
        return threshold;
    }

    /**
     * Legacy analysis method used for batch summary reports (SentinelCheck 1.0).
     */
    public List<AuthResult> analyzeAuthentication(List<SecurityEvent> events) {
        Map<String, List<SecurityEvent>> failedByIP = new LinkedHashMap<>();

        for (SecurityEvent event : events) {
            if (event.getEventType() == EventType.FAILED_LOGIN) {
                failedByIP
                        .computeIfAbsent(event.getSourceIP(), k -> new ArrayList<>())
                        .add(event);
            }
        }

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

    /**
     * V2.0 sliding-window rule detection.
     * Detects AUTH-001 (Brute Force), AUTH-002 (Suspicious Success), and AUTH-003 (Multiple Account Targeting).
     */
    public List<Alert> detectAuthAlerts(List<SecurityEvent> events, int authThreshold, 
                                        int windowMinutes, int multiAccountThreshold, RiskScorer riskScorer) {
        List<Alert> alerts = new ArrayList<>();

        // Group auth events by source IP
        Map<String, List<SecurityEvent>> ipEvents = new HashMap<>();
        for (SecurityEvent event : events) {
            if (event.getEventType() == EventType.FAILED_LOGIN || event.getEventType() == EventType.SUCCESSFUL_LOGIN) {
                ipEvents.computeIfAbsent(event.getSourceIP(), k -> new ArrayList<>()).add(event);
            }
        }

        for (Map.Entry<String, List<SecurityEvent>> entry : ipEvents.entrySet()) {
            String ip = entry.getKey();
            if (ip.equals("LOCAL")) {
                continue; // Skip local events for IP analysis
            }

            List<SecurityEvent> sortedEvents = new ArrayList<>(entry.getValue());
            sortedEvents.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp()));

            // 1. Detect AUTH-002: Suspicious Success (Multiple failures followed by a successful login)
            detectSuspiciousSuccess(ip, sortedEvents, authThreshold, windowMinutes, alerts, riskScorer);

            // 2. Detect AUTH-001: Brute Force Attempt (Slide window through failures)
            detectBruteForce(ip, sortedEvents, authThreshold, windowMinutes, alerts, riskScorer);

            // 3. Detect AUTH-003: Multiple Account Targeting (Slide window checking unique targeted users)
            detectMultipleAccountTargeting(ip, sortedEvents, windowMinutes, multiAccountThreshold, alerts, riskScorer);
        }

        return alerts;
    }

    private void detectBruteForce(String ip, List<SecurityEvent> sortedEvents, int authThreshold, 
                                  int windowMinutes, List<Alert> alerts, RiskScorer riskScorer) {
        // Collect failed events
        List<SecurityEvent> failures = new ArrayList<>();
        for (SecurityEvent e : sortedEvents) {
            if (e.getEventType() == EventType.FAILED_LOGIN) {
                failures.add(e);
            }
        }

        if (failures.size() < authThreshold) {
            return;
        }

        // Slide window
        for (int i = 0; i <= failures.size() - authThreshold; i++) {
            SecurityEvent startEvent = failures.get(i);
            List<SecurityEvent> windowFailures = new ArrayList<>();
            windowFailures.add(startEvent);

            for (int j = i + 1; j < failures.size(); j++) {
                SecurityEvent nextEvent = failures.get(j);
                long minutes = Duration.between(startEvent.getTimestamp(), nextEvent.getTimestamp()).toMinutes();
                if (minutes <= windowMinutes) {
                    windowFailures.add(nextEvent);
                } else {
                    break;
                }
            }

            if (windowFailures.size() >= authThreshold) {
                // Trigger Brute Force Alert
                LocalDateTime lastTimestamp = windowFailures.get(windowFailures.size() - 1).getTimestamp();
                Set<String> targetedUsers = new HashSet<>();
                for (SecurityEvent e : windowFailures) {
                    targetedUsers.add(e.getUsername());
                }

                String description = String.format("%d failed login attempts within %d minutes (Targeted accounts: %s)",
                        windowFailures.size(), windowMinutes, String.join(", ", targetedUsers));

                int score = riskScorer.scoreRule("AUTH-001");
                Severity severity = riskScorer.calculateSeverity(score);

                alerts.add(new Alert(
                        "AUTH-001",
                        "Brute Force Attempt",
                        "BRUTE_FORCE_ATTEMPT",
                        severity,
                        description,
                        windowFailures,
                        ip,
                        score,
                        lastTimestamp
                ));

                // Skip ahead to the end of this block to avoid spamming multiple alerts for the same window
                i += windowFailures.size() - 1;
            }
        }
    }

    private void detectSuspiciousSuccess(String ip, List<SecurityEvent> sortedEvents, int authThreshold, 
                                         int windowMinutes, List<Alert> alerts, RiskScorer riskScorer) {
        for (int i = 0; i < sortedEvents.size(); i++) {
            SecurityEvent current = sortedEvents.get(i);
            if (current.getEventType() == EventType.SUCCESSFUL_LOGIN) {
                LocalDateTime successTime = current.getTimestamp();
                List<SecurityEvent> priorFailures = new ArrayList<>();

                // Look backward for failed events within the window
                for (int j = i - 1; j >= 0; j--) {
                    SecurityEvent prior = sortedEvents.get(j);
                    if (prior.getEventType() == EventType.FAILED_LOGIN) {
                        long minutes = Duration.between(prior.getTimestamp(), successTime).toMinutes();
                        if (minutes <= windowMinutes) {
                            priorFailures.add(0, prior); // keep chronological order
                        } else {
                            break;
                        }
                    }
                }

                if (priorFailures.size() >= authThreshold) {
                    // Trigger AUTH-002: Suspicious Success
                    String description = String.format("Successful login as '%s' after %d failed attempts within %d minutes",
                            current.getUsername(), priorFailures.size(), windowMinutes);

                    List<SecurityEvent> contributingEvents = new ArrayList<>(priorFailures);
                    contributingEvents.add(current);

                    int score = riskScorer.scoreRule("AUTH-002");
                    Severity severity = riskScorer.calculateSeverity(score);

                    alerts.add(new Alert(
                            "AUTH-002",
                            "Suspicious Successful Login",
                            "SUSPICIOUS_AUTH_SEQUENCE",
                            severity,
                            description,
                            contributingEvents,
                            ip,
                            score,
                            successTime
                    ));
                }
            }
        }
    }

    private void detectMultipleAccountTargeting(String ip, List<SecurityEvent> sortedEvents, 
                                                int windowMinutes, int multiAccountThreshold, 
                                                List<Alert> alerts, RiskScorer riskScorer) {
        // Collect failed events
        List<SecurityEvent> failures = new ArrayList<>();
        for (SecurityEvent e : sortedEvents) {
            if (e.getEventType() == EventType.FAILED_LOGIN) {
                failures.add(e);
            }
        }

        if (failures.size() < multiAccountThreshold) {
            return;
        }

        for (int i = 0; i < failures.size(); i++) {
            SecurityEvent startEvent = failures.get(i);
            Set<String> uniqueUsers = new HashSet<>();
            uniqueUsers.add(startEvent.getUsername());
            List<SecurityEvent> windowFailures = new ArrayList<>();
            windowFailures.add(startEvent);

            for (int j = i + 1; j < failures.size(); j++) {
                SecurityEvent nextEvent = failures.get(j);
                long minutes = Duration.between(startEvent.getTimestamp(), nextEvent.getTimestamp()).toMinutes();
                if (minutes <= windowMinutes) {
                    uniqueUsers.add(nextEvent.getUsername());
                    windowFailures.add(nextEvent);
                } else {
                    break;
                }
            }

            if (uniqueUsers.size() >= multiAccountThreshold) {
                // Trigger Multiple Account Targeting Alert
                LocalDateTime lastTimestamp = windowFailures.get(windowFailures.size() - 1).getTimestamp();
                String description = String.format("Failed logins targeted %d unique accounts (%s) within %d minutes",
                        uniqueUsers.size(), String.join(", ", uniqueUsers), windowMinutes);

                int score = riskScorer.scoreRule("AUTH-003");
                Severity severity = riskScorer.calculateSeverity(score);

                alerts.add(new Alert(
                        "AUTH-003",
                        "Multiple Account Targeting",
                        "MULTIPLE_ACCOUNT_TARGETING",
                        severity,
                        description,
                        windowFailures,
                        ip,
                        score,
                        lastTimestamp
                ));

                // Slide ahead
                i += windowFailures.size() - 1;
            }
        }
    }

    // ─── Inner result class ──────────────────────────────────────

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
