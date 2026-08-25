package sentinelcheck.detection;

import sentinelcheck.model.Severity;

import java.util.HashMap;
import java.util.Map;

/**
 * Centralized, explainable risk scoring engine for SentinelCheck.
 * Assigns numeric weights to rules and maps cumulative scores to severity tiers.
 */
public class RiskScorer {

    // Thresholds
    private int thresholdMedium = 30;
    private int thresholdHigh = 60;
    private int thresholdCritical = 100;

    // Centralized rule weights
    private final Map<String, Integer> ruleScores;

    public RiskScorer() {
        ruleScores = new HashMap<>();
        resetDefaults();
    }

    public void resetDefaults() {
        ruleScores.put("FILE-001", 40);  // File Modified
        ruleScores.put("FILE-002", 30);  // File Missing
        ruleScores.put("FILE-003", 20);  // File New
        ruleScores.put("FILE-004", 100); // Baseline Tampered
        
        ruleScores.put("AUTH-001", 30);  // Brute Force
        ruleScores.put("AUTH-002", 50);  // Suspicious Success
        ruleScores.put("AUTH-003", 40);  // Multiple Account Targeting
        
        ruleScores.put("FW-001", 30);   // Port Probing
        ruleScores.put("CORR-001", 20);  // Correlation Bonus
    }

    /**
     * Looks up the score for a specific rule ID.
     */
    public int scoreRule(String ruleId) {
        return ruleScores.getOrDefault(ruleId, 10); // default to 10 points if unknown
    }

    public void setRuleScore(String ruleId, int score) {
        ruleScores.put(ruleId, score);
    }

    public Map<String, Integer> getRuleScores() {
        return new HashMap<>(ruleScores);
    }

    /**
     * Legacy mappings for compatibility with SentinelCheck 1.0.
     */
    public int scoreAuthAlert(int failedCount) {
        int score = failedCount * 10;
        if (failedCount >= 3) {
            score += 30;
        }
        return score;
    }

    public int scoreFirewallAlert(int dropCount) {
        return dropCount * 15;
    }

    /**
     * Maps a cumulative risk score to a Severity level.
     */
    public Severity calculateSeverity(int totalScore) {
        if (totalScore >= thresholdCritical) {
            return Severity.CRITICAL;
        } else if (totalScore >= thresholdHigh) {
            return Severity.HIGH;
        } else if (totalScore >= thresholdMedium) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }

    // Configurable thresholds getters and setters
    public int getThresholdMedium() {
        return thresholdMedium;
    }

    public void setThresholdMedium(int thresholdMedium) {
        this.thresholdMedium = thresholdMedium;
    }

    public int getThresholdHigh() {
        return thresholdHigh;
    }

    public void setThresholdHigh(int thresholdHigh) {
        this.thresholdHigh = thresholdHigh;
    }

    public int getThresholdCritical() {
        return thresholdCritical;
    }

    public void setThresholdCritical(int thresholdCritical) {
        this.thresholdCritical = thresholdCritical;
    }
}
