package sentinelcheck.detection;

import sentinelcheck.model.Severity;

/**
 * Transparent, rule-based risk scoring engine.
 *
 * Assigns numeric scores to individual events, then maps
 * the cumulative total to a severity level.
 *
 * Score table:
 *   Failed login (each)           +10
 *   3+ failed logins (per IP)     +30
 *   Firewall DROP (each)          +15
 *   Critical file modified        +40
 *   New file detected             +20
 *   Missing file                  +30
 *
 * Severity thresholds:
 *   0–29   LOW
 *   30–59  MEDIUM
 *   60–89  HIGH
 *   90+    CRITICAL
 *
 * No machine learning — fully explainable for a diploma project.
 */
public class RiskScorer {

    // ─── Individual event scores ─────────────────────────────────

    public static final int SCORE_FAILED_LOGIN       = 10;
    public static final int SCORE_BRUTE_FORCE_BONUS  = 30;
    public static final int SCORE_FIREWALL_DROP      = 15;
    public static final int SCORE_FILE_MODIFIED      = 40;
    public static final int SCORE_FILE_NEW           = 20;
    public static final int SCORE_FILE_MISSING       = 30;

    // ─── Severity thresholds ─────────────────────────────────────

    private static final int THRESHOLD_MEDIUM   = 30;
    private static final int THRESHOLD_HIGH     = 60;
    private static final int THRESHOLD_CRITICAL = 90;

    /**
     * Maps a cumulative risk score to a Severity level.
     *
     * @param totalScore the sum of all individual event scores
     * @return the corresponding Severity
     */
    public Severity calculateSeverity(int totalScore) {
        if (totalScore >= THRESHOLD_CRITICAL) {
            return Severity.CRITICAL;
        } else if (totalScore >= THRESHOLD_HIGH) {
            return Severity.HIGH;
        } else if (totalScore >= THRESHOLD_MEDIUM) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }

    /**
     * Returns the risk score for failed login alerts.
     *
     * @param failedCount number of failed attempts from one IP
     * @return the total score for this authentication alert
     */
    public int scoreAuthAlert(int failedCount) {
        int score = failedCount * SCORE_FAILED_LOGIN;
        if (failedCount >= 3) {
            score += SCORE_BRUTE_FORCE_BONUS;
        }
        return score;
    }

    /**
     * Returns the risk score for firewall DROP alerts.
     *
     * @param dropCount number of DROP events from one IP
     * @return the total score for this firewall alert
     */
    public int scoreFirewallAlert(int dropCount) {
        return dropCount * SCORE_FIREWALL_DROP;
    }
}
