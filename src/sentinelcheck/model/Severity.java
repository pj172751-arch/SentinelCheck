package sentinelcheck.model;

/**
 * Risk severity levels assigned by the scoring engine.
 *
 * Thresholds (cumulative risk score):
 *   LOW      —  0–29 points
 *   MEDIUM   — 30–59 points
 *   HIGH     — 60–89 points
 *   CRITICAL — 90+  points
 */
public enum Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
