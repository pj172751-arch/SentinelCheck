package sentinelcheck.model;

/**
 * Classifies each security event parsed from logs or detected by modules.
 */
public enum EventType {
    FAILED_LOGIN,
    SUCCESSFUL_LOGIN,
    FIREWALL_DROP,
    FIREWALL_ACCEPT,
    FILE_MODIFIED,
    FILE_MISSING,
    FILE_NEW,
    BASELINE_TAMPERED
}
