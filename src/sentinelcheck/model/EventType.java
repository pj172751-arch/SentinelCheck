package sentinelcheck.model;

/**
 * Classifies each security event parsed from logs or detected by modules.
 *
 * Authentication events:
 *   FAILED_LOGIN      — unsuccessful authentication attempt
 *   SUCCESSFUL_LOGIN  — successful authentication
 *
 * Firewall events:
 *   FIREWALL_DROP     — connection blocked by firewall rule
 *   FIREWALL_ACCEPT   — connection permitted (logged for context)
 *
 * File integrity events:
 *   FILE_MODIFIED     — monitored file content has changed
 *   FILE_MISSING      — monitored file has been deleted
 *   FILE_NEW          — unrecognized file appeared in monitored directory
 */
public enum EventType {
    FAILED_LOGIN,
    SUCCESSFUL_LOGIN,
    FIREWALL_DROP,
    FIREWALL_ACCEPT,
    FILE_MODIFIED,
    FILE_MISSING,
    FILE_NEW
}
