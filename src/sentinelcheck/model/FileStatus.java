package sentinelcheck.model;

/**
 * Represents the integrity status of a monitored file.
 *
 * UNCHANGED — file hash matches the baseline
 * MODIFIED  — file exists but hash differs from baseline
 * MISSING   — file was in baseline but no longer exists on disk
 * NEW       — file exists on disk but was not in the baseline
 */
public enum FileStatus {
    UNCHANGED,
    MODIFIED,
    MISSING,
    NEW
}
