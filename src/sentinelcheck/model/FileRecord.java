package sentinelcheck.model;

import java.time.LocalDateTime;

/**
 * Represents the integrity state of a single monitored file.
 */
public record FileRecord(
        String filePath,
        String oldHash,
        String newHash,
        FileStatus status,
        LocalDateTime timestamp
) {
    // Compatibility accessors for existing getX() callers
    public String getFilePath() { return filePath; }
    public String getOldHash() { return oldHash; }
    public String getNewHash() { return newHash; }
    public FileStatus getStatus() { return status; }
    public LocalDateTime getTimestamp() { return timestamp; }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(timestamp).append("] ");
        sb.append("File: ").append(filePath);
        sb.append(" | Status: ").append(status);

        if (status == FileStatus.MODIFIED) {
            sb.append("\n  Old SHA-256: ").append(oldHash);
            sb.append("\n  New SHA-256: ").append(newHash);
        } else if (status == FileStatus.NEW) {
            sb.append("\n  SHA-256: ").append(newHash);
        } else if (status == FileStatus.MISSING) {
            sb.append("\n  Last known SHA-256: ").append(oldHash);
        }

        return sb.toString();
    }
}
