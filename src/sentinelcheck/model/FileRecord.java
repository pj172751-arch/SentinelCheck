package sentinelcheck.model;

import java.time.LocalDateTime;

/**
 * Represents the integrity state of a single monitored file.
 *
 * Captures the file path, current and previous SHA-256 hashes,
 * the detected status (UNCHANGED / MODIFIED / MISSING / NEW),
 * and the timestamp when the check was performed.
 */
public class FileRecord {

    private final String filePath;
    private final String oldHash;
    private final String newHash;
    private final FileStatus status;
    private final LocalDateTime timestamp;

    public FileRecord(String filePath, String oldHash, String newHash,
                      FileStatus status, LocalDateTime timestamp) {
        this.filePath = filePath;
        this.oldHash = oldHash;
        this.newHash = newHash;
        this.status = status;
        this.timestamp = timestamp;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getOldHash() {
        return oldHash;
    }

    public String getNewHash() {
        return newHash;
    }

    public FileStatus getStatus() {
        return status;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

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
