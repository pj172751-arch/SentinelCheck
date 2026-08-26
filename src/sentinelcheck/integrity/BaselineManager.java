package sentinelcheck.integrity;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Manages the SHA-256 hash baseline for a monitored directory.
 * Includes baseline integrity verification via a sibling .sha256 checksum file.
 */
public class BaselineManager {

    private static final String COMMENT_PREFIX = "#";
    private static final String DELIMITER = "=";
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");

    private final HashCalculator hashCalculator;

    public BaselineManager() {
        this.hashCalculator = new HashCalculator();
    }

    /**
     * Creates a new baseline file by hashing every file in the directory.
     * Also writes a sibling .sha256 file containing the baseline's own hash.
     */
    public int createBaseline(File directory, File baselineFile) throws IOException {
        if (!directory.isDirectory()) {
            throw new IOException("Not a directory: " + directory.getAbsolutePath());
        }

        File[] files = directory.listFiles();
        if (files == null) {
            throw new IOException("Cannot list files in: " + directory.getAbsolutePath());
        }

        StringBuilder content = new StringBuilder();
        content.append(COMMENT_PREFIX).append(" SentinelCheck Baseline\n")
               .append(COMMENT_PREFIX).append(" Created: ").append(LocalDateTime.now().format(TIMESTAMP_FORMAT)).append("\n")
               .append(COMMENT_PREFIX).append(" Directory: ").append(directory.getAbsolutePath()).append("\n");

        int count = 0;
        StringBuilder entries = new StringBuilder();
        for (File file : files) {
            if (file.isFile()) {
                String name = file.getName();
                if (name.endsWith(".baseline") || name.endsWith(".sha256")) {
                    continue;
                }
                String hash = hashCalculator.calculateSHA256(file);
                entries.append(name).append(DELIMITER).append(hash).append("\n");
                count++;
            }
        }

        content.append(COMMENT_PREFIX).append(" Files: ").append(count).append("\n\n").append(entries);
        Files.writeString(baselineFile.toPath(), content.toString());
        writeBaselineChecksum(baselineFile);
        return count;
    }

    /**
     * Loads a previously saved baseline from disk.
     */
    public Map<String, String> loadBaseline(File baselineFile) throws IOException {
        Map<String, String> baseline = new LinkedHashMap<>();
        for (String line : Files.readAllLines(baselineFile.toPath())) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith(COMMENT_PREFIX)) {
                continue;
            }
            int idx = line.indexOf(DELIMITER);
            if (idx > 0) {
                baseline.put(line.substring(0, idx).trim(), line.substring(idx + 1).trim());
            }
        }
        return baseline;
    }

    /**
     * Computes the hash of the baseline file and saves it to a sibling .sha256 file.
     */
    public void writeBaselineChecksum(File baselineFile) throws IOException {
        String hash = hashCalculator.calculateSHA256(baselineFile);
        File shaFile = new File(baselineFile.getAbsolutePath() + ".sha256");
        Files.writeString(shaFile.toPath(), hash);
    }

    /**
     * Checks if the baseline file matches its recorded SHA-256 checksum.
     * Returns true if valid, false if tampered or if checksum is missing.
     */
    public boolean verifyBaselineIntegrity(File baselineFile) {
        if (!baselineFile.exists()) return false;
        File shaFile = new File(baselineFile.getAbsolutePath() + ".sha256");
        if (!shaFile.exists()) return false;

        try {
            String currentHash = hashCalculator.calculateSHA256(baselineFile);
            String expectedHash = Files.readString(shaFile.toPath()).trim();
            byte[] currentBytes = currentHash.toLowerCase().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] expectedBytes = expectedHash.toLowerCase().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            return java.security.MessageDigest.isEqual(currentBytes, expectedBytes);
        } catch (IOException e) {
            System.err.println("  [ERROR] Failed to verify baseline integrity: " + e.getMessage());
            return false;
        }
    }
}
