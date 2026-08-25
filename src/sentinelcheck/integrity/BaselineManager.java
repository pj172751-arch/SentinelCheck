package sentinelcheck.integrity;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
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

        Map<String, String> hashes = new LinkedHashMap<>();
        File[] files = directory.listFiles();

        if (files == null) {
            throw new IOException("Cannot list files in: " + directory.getAbsolutePath());
        }

        for (File file : files) {
            if (file.isFile()) {
                String relativePath = file.getName();
                // Exclude any temporary or checksum files if needed
                if (relativePath.endsWith(".baseline") || relativePath.endsWith(".sha256")) {
                    continue;
                }
                String hash = hashCalculator.calculateSHA256(file);
                hashes.put(relativePath, hash);
            }
        }

        // Write baseline with metadata header
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(baselineFile))) {
            writer.write(COMMENT_PREFIX + " SentinelCheck Baseline");
            writer.newLine();
            writer.write(COMMENT_PREFIX + " Created: " +
                    LocalDateTime.now().format(TIMESTAMP_FORMAT));
            writer.newLine();
            writer.write(COMMENT_PREFIX + " Directory: " +
                    directory.getAbsolutePath());
            writer.newLine();
            writer.write(COMMENT_PREFIX + " Files: " + hashes.size());
            writer.newLine();
            writer.newLine();

            for (Map.Entry<String, String> entry : hashes.entrySet()) {
                writer.write(entry.getKey() + DELIMITER + entry.getValue());
                writer.newLine();
            }
        }

        // Write baseline checksum for integrity validation
        writeBaselineChecksum(baselineFile);

        return hashes.size();
    }

    /**
     * Loads a previously saved baseline from disk.
     */
    public Map<String, String> loadBaseline(File baselineFile) throws IOException {
        Map<String, String> baseline = new LinkedHashMap<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(baselineFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();

                // Skip empty lines and comments
                if (line.isEmpty() || line.startsWith(COMMENT_PREFIX)) {
                    continue;
                }

                int delimiterIndex = line.indexOf(DELIMITER);
                if (delimiterIndex > 0) {
                    String filePath = line.substring(0, delimiterIndex).trim();
                    String hash = line.substring(delimiterIndex + 1).trim();
                    baseline.put(filePath, hash);
                }
            }
        }

        return baseline;
    }

    /**
     * Computes the hash of the baseline file and saves it to a sibling .sha256 file.
     */
    public void writeBaselineChecksum(File baselineFile) throws IOException {
        String baselineHash = hashCalculator.calculateSHA256(baselineFile);
        File shaFile = new File(baselineFile.getAbsolutePath() + ".sha256");
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(shaFile))) {
            writer.write(baselineHash);
        }
    }

    /**
     * Checks if the baseline file matches its recorded SHA-256 checksum.
     * Returns true if valid, false if tampered or if checksum is missing.
     */
    public boolean verifyBaselineIntegrity(File baselineFile) {
        if (!baselineFile.exists()) {
            return false;
        }

        File shaFile = new File(baselineFile.getAbsolutePath() + ".sha256");
        if (!shaFile.exists()) {
            return false;
        }

        try {
            String currentHash = hashCalculator.calculateSHA256(baselineFile);
            String expectedHash = new String(Files.readAllBytes(shaFile.toPath())).trim();
            return currentHash.equalsIgnoreCase(expectedHash);
        } catch (IOException e) {
            System.err.println("  [ERROR] Failed to verify baseline integrity: " + e.getMessage());
            return false;
        }
    }
}
