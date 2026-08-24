package sentinelcheck.integrity;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Manages the SHA-256 hash baseline for a monitored directory.
 *
 * Baseline file format (properties-style, inspired by
 * karsany/file-integrity-check PropertiesFileIntegrityDatabase):
 *
 *   # SentinelCheck Baseline
 *   # Created: 2026-08-24T21:30:00
 *   # Directory: monitored
 *   # Files: 5
 *   config.txt=abc123...
 *   users.csv=7f92...
 *
 * The file uses '=' as the delimiter between relative file path
 * and its SHA-256 hash. Comment lines start with '#'.
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
     *
     * @param directory    the folder to scan
     * @param baselineFile where to write the baseline
     * @return the number of files hashed
     * @throws IOException if directory cannot be read or baseline cannot be written
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

        return hashes.size();
    }

    /**
     * Loads a previously saved baseline from disk.
     *
     * @param baselineFile the baseline file to read
     * @return map of relative file path → SHA-256 hash
     * @throws IOException if the file cannot be read
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
}
