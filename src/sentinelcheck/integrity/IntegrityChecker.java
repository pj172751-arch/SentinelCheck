package sentinelcheck.integrity;

import sentinelcheck.model.FileRecord;
import sentinelcheck.model.FileStatus;

import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Compares the current state of a monitored directory against
 * a stored SHA-256 baseline and classifies each file as:
 *
 *   UNCHANGED — hash matches baseline
 *   MODIFIED  — file exists but hash differs
 *   MISSING   — in baseline but not on disk
 *   NEW       — on disk but not in baseline
 *
 * Inspired by karsany/file-integrity-check's listener-based
 * approach (newFile, hashChanged, hashUnchanged) and
 * Glavo/gchecksum's verify + update modes.
 */
public class IntegrityChecker {

    private final HashCalculator hashCalculator;
    private final BaselineManager baselineManager;

    public IntegrityChecker() {
        this.hashCalculator = new HashCalculator();
        this.baselineManager = new BaselineManager();
    }

    /**
     * Verifies the integrity of all files in the directory
     * against the stored baseline.
     *
     * @param directory    the monitored folder
     * @param baselineFile the baseline to compare against
     * @return list of FileRecord results for every file
     * @throws IOException if files cannot be read
     */
    public List<FileRecord> verifyIntegrity(File directory, File baselineFile)
            throws IOException {

        List<FileRecord> results = new ArrayList<>();
        LocalDateTime now = LocalDateTime.now();

        // Load the stored baseline
        Map<String, String> baseline = baselineManager.loadBaseline(baselineFile);

        // Track which baseline entries we've accounted for
        Set<String> accountedFiles = new HashSet<>();

        // Scan current directory
        File[] currentFiles = directory.listFiles();
        if (currentFiles != null) {
            for (File file : currentFiles) {
                if (!file.isFile()) {
                    continue;
                }

                String fileName = file.getName();
                if (fileName.endsWith(".baseline") || fileName.endsWith(".sha256")) {
                    continue;
                }
                String currentHash = hashCalculator.calculateSHA256(file);

                if (baseline.containsKey(fileName)) {
                    // File exists in baseline — check if hash matches
                    String baselineHash = baseline.get(fileName);
                    accountedFiles.add(fileName);

                    if (currentHash.equals(baselineHash)) {
                        results.add(new FileRecord(
                                fileName, baselineHash, currentHash,
                                FileStatus.UNCHANGED, now));
                    } else {
                        results.add(new FileRecord(
                                fileName, baselineHash, currentHash,
                                FileStatus.MODIFIED, now));
                    }
                } else {
                    // File not in baseline — it's new
                    results.add(new FileRecord(
                            fileName, "", currentHash,
                            FileStatus.NEW, now));
                }
            }
        }

        // Check for missing files (in baseline but not on disk)
        for (Map.Entry<String, String> entry : baseline.entrySet()) {
            if (!accountedFiles.contains(entry.getKey())) {
                results.add(new FileRecord(
                        entry.getKey(), entry.getValue(), "",
                        FileStatus.MISSING, now));
            }
        }

        return results;
    }
}
