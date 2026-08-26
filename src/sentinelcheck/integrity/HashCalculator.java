package sentinelcheck.integrity;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.HexFormat;

/**
 * Computes SHA-256 hash digests for files.
 *
 * Uses java.security.MessageDigest with a streaming approach
 * (8 KB buffer) so large files are hashed without loading
 * the entire content into memory.
 *
 * Reference: karsany/file-integrity-check SaltedSha256DigestStrategy
 * and Glavo/gchecksum create mode — simplified for this project.
 */
public class HashCalculator {

    private static final String ALGORITHM = "SHA-256";
    private static final int BUFFER_SIZE = 8192; // 8 KB read buffer

    /**
     * Calculates the SHA-256 hash of a file.
     *
     * @param file the file to hash
     * @return lowercase hexadecimal SHA-256 digest string
     * @throws IOException if the file cannot be read
     */
    public String calculateSHA256(File file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;

            try (FileInputStream fis = new FileInputStream(file)) {
                while ((bytesRead = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            return HexFormat.of().formatHex(digest.digest());

        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available in every JDK
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
