package sentinelcheck.integrity;

import sentinelcheck.model.EventType;
import sentinelcheck.model.SecurityEvent;
import sentinelcheck.detection.EventHistory;
import sentinelcheck.detection.DetectionEngine;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Runs a background daemon thread that uses Java's WatchService
 * to monitor a directory for real-time file integrity changes.
 * Incorporates event debouncing and robust exception handling.
 */
public class FileMonitor implements Runnable {

    private final File directory;
    private final File baselineFile;
    private final EventHistory eventHistory;
    private final DetectionEngine detectionEngine;
    private final HashCalculator hashCalculator;
    private final BaselineManager baselineManager;

    private WatchService watchService;
    private Thread monitorThread;
    private volatile boolean running;
    private boolean maintenanceMode;

    public FileMonitor(File directory, File baselineFile, EventHistory eventHistory, DetectionEngine detectionEngine) {
        this.directory = directory;
        this.baselineFile = baselineFile;
        this.eventHistory = eventHistory;
        this.detectionEngine = detectionEngine;
        this.hashCalculator = new HashCalculator();
        this.baselineManager = new BaselineManager();
        this.maintenanceMode = false;
    }

    public synchronized void start() throws IOException {
        if (running) {
            return;
        }

        this.watchService = FileSystems.getDefault().newWatchService();
        Path path = directory.toPath();
        path.register(watchService, 
                StandardWatchEventKinds.ENTRY_CREATE, 
                StandardWatchEventKinds.ENTRY_MODIFY, 
                StandardWatchEventKinds.ENTRY_DELETE);

        this.running = true;
        this.monitorThread = new Thread(this, "SentinelCheck-FileMonitor");
        this.monitorThread.setDaemon(true);
        this.monitorThread.start();
    }

    public synchronized void stop() {
        if (!running) {
            return;
        }

        this.running = false;
        if (monitorThread != null) {
            monitorThread.interrupt();
        }
        if (watchService != null) {
            try {
                watchService.close();
            } catch (IOException e) {
                // Ignore close errors
            }
        }
    }

    public boolean isRunning() {
        return running;
    }

    public synchronized void setMaintenanceMode(boolean active) {
        this.maintenanceMode = active;
    }

    @Override
    public void run() {
        // Track the last modified times of files to prevent rapid duplicate event processing
        Map<String, Long> lastProcessedTimes = new HashMap<>();
        
        while (running) {
            try {
                WatchKey key = watchService.take(); // Blocks until an event occurs
                
                // Sleep for 500ms to debounce (coalesce multiple rapid filesystem events)
                Thread.sleep(500);
                
                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();
                    if (kind == StandardWatchEventKinds.OVERFLOW) {
                        continue;
                    }

                    @SuppressWarnings("unchecked")
                    WatchEvent<Path> ev = (WatchEvent<Path>) event;
                    Path filename = ev.context();
                    File file = new File(directory, filename.toString());
                    String name = filename.toString();

                    // Skip the baseline and temporary checksum files
                    if (name.endsWith(".baseline") || name.endsWith(".sha256") || name.startsWith(".")) {
                        continue;
                    }

                    // Extra layer of debouncing: throttle identical file events within 1 second of each other
                    long now = System.currentTimeMillis();
                    if (lastProcessedTimes.containsKey(name) && (now - lastProcessedTimes.get(name)) < 1000) {
                        continue;
                    }
                    lastProcessedTimes.put(name, now);

                    try {
                        processFileEvent(file, kind);
                    } catch (Exception e) {
                        // Catch and log all errors during processing to ensure the monitor NEVER dies
                        System.err.println("  [WARN] Exception while processing event for " + name + ": " + e.getMessage());
                    }
                }

                boolean valid = key.reset();
                if (!valid) {
                    break;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // Catch any other top-level exceptions so the thread keeps looping
                System.err.println("  [ERROR] WatchService loop encountered error: " + e.getMessage());
            }
        }
        running = false;
    }

    private void processFileEvent(File file, WatchEvent.Kind<?> kind) {
        String name = file.getName();
        LocalDateTime timestamp = LocalDateTime.now();
        String authContext = maintenanceMode ? "MAINTENANCE" : "UNAUTHORIZED";

        // Load current baseline to compare
        Map<String, String> baseline = new HashMap<>();
        if (baselineFile.exists()) {
            try {
                baseline = baselineManager.loadBaseline(baselineFile);
            } catch (IOException e) {
                // Squelch and default to empty
            }
        }

        if (kind == StandardWatchEventKinds.ENTRY_DELETE || !file.exists()) {
            // File was deleted
            if (baseline.containsKey(name)) {
                String oldHash = baseline.get(name);
                String details = "File deleted: " + name;
                SecurityEvent secEvent = new SecurityEvent(timestamp, EventType.FILE_MISSING, name, oldHash, details, authContext);
                eventHistory.addEvent(secEvent);
                detectionEngine.processNewEvent(secEvent);
            }
        } else if (kind == StandardWatchEventKinds.ENTRY_CREATE) {
            // File was created
            try {
                String newHash = hashCalculator.calculateSHA256(file);
                String details = "New file created: " + name;
                SecurityEvent secEvent = new SecurityEvent(timestamp, EventType.FILE_NEW, name, newHash, details, authContext);
                eventHistory.addEvent(secEvent);
                detectionEngine.processNewEvent(secEvent);
            } catch (IOException e) {
                // File disappeared or locked
                System.err.println("  [WARN] Failed to calculate hash for new file: " + name + " (" + e.getMessage() + ")");
            }
        } else if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
            // File was modified
            try {
                String newHash = hashCalculator.calculateSHA256(file);
                String oldHash = baseline.getOrDefault(name, "");

                if (oldHash.isEmpty()) {
                    // Treat as new if it wasn't baselined
                    String details = "New untracked file modified: " + name;
                    SecurityEvent secEvent = new SecurityEvent(timestamp, EventType.FILE_NEW, name, newHash, details, authContext);
                    eventHistory.addEvent(secEvent);
                    detectionEngine.processNewEvent(secEvent);
                } else if (!newHash.equals(oldHash)) {
                    // Content actually changed
                    String details = "File modified: " + name;
                    SecurityEvent secEvent = new SecurityEvent(timestamp, EventType.FILE_MODIFIED, name, newHash, details, authContext);
                    eventHistory.addEvent(secEvent);
                    detectionEngine.processNewEvent(secEvent);
                }
            } catch (IOException e) {
                // Ignore transient write-locks or file disappearances
                System.err.println("  [WARN] Failed to hash modified file (possibly locked or deleted): " + name);
            }
        }
    }
}
