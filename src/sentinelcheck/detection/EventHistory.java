package sentinelcheck.detection;

import sentinelcheck.model.SecurityEvent;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles in-memory and persistent storage of SecurityEvents using data/events.csv.
 */
public class EventHistory {

    private static final String EVENTS_FILE = "data/events.csv";
    private final List<SecurityEvent> events;

    public EventHistory() {
        this.events = new ArrayList<>();
        ensureDataDirExists();
    }

    private void ensureDataDirExists() {
        File dataDir = new File("data");
        if (!dataDir.exists()) {
            dataDir.mkdirs();
        }
    }

    public synchronized void addEvent(SecurityEvent event) {
        if (events.contains(event)) {
            return; // Skip duplicate events to prevent redundant logs
        }
        events.add(event);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(EVENTS_FILE, true))) {
            writer.write(event.toCSVLine());
            writer.newLine();
        } catch (IOException e) {
            System.err.println("  [ERROR] Failed to persist event: " + e.getMessage());
        }
    }

    /**
     * Loads all historical events from data/events.csv.
     */
    public synchronized void loadEvents() {
        events.clear();
        File file = new File(EVENTS_FILE);
        if (!file.exists()) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                try {
                    SecurityEvent event = SecurityEvent.fromCSVLine(line);
                    events.add(event);
                } catch (Exception e) {
                    System.err.println("  [WARN] Skipping malformed history event: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("  [ERROR] Failed to load event history: " + e.getMessage());
        }
    }

    public synchronized List<SecurityEvent> getEvents() {
        return new ArrayList<>(events);
    }

    /**
     * Counts the number of events recorded today.
     */
    public synchronized int getEventsTodayCount() {
        LocalDate today = LocalDate.now();
        int count = 0;
        for (SecurityEvent event : events) {
            if (event.getTimestamp().toLocalDate().equals(today)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Clears all in-memory events and deletes data/events.csv.
     */
    public synchronized void clear() {
        events.clear();
        File file = new File(EVENTS_FILE);
        if (file.exists()) {
            file.delete();
        }
    }
}
