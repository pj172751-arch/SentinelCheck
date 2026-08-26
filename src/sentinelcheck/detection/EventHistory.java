package sentinelcheck.detection;

import sentinelcheck.model.SecurityEvent;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles in-memory and persistent storage of SecurityEvents using data/events.csv.
 */
public class EventHistory {

    private static final Path EVENTS_FILE = Path.of("data", "events.csv");
    private final List<SecurityEvent> events = new ArrayList<>();

    public EventHistory() {
        try {
            Files.createDirectories(EVENTS_FILE.getParent());
        } catch (IOException ignored) {}
    }

    public synchronized void addEvent(SecurityEvent event) {
        if (events.contains(event)) {
            return;
        }
        events.add(event);
        try {
            Files.writeString(EVENTS_FILE, event.toCSVLine() + System.lineSeparator(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("  [ERROR] Failed to persist event: " + e.getMessage());
        }
    }

    /**
     * Loads all historical events from data/events.csv.
     */
    public synchronized void loadEvents() {
        events.clear();
        if (!Files.exists(EVENTS_FILE)) return;

        try {
            for (String line : Files.readAllLines(EVENTS_FILE)) {
                line = line.trim();
                if (line.isEmpty()) continue;
                try {
                    events.add(SecurityEvent.fromCSVLine(line));
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
        try {
            Files.deleteIfExists(EVENTS_FILE);
        } catch (IOException ignored) {}
    }
}
