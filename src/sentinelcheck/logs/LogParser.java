package sentinelcheck.logs;

import sentinelcheck.model.EventType;
import sentinelcheck.model.SecurityEvent;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses CSV-formatted security log files into SecurityEvent objects.
 *
 * Supports two log formats:
 *   Authentication: yyyy-MM-dd HH:mm:ss,EVENT_TYPE,username,source_ip
 *   Firewall:       yyyy-MM-dd HH:mm:ss,EVENT_TYPE,source_ip,dest_ip,port,protocol
 */
public class LogParser {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Parses an authentication log file.
     */
    public List<SecurityEvent> parseAuthLog(File logFile) throws IOException {
        List<SecurityEvent> events = new ArrayList<>();
        int lineNumber = 0;

        for (String line : Files.readAllLines(logFile.toPath())) {
            lineNumber++;
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#") || line.toLowerCase().startsWith("timestamp")) {
                continue;
            }

            try {
                String[] parts = line.split(",");
                if (parts.length < 4) {
                    System.err.println("[WARN] Skipping malformed auth log line " + lineNumber + ": " + line);
                    continue;
                }

                LocalDateTime timestamp = LocalDateTime.parse(parts[0].trim(), TIMESTAMP_FORMAT);
                EventType eventType = parseEventType(parts[1].trim());
                String username = parts[2].trim();
                String sourceIP = parts[3].trim();

                events.add(new SecurityEvent(timestamp, eventType, sourceIP, username, "User: " + username));
            } catch (DateTimeParseException e) {
                System.err.println("[WARN] Invalid timestamp at line " + lineNumber + ": " + line);
            } catch (IllegalArgumentException e) {
                System.err.println("[WARN] Unknown event type at line " + lineNumber + ": " + line);
            }
        }
        return events;
    }

    /**
     * Parses a firewall log file.
     */
    public List<SecurityEvent> parseFirewallLog(File logFile) throws IOException {
        List<SecurityEvent> events = new ArrayList<>();
        int lineNumber = 0;

        for (String line : Files.readAllLines(logFile.toPath())) {
            lineNumber++;
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#") || line.toLowerCase().startsWith("timestamp")) {
                continue;
            }

            try {
                String[] parts = line.split(",");
                if (parts.length < 6) {
                    System.err.println("[WARN] Skipping malformed firewall log line " + lineNumber + ": " + line);
                    continue;
                }

                LocalDateTime timestamp = LocalDateTime.parse(parts[0].trim(), TIMESTAMP_FORMAT);
                EventType eventType = parseEventType(parts[1].trim());
                String sourceIP = parts[2].trim();
                String destIP = parts[3].trim();
                int port = Integer.parseInt(parts[4].trim());
                if (port < 0 || port > 65535) {
                    System.err.println("[WARN] Port out of range (0-65535) at line " + lineNumber + ": " + line);
                    continue;
                }
                String protocol = parts[5].trim();

                events.add(new SecurityEvent(timestamp, eventType, sourceIP, destIP, port, protocol, "Port " + port + "/" + protocol));
            } catch (DateTimeParseException e) {
                System.err.println("[WARN] Invalid timestamp at line " + lineNumber + ": " + line);
            } catch (NumberFormatException e) {
                System.err.println("[WARN] Invalid port number at line " + lineNumber + ": " + line);
            } catch (IllegalArgumentException e) {
                System.err.println("[WARN] Unknown event type at line " + lineNumber + ": " + line);
            }
        }
        return events;
    }

    /**
     * Converts a string event type from the log to an EventType enum.
     */
    private EventType parseEventType(String type) {
        switch (type.toUpperCase()) {
            case "FAILED_LOGIN":     return EventType.FAILED_LOGIN;
            case "SUCCESSFUL_LOGIN": return EventType.SUCCESSFUL_LOGIN;
            case "FIREWALL_DROP":    return EventType.FIREWALL_DROP;
            case "FIREWALL_ACCEPT":  return EventType.FIREWALL_ACCEPT;
            default:
                throw new IllegalArgumentException("Unknown event type: " + type);
        }
    }
}
