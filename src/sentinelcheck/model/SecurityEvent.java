package sentinelcheck.model;

import java.time.LocalDateTime;

/**
 * Universal security event used across all monitoring modules.
 *
 * Every parsed log entry and every integrity detection is normalized
 * into a SecurityEvent so the correlation engine can compare them
 * using a common structure.
 */
public class SecurityEvent {

    private final LocalDateTime timestamp;
    private final EventType eventType;
    private final String sourceIP;
    private final String destinationIP;
    private final int port;
    private final String protocol;
    private final String details;

    /**
     * Full constructor for firewall events (all fields populated).
     */
    public SecurityEvent(LocalDateTime timestamp, EventType eventType,
                         String sourceIP, String destinationIP,
                         int port, String protocol, String details) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.port = port;
        this.protocol = protocol;
        this.details = details;
    }

    /**
     * Simplified constructor for authentication and file events
     * where destination IP, port, and protocol are not applicable.
     */
    public SecurityEvent(LocalDateTime timestamp, EventType eventType,
                         String sourceIP, String details) {
        this(timestamp, eventType, sourceIP, "", 0, "", details);
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public EventType getEventType() {
        return eventType;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public int getPort() {
        return port;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getDetails() {
        return details;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(timestamp).append("] ");
        sb.append(eventType);

        if (!sourceIP.isEmpty()) {
            sb.append(" | Source: ").append(sourceIP);
        }
        if (!destinationIP.isEmpty()) {
            sb.append(" | Dest: ").append(destinationIP);
        }
        if (port > 0) {
            sb.append(":").append(port);
        }
        if (!protocol.isEmpty()) {
            sb.append(" (").append(protocol).append(")");
        }
        if (!details.isEmpty()) {
            sb.append(" | ").append(details);
        }

        return sb.toString();
    }
}
