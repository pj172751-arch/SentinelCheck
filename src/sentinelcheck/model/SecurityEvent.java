package sentinelcheck.model;

import java.time.LocalDateTime;

/**
 * Universal security event used across all monitoring modules.
 * Logged in data/events.csv and loaded into EventHistory.
 */
public class SecurityEvent {

    private final LocalDateTime timestamp;
    private final EventType eventType;
    private final String sourceIP; // "LOCAL" or IP address
    private final String destinationIP; // optional
    private final String username; // optional
    private final String filePath; // optional
    private final String fileHash; // optional
    private final int port; // optional, dest port
    private final String protocol; // optional
    private final String details;
    private final String authorizationContext; // e.g. "UNAUTHORIZED" or "MAINTENANCE"

    /**
     * Comprehensive constructor (11 parameters).
     */
    public SecurityEvent(LocalDateTime timestamp, EventType eventType, String sourceIP, String destinationIP,
                         String username, String filePath, String fileHash,
                         int port, String protocol, String details, String authorizationContext) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.sourceIP = sourceIP == null || sourceIP.isEmpty() ? "LOCAL" : sourceIP;
        this.destinationIP = destinationIP == null ? "" : destinationIP;
        this.username = username == null ? "" : username;
        this.filePath = filePath == null ? "" : filePath;
        this.fileHash = fileHash == null ? "" : fileHash;
        this.port = port;
        this.protocol = protocol == null ? "" : protocol;
        this.details = details == null ? "" : details.replace("|", " ");
        this.authorizationContext = authorizationContext == null || authorizationContext.isEmpty() 
                                    ? "UNAUTHORIZED" : authorizationContext;
    }

    /**
     * Constructor without destinationIP (10 parameters) - used in Main.java and FileMonitor.java.
     */
    public SecurityEvent(LocalDateTime timestamp, EventType eventType, String sourceIP,
                         String username, String filePath, String fileHash,
                         int port, String protocol, String details, String authorizationContext) {
        this(timestamp, eventType, sourceIP, "", username, filePath, fileHash, port, protocol, details, authorizationContext);
    }

    /**
     * Simplified constructor for file events (6 parameters).
     */
    public SecurityEvent(LocalDateTime timestamp, EventType eventType, String filePath, 
                         String fileHash, String details, String authorizationContext) {
        this(timestamp, eventType, "LOCAL", "", "", filePath, fileHash, 0, "", details, authorizationContext);
    }

    /**
     * Simplified constructor for authentication events (4 parameters).
     */
    public SecurityEvent(LocalDateTime timestamp, EventType eventType, String sourceIP, String details) {
        this(timestamp, eventType, sourceIP, "", "", "", "", 0, "", details, "UNAUTHORIZED");
    }

    /**
     * Simplified constructor for auth events with username (5 parameters).
     */
    public SecurityEvent(LocalDateTime timestamp, EventType eventType, String sourceIP, 
                         String username, String details) {
        this(timestamp, eventType, sourceIP, "", username, "", "", 0, "", details, "UNAUTHORIZED");
    }

    /**
     * Simplified constructor for firewall events (7 parameters).
     */
    public SecurityEvent(LocalDateTime timestamp, EventType eventType, String sourceIP, 
                         String destinationIP, int port, String protocol, String details) {
        this(timestamp, eventType, sourceIP, destinationIP, "", "", "", port, protocol, details, "UNAUTHORIZED");
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

    public String getUsername() {
        return username;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getFileHash() {
        return fileHash;
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

    public String getAuthorizationContext() {
        return authorizationContext;
    }

    /**
     * Converts the event to a pipeline-parseable CSV line.
     * Format: timestamp|eventType|sourceIP|destinationIP|username|filePath|fileHash|port|protocol|details|authContext
     */
    public String toCSVLine() {
        return String.join("|",
                timestamp.toString(),
                eventType.name(),
                sourceIP,
                destinationIP,
                username,
                filePath,
                fileHash,
                String.valueOf(port),
                protocol,
                details,
                authorizationContext
        );
    }

    /**
     * Parses a SecurityEvent from a CSV line.
     */
    public static SecurityEvent fromCSVLine(String line) {
        String[] parts = line.split("\\|", -1);
        if (parts.length < 11) {
            throw new IllegalArgumentException("Malformed security event line: " + line);
        }
        LocalDateTime timestamp = LocalDateTime.parse(parts[0]);
        EventType eventType = EventType.valueOf(parts[1]);
        String sourceIP = parts[2];
        String destinationIP = parts[3];
        String username = parts[4];
        String filePath = parts[5];
        String fileHash = parts[6];
        int port = Integer.parseInt(parts[7]);
        String protocol = parts[8];
        String details = parts[9];
        String authorizationContext = parts[10];

        return new SecurityEvent(timestamp, eventType, sourceIP, destinationIP, username, filePath, fileHash,
                port, protocol, details, authorizationContext);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        SecurityEvent other = (SecurityEvent) obj;
        return timestamp.equals(other.timestamp) &&
               eventType == other.eventType &&
               sourceIP.equals(other.sourceIP) &&
               details.equals(other.details);
    }

    @Override
    public int hashCode() {
        int result = timestamp.hashCode();
        result = 31 * result + eventType.hashCode();
        result = 31 * result + sourceIP.hashCode();
        result = 31 * result + details.hashCode();
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(timestamp).append("] ");
        sb.append(eventType);

        if (!sourceIP.equals("LOCAL")) {
            sb.append(" | Source: ").append(sourceIP);
        }
        if (!destinationIP.isEmpty()) {
            sb.append(" | Dest: ").append(destinationIP);
        }
        if (!username.isEmpty()) {
            sb.append(" | User: ").append(username);
        }
        if (!filePath.isEmpty()) {
            sb.append(" | File: ").append(filePath);
        }
        if (port > 0) {
            sb.append(" | Port: ").append(port).append("/").append(protocol);
        }
        if (!details.isEmpty()) {
            sb.append(" | ").append(details);
        }
        if (!authorizationContext.equals("UNAUTHORIZED")) {
            sb.append(" (").append(authorizationContext).append(")");
        }

        return sb.toString();
    }
}
