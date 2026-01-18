# DrumScore Version API - API Contract

## Base URL
```
https://support.drumscore.scot
```

## Authentication
Analytics requests require HMAC-SHA256 signature validation.

---

## Endpoint 1: Version Check

### Request
```http
GET /api/version?platform={platform}&arch={arch}
Headers:
  X-Client-ID: string (optional, recommended)
    - SHA-256 hash of machine identifier
    - 64 character hex string
    - Example: "a3f5b8c2d1e4f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
  X-App-Version: string (optional, recommended)
    - Current installed app version
    - Semantic version format (e.g., "3.3.0", "3.4.0")
    - Used for version distribution analytics

Query Parameters:
  platform: string (required)
    - Must be one of: "windows", "macos", "linux"
  arch: string (required)
    - Must be one of: "x86_64", "aarch64"
```

### Response
```http
200 OK
Content-Type: application/json

{
  "version": "3.4.0",
  "build": "2025.11.23.4",
  "releaseDate": "2025-11-23T10:00:00Z",
  "downloadUrl": "https://drumscore.scot",
  "minSupportedVersion": "3.3.0",
  "releaseNotes": "macOS Apple Silicon release"
}
```

### Error Responses
```http
400 Bad Request
{
  "error": "Missing platform parameter",
  "details": "Please specify platform: ?platform=windows, ?platform=macos, or ?platform=linux"
}

400 Bad Request
{
  "error": "Invalid platform",
  "details": "Platform must be: windows, macos, or linux"
}

400 Bad Request
{
  "error": "Missing arch parameter",
  "details": "Please specify arch: ?arch=x86_64 or ?arch=aarch64"
}

400 Bad Request
{
  "error": "Invalid architecture",
  "details": "Architecture must be: x86_64 or aarch64"
}

429 Too Many Requests - Rate limit exceeded (60 requests/minute per IP)
500 Internal Server Error - Server error
```

---

## Endpoint 2: Analytics Batch

### Request
```http
POST /api/analytics/batch
Headers:
  Content-Type: application/json
  X-Client-ID: string (required)
    - Same format as version check
  X-Signature: string (required)
    - HMAC-SHA256 of request body using shared secret
    - Base64 encoded

Body:
{
  "clientId": "a3f5b8c2d1e4f6a7b8c9d0e1f2a3b4c5...",
  "appVersion": "3.4.0",
  "os": {
    "family": "Windows",
    "version": "11",
    "arch": "x86_64"
  },
  "sessionStart": 1700567890000,
  "events": [
    {
      "timestamp": 1700567900000,
      "eventType": "feature_used",
      "featureName": "export_pdf",
      "metadata": {
        "duration_ms": 1234,
        "file_size_bytes": 56789
      }
    }
  ]
}
```

### Field Specifications

**Top Level:**
- `clientId`: string, required, 64 char hex (SHA-256 hash)
- `appVersion`: string, required, semantic version (e.g., "3.4.0")
- `os`: object, required
- `sessionStart`: integer, required, Unix timestamp (ms) when app session started
- `events`: array, required, 1-1000 events per batch

**OS Object:**
- `family`: string, required, one of: "Windows", "macOS", "Linux"
- `version`: string, required, OS version
- `arch`: string, required, one of: "x86_64", "aarch64", "x86"

**Event Object:**
- `timestamp`: integer, required, Unix timestamp (ms) when event occurred
- `eventType`: string, required, one of: "feature_used", "session_start", "session_end", "error"
- `featureName`: string, required if eventType is "feature_used"
- `metadata`: object, optional, arbitrary key-value pairs

### Response
```http
202 Accepted
Content-Type: application/json

{
  "status": "accepted",
  "eventsReceived": 2
}
```

### Error Responses
```http
400 Bad Request
{
  "error": "Invalid request format",
  "details": "Missing required field: clientId"
}

401 Unauthorized
{
  "error": "Invalid signature"
}

429 Too Many Requests
{
  "error": "Rate limit exceeded"
}

413 Payload Too Large
{
  "error": "Batch too large, maximum 1000 events"
}
```

---

## Endpoint 3: Health Check

### Request
```http
GET /health
```

### Response
```http
200 OK
Body: OK
```

---

## Standard Feature Names

Use these standardized feature names for consistency:

**File Operations:**
- `file_new`
- `file_open`
- `file_save`
- `file_export_pdf`
- `file_export_midi`
- `file_print`

**Editing:**
- `notation_add_note`
- `notation_delete_note`
- `notation_edit_note`
- `measure_add`
- `measure_delete`
- `tempo_change`
- `time_signature_change`

**Playback:**
- `playback_start`
- `playback_stop`
- `playback_pause`

**View:**
- `zoom_in`
- `zoom_out`
- `view_fullscreen`

**Tools:**
- `metronome_toggle`
- `tuner_open`

---

## Rate Limits

- **Version Check**: 60 requests/minute per IP, burst 20
- **Analytics Batch**: 1 request/minute per client ID, burst 5
- **Health Check**: No limit

---

## Request Signing

### Generate Signature (Java Example)

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

private static String signRequest(String payload, String secret) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256");
    mac.init(secretKey);
    byte[] signature = mac.doFinal(payload.getBytes("UTF-8"));
    return Base64.getEncoder().encodeToString(signature);
}

// Usage:
String jsonPayload = gson.toJson(batch);
String signature = signRequest(jsonPayload, "your-secret-here");

HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create(ANALYTICS_URL))
    .header("Content-Type", "application/json")
    .header("X-Client-ID", clientId)
    .header("X-Signature", signature)
    .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
    .build();
```

---

## Client Implementation Guidelines

### Platform Detection

```java
private static String getPlatform() {
    String osName = System.getProperty("os.name").toLowerCase();
    
    if (osName.contains("win")) {
        return "windows";
    } else if (osName.contains("mac")) {
        return "macos";
    } else if (osName.contains("linux")) {
        return "linux";
    } else {
        // Fallback - default to linux for other Unix-like systems
        return "linux";
    }
}

private static String getArch() {
    String osArch = System.getProperty("os.arch").toLowerCase();
    
    // Normalize architecture names
    if (osArch.equals("amd64") || osArch.equals("x86_64") || osArch.equals("x64")) {
        return "x86_64";
    } else if (osArch.equals("aarch64") || osArch.equals("arm64")) {
        return "aarch64";
    } else {
        // Fallback to x86_64 for unknown architectures
        return "x86_64";
    }
}
```

### Version Check Example

```java
public VersionInfo checkVersion(String currentAppVersion) throws Exception {
    String platform = getPlatform();
    String arch = getArch();
    String clientId = generateClientId();

    String url = "https://support.drumscore.scot/api/version" +
                 "?platform=" + platform +
                 "&arch=" + arch;

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .header("X-Client-ID", clientId)
        .header("X-App-Version", currentAppVersion)
        .timeout(Duration.ofSeconds(10))
        .GET()
        .build();
        
    HttpResponse<String> response = httpClient.send(request, 
        HttpResponse.BodyHandlers.ofString());
        
    if (response.statusCode() == 200) {
        return gson.fromJson(response.body(), VersionInfo.class);
    } else if (response.statusCode() == 400) {
        throw new IOException("Invalid platform or architecture parameter");
    } else if (response.statusCode() == 429) {
        throw new IOException("Rate limited - try again later");
    } else {
        throw new IOException("Failed to check version: " + response.statusCode());
    }
}
```

### Batching Strategy
- Collect events in memory queue
- Send batch every 5 minutes
- OR send when queue reaches 100 events (whichever first)
- Send on app shutdown (important!)
- Send on version check (piggyback opportunity)

### Error Handling
- Analytics should NEVER crash the app
- Network failures should be logged but silent to user
- Failed batches can be discarded (don't retry indefinitely)
- If server returns 429, back off (double interval up to 30 min)

### Privacy
- NO usernames, emails, or PII
- Client ID should be anonymous but stable per machine
- IP address captured server-side for country only (not stored)

### Client ID Generation

```java
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Enumeration;

public class MachineIdGenerator {
    
    /**
     * Generates a stable, anonymous machine identifier using OS-specific facilities.
     * NO PII - uses system machine IDs, not user information.
     */
    public static String generateClientId() {
        try {
            String machineId = getMachineId();
            
            // Hash with SHA-256 to create 64-character hex string
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(machineId.getBytes("UTF-8"));
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate client ID", e);
        }
    }
    
    /**
     * Gets OS-specific machine identifier.
     * Uses actual system machine IDs, not user info or network adapters.
     */
    private static String getMachineId() throws Exception {
        String os = System.getProperty("os.name").toLowerCase();
        
        if (os.contains("win")) {
            return getWindowsMachineId();
        } else if (os.contains("mac")) {
            return getMacMachineId();
        } else if (os.contains("linux")) {
            return getLinuxMachineId();
        } else {
            // Fallback for other Unix-like systems
            return getGenericMachineId();
        }
    }
    
    /**
     * Windows: Read MachineGuid from registry
     */
    private static String getWindowsMachineId() throws Exception {
        Process process = Runtime.getRuntime().exec(
            "reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid"
        );
        
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("MachineGuid")) {
                    String[] parts = line.trim().split("\\s+");
                    return parts[parts.length - 1];
                }
            }
        }
        
        throw new Exception("Could not read Windows MachineGuid");
    }
    
    /**
     * macOS: Read IOPlatformUUID (hardware UUID)
     */
    private static String getMacMachineId() throws Exception {
        Process process = Runtime.getRuntime().exec(
            "ioreg -rd1 -c IOPlatformExpertDevice"
        );
        
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("IOPlatformUUID")) {
                    // Format: "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
                    int start = line.indexOf("\"", line.indexOf("=")) + 1;
                    int end = line.lastIndexOf("\"");
                    return line.substring(start, end);
                }
            }
        }
        
        throw new Exception("Could not read macOS IOPlatformUUID");
    }
    
    /**
     * Linux: Read /etc/machine-id (systemd machine ID)
     */
    private static String getLinuxMachineId() throws Exception {
        File machineIdFile = new File("/etc/machine-id");
        if (!machineIdFile.exists()) {
            // Fallback to /var/lib/dbus/machine-id
            machineIdFile = new File("/var/lib/dbus/machine-id");
        }
        
        if (machineIdFile.exists()) {
            return new String(Files.readAllBytes(machineIdFile.toPath())).trim();
        }
        
        throw new Exception("Could not read Linux machine-id");
    }
    
    /**
     * Generic fallback: Use MAC address + system properties
     */
    private static String getGenericMachineId() throws Exception {
        StringBuilder sb = new StringBuilder();
        
        // System properties (NO PII)
        sb.append(System.getProperty("os.name"));
        sb.append(System.getProperty("os.version"));
        sb.append(System.getProperty("os.arch"));
        
        // MAC address as fallback identifier
        Enumeration<NetworkInterface> networks = NetworkInterface.getNetworkInterfaces();
        while (networks.hasMoreElements()) {
            NetworkInterface network = networks.nextElement();
            if (!network.isLoopback() && network.getHardwareAddress() != null) {
                byte[] mac = network.getHardwareAddress();
                for (byte b : mac) {
                    sb.append(String.format("%02X", b));
                }
                break; // Use first non-loopback MAC
            }
        }
        
        if (sb.length() == 0) {
            throw new Exception("Could not determine machine ID");
        }
        
        return sb.toString();
    }
}
```

**What's used (NOT PII):**
- **Windows**: `MachineGuid` from registry - unique per Windows installation
- **macOS**: `IOPlatformUUID` - hardware UUID from the platform
- **Linux**: `/etc/machine-id` - systemd machine ID, unique per installation
- **Fallback**: MAC address + OS properties (for other Unix systems)

**What's excluded (PII):**
- ❌ Username
- ❌ User home path
- ❌ User email
- ❌ Any user-identifiable information

**Properties:**
- ✅ Stable across reboots
- ✅ Unique per machine
- ✅ Works offline
- ✅ Privacy-preserving
- ✅ GDPR compliant

---

## Testing

### Generate a Valid Test Client ID

```bash
# Generate a valid 64-character hex client ID for testing
TEST_CLIENT_ID=$(echo -n "test-client-$(date +%s)" | sha256sum | awk '{print $1}')
echo "Test Client ID: $TEST_CLIENT_ID"
```

### Test Version Check
```bash
# With valid client ID and app version (will be logged to analytics)
curl -H "X-Client-ID: $TEST_CLIENT_ID" \
     -H "X-App-Version: 3.3.0" \
  "https://support.drumscore.scot/api/version?platform=macos&arch=aarch64"

# Test each platform and architecture combination
curl "https://support.drumscore.scot/api/version?platform=windows&arch=x86_64"
curl "https://support.drumscore.scot/api/version?platform=windows&arch=aarch64"
curl "https://support.drumscore.scot/api/version?platform=macos&arch=x86_64"
curl "https://support.drumscore.scot/api/version?platform=macos&arch=aarch64"
curl "https://support.drumscore.scot/api/version?platform=linux&arch=x86_64"
curl "https://support.drumscore.scot/api/version?platform=linux&arch=aarch64"

# Missing parameters (will return 400 error)
curl "https://support.drumscore.scot/api/version?platform=macos"
curl "https://support.drumscore.scot/api/version?arch=aarch64"
curl "https://support.drumscore.scot/api/version"
```

**Note:** Invalid client IDs are silently ignored - the API will still return version info, but won't log the request to analytics.

### Test Analytics Batch
```bash
# First generate a valid client ID and secret
TEST_CLIENT_ID=$(echo -n "test-client-$(date +%s)" | sha256sum | awk '{print $1}')
SECRET="your-secret-here"  # Use the actual secret from your .env file

# Create test payload
PAYLOAD=$(cat <<EOF
{"clientId":"$TEST_CLIENT_ID","appVersion":"3.4.0","os":{"family":"Linux","version":"Ubuntu 22.04","arch":"x86_64"},"sessionStart":$(date +%s)000,"events":[{"timestamp":$(date +%s)000,"eventType":"feature_used","featureName":"export_pdf","metadata":{}}]}
EOF
)

# Generate signature
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64)

# Send request
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: $TEST_CLIENT_ID" \
  -H "X-Signature: $SIGNATURE" \
  -d "$PAYLOAD" \
  https://support.drumscore.scot/api/analytics/batch
```

---

## Validation Rules

The server performs these validations:

1. **Client ID**: Must be 64 character hex string
2. **App Version**: Must match semantic versioning (e.g., "3.4.0")
3. **OS Family**: Must be "Windows", "macOS", or "Linux"
4. **OS Architecture**: Must be "x86_64", "aarch64", or "x86"
5. **Event Type**: Must be "feature_used", "session_start", "session_end", or "error"
6. **Feature Name**: Must be in whitelist (see Standard Feature Names)
7. **Timestamps**: Must be within last 7 days and not in future
8. **Batch Size**: 1-1000 events
9. **Signature**: Must match HMAC-SHA256 of request body

Invalid requests will be rejected with 400 Bad Request and error details.
