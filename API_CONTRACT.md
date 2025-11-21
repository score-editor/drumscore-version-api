# DrumScore Version API - API Contract

## Base URL
```
https://version.drumscore.scot
```

## Authentication
Analytics requests require HMAC-SHA256 signature validation.

---

## Endpoint 1: Version Check

### Request
```http
GET /api/version
Headers:
  X-Client-ID: string (optional, recommended)
    - SHA-256 hash of machine identifier
    - 64 character hex string
    - Example: "a3f5b8c2d1e4f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
```

### Response
```http
200 OK
Content-Type: application/json

{
  "version": "3.4.0",
  "build": "2025.11.20.1",
  "releaseDate": "2025-11-20T10:00:00Z",
  "downloadUrl": "https://www.drummingondemand.com/drum-score-editor",
  "minSupportedVersion": "3.3.0",
  "releaseNotes": "Bug fixes and performance improvements"
}
```

### Error Responses
```http
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
- **Analytics Batch**: 12 requests/hour per client ID (one every 5 minutes), burst 5
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
import java.security.MessageDigest;
import java.net.NetworkInterface;
import java.util.Enumeration;

private static String generateClientId() throws Exception {
    // Get stable machine identifiers
    StringBuilder machineInfo = new StringBuilder();
    
    // MAC address (first non-loopback)
    Enumeration<NetworkInterface> networks = NetworkInterface.getNetworkInterfaces();
    while (networks.hasMoreElements()) {
        NetworkInterface network = networks.nextElement();
        if (!network.isLoopback() && network.getHardwareAddress() != null) {
            byte[] mac = network.getHardwareAddress();
            for (byte b : mac) {
                machineInfo.append(String.format("%02X", b));
            }
            break;
        }
    }
    
    // OS info
    machineInfo.append(System.getProperty("os.name"));
    machineInfo.append(System.getProperty("os.version"));
    machineInfo.append(System.getProperty("user.home")); // path, not username
    
    // Hash with SHA-256
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(machineInfo.toString().getBytes("UTF-8"));
    
    // Convert to hex string
    StringBuilder hexString = new StringBuilder();
    for (byte b : hash) {
        hexString.append(String.format("%02x", b));
    }
    
    return hexString.toString();
}
```

---

## Testing

### Test Version Check
```bash
curl -H "X-Client-ID: abc123..." \
  https://version.drumscore.scot/api/version
```

### Test Analytics Batch
```bash
# Generate signature first with your secret
PAYLOAD='{"clientId":"abc123...","appVersion":"3.4.0","os":{"family":"macOS","version":"14.1","arch":"aarch64"},"sessionStart":1700567890000,"events":[{"timestamp":1700567900000,"eventType":"feature_used","featureName":"export_pdf","metadata":{}}]}'

SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "your-secret-here" -binary | base64)

curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Client-ID: abc123..." \
  -H "X-Signature: $SIGNATURE" \
  -d "$PAYLOAD" \
  https://version.drumscore.scot/api/analytics/batch
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
