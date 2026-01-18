# Version API Service

Production-ready HTTPS API endpoint for app version checking with DDoS protection and rate limiting.

## Architecture

- **Nginx**: Reverse proxy with TLS termination, rate limiting, DDoS protection
  - Routes multiple subdomains to different backend services
  - Each service gets its own SSL certificate
- **Go API**: Lightweight version and analytics service (support.drumscore.scot)
- **Certbot**: Automatic Let's Encrypt certificate management for all domains
- **Multi-Service Ready**: Easy to add new services (license, auth, etc.) on separate subdomains

See [ADDING_SERVICES.md](ADDING_SERVICES.md) for how to add additional services.

## Features

- ✅ HTTPS with Let's Encrypt (auto-renewal)
- ✅ Cloudflare Authenticated Origin Pulls (blocks direct access to origin)
- ✅ Local network bypass for admin access via mDNS (droid1.local)
- ✅ Rate limiting: 60 requests/minute per IP for version checks
- ✅ Rate limiting: 1 request/minute per client for analytics batches
- ✅ DDoS protection: connection limits, timeouts, request size limits
- ✅ Zero-downtime version updates (edit config file)
- ✅ Analytics collection with SQLite database
- ✅ Request signing for analytics (HMAC-SHA256)
- ✅ Feature usage tracking
- ✅ Comprehensive payload validation
- ✅ Health check endpoint
- ✅ Containerized for easy migration to AWS/cloud

## Prerequisites

1. **DNS Configuration**
   - A record: `support.drumscore.scot` → your static IPv4
   - AAAA record (optional): `support.drumscore.scot` → your static IPv6 (if you have one)
   - Wait 5-10 minutes for DNS propagation
   - Verify: `dig support.drumscore.scot` or `nslookup support.drumscore.scot`

2. **Router Port Forwarding**
   - Forward port 80 → Odroid M1 local IP (IPv4)
   - Forward port 443 → Odroid M1 local IP (IPv4)
   - If using IPv6: Ensure firewall allows ports 80/443 (IPv6 typically doesn't need NAT)

3. **Docker Installation**
   ```bash
   # Install Docker
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo usermod -aG docker $USER
   
   # Install Docker Compose
   sudo apt-get update
   sudo apt-get install docker-compose-plugin
   
   # Log out and back in for group changes to take effect
   ```

## Installation

1. **Copy files to Odroid M1**
   ```bash
   # Transfer the version-api directory to your Odroid M1
   scp -r version-api/ user@odroid-m1-ip:~/
   ```

2. **SSH into Odroid M1**
   ```bash
   ssh user@odroid-m1-ip
   cd ~/version-api
   ```

3. **Make setup script executable**
   ```bash
   chmod +x setup-letsencrypt.sh
   ```

4. **Obtain Let's Encrypt Certificate**
   ```bash
   ./setup-letsencrypt.sh
   ```
   
   This will:
   - Request a certificate for support.drumscore.scot
   - Use email: alan@drumscore.scot
   - Store certificates in `./letsencrypt/`

5. **Configure Analytics Secret** (Optional but Recommended)
   ```bash
   # Generate a strong secret
   openssl rand -base64 32 > .analytics_secret
   
   # Create .env file
   echo "ANALYTICS_SECRET=$(cat .analytics_secret)" > .env
   
   # Keep this secret safe and use the same value in your client app
   ```
   
   **CRITICAL:** 
   - Back up this secret in a secure location (password manager, etc.)
   - You'll need it when implementing the Java client
   - Once clients are deployed, this secret becomes permanent
   - Never rotate without updating all clients simultaneously

6. **Start the services**
   ```bash
   docker compose up -d
   ```

7. **Verify it's working**
   ```bash
   # Check container status
   docker compose ps
   
   # Check logs
   docker compose logs -f
   
   # Test the endpoint
   curl https://support.drumscore.scot/api/version
   ```

## Directory Structure

```
version-api/
├── docker-compose.yml                    # Container orchestration
├── setup-letsencrypt.sh                  # Certificate setup script
├── .env.example                          # Example environment variables
├── API_CONTRACT.md                       # API documentation for client developers
├── config/
│   ├── version-multiplatform.example.json  # Template config (tracked in git)
│   └── version-multiplatform.json          # Server config (git-ignored, create from example)
├── nginx/
│   ├── nginx.conf                        # Nginx configuration
│   └── cloudflare-origin-pull-ca.pem     # Cloudflare mTLS certificate
├── api/
│   ├── Dockerfile                        # Go API container build
│   └── main.go                           # API server code
├── data/                                 # Created automatically
│   └── analytics.db                      # SQLite database (created on first run)
└── letsencrypt/                          # Let's Encrypt certificates (created by setup)
```

## Usage

### Initial Configuration

On first deployment, create the config file from the example:

```bash
cp config/version-multiplatform.example.json config/version-multiplatform.json
nano config/version-multiplatform.json
```

The actual config file is git-ignored to prevent conflicts when pulling updates.

### Updating Version Information

Simply edit the config file - changes take effect within 30 seconds:

```bash
nano config/version-multiplatform.json
```

Example (per-platform format):
```json
{
  "windows": {
    "version": "3.4.0",
    "build": "2025.11.23.1",
    "releaseDate": "2025-11-23T10:00:00Z",
    "downloadUrl": "https://drumscore.scot",
    "minSupportedVersion": "3.3.0",
    "releaseNotes": "Bug fixes and performance improvements"
  },
  "macos": {
    "version": "3.4.0",
    "build": "2025.11.23.2",
    "releaseDate": "2025-11-23T10:00:00Z",
    "downloadUrl": "https://drumscore.scot",
    "minSupportedVersion": "3.3.0",
    "releaseNotes": "Bug fixes and performance improvements"
  },
  "linux": {
    "version": "3.4.0",
    "build": "2025.11.23.3",
    "releaseDate": "2025-11-23T10:00:00Z",
    "downloadUrl": "https://drumscore.scot",
    "minSupportedVersion": "3.3.0",
    "releaseNotes": "Bug fixes and performance improvements"
  }
}
```

No container restart needed! The API checks for file changes every 30 seconds.

### API Endpoints

**Version Check**
```bash
GET https://support.drumscore.scot/api/version

# With client ID for analytics tracking
curl -H "X-Client-ID: your-client-id-hash" \
  https://support.drumscore.scot/api/version
```

Response:
```json
{
  "version": "1.0.0",
  "build": "2025.11.20.1",
  "releaseDate": "2025-11-20T10:00:00Z",
  "downloadUrl": "https://drumscore.scot",
  "minSupportedVersion": "1.0.0",
  "releaseNotes": "Initial release"
}
```

**Analytics Batch** (for app feature tracking)
```bash
POST https://support.drumscore.scot/api/analytics/batch
Headers:
  Content-Type: application/json
  X-Client-ID: client-id-hash
  X-Signature: hmac-sha256-signature

Body: See API_CONTRACT.md for detailed specification
```

**Health Check** (no rate limiting)
```bash
GET https://support.drumscore.scot/health
```

For complete API documentation and client implementation guide, see [API_CONTRACT.md](API_CONTRACT.md).

### Rate Limiting

- **Normal rate**: 60 requests/minute per IP
- **Burst allowance**: 20 requests (for legitimate spikes)
- **Exceeded**: HTTP 429 (Too Many Requests)

### Managing Services

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# View logs
docker compose logs -f

# View specific service logs
docker compose logs -f api
docker compose logs -f nginx

# Restart a service
docker compose restart api

# Rebuild after code changes
docker compose up -d --build
```

### Certificate Renewal

Certificates auto-renew via the certbot container. To manually trigger renewal:

```bash
docker compose exec certbot certbot renew
docker compose restart nginx
```

## Auto-Start on Boot

Create a systemd service:

```bash
sudo nano /etc/systemd/system/version-api.service
```

Add:
```ini
[Unit]
Description=Version API Service
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/alanwhite/drumscore-version-api
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
User=alanwhite

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable version-api
sudo systemctl start version-api
```

## Security Features

### Cloudflare Authenticated Origin Pulls

The server only accepts connections from Cloudflare, preventing direct access to the origin IP. This provides:
- Protection against DDoS attacks bypassing Cloudflare
- Ensures all traffic benefits from Cloudflare's security features
- mTLS verification of Cloudflare's identity

**Setup in Cloudflare Dashboard:**
1. Log into [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Select your domain
3. Go to **SSL/TLS** → **Origin Server**
4. Enable **Authenticated Origin Pulls**

### Local Network Access

For admin access to the analytics dashboard from your local network, the server accepts connections from local IPs (10.x.x.x, 172.16.x.x, 192.168.x.x) without requiring Cloudflare certificates.

Access via mDNS:
```
https://droid1.local/platforms
```

You'll see a certificate warning (the cert is for support.drumscore.scot) - accept it to proceed.

### DDoS Protection
- Connection limits: 10 concurrent per IP
- Request size limit: 1MB
- Timeout protection: 10s for slow connections
- Request rate limiting: 60/minute per IP

### HTTPS/TLS
- TLS 1.2 and 1.3 only
- Modern cipher suites
- HSTS enabled
- Certificate auto-renewal

### Headers
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: enabled

### Monitoring

### Check if services are running
```bash
docker compose ps
```

### View resource usage
```bash
docker stats
```

### Query Analytics Data

**Install sqlite3 on the Odroid (if not already installed):**
```bash
sudo apt-get install sqlite3
```

**Access the database directly from the host:**

```bash
# Connect to database
sqlite3 ~/drumscore-version-api/data/analytics.db
```

**Useful queries:**

**Unique users (last 30 days):**
```bash
sqlite3 ~/drumscore-version-api/data/analytics.db \
  "SELECT COUNT(DISTINCT client_id) as unique_users
   FROM version_checks
   WHERE timestamp > datetime('now', '-30 days');"
```

**Most used features:**
```bash
sqlite3 ~/drumscore-version-api/data/analytics.db \
  "SELECT feature_name, COUNT(*) as usage_count
   FROM analytics_events
   WHERE event_type = 'feature_used'
     AND timestamp > datetime('now', '-30 days')
   GROUP BY feature_name
   ORDER BY usage_count DESC
   LIMIT 10;"
```

**Platform breakdown:**
```bash
sqlite3 ~/drumscore-version-api/data/analytics.db \
  "SELECT os_family, COUNT(DISTINCT client_id) as users
   FROM analytics_events
   GROUP BY os_family;"
```

**Daily active users:**
```bash
sqlite3 ~/drumscore-version-api/data/analytics.db \
  "SELECT DATE(timestamp) as date, COUNT(DISTINCT client_id) as dau
   FROM analytics_events
   WHERE timestamp > datetime('now', '-30 days')
   GROUP BY DATE(timestamp)
   ORDER BY date DESC;"
```

### Test from your Flutter app
```dart
Future<Map<String, dynamic>> checkVersion() async {
  final response = await http.get(
    Uri.parse('https://support.drumscore.scot/api/version')
  );
  
  if (response.statusCode == 200) {
    return json.decode(response.body);
  } else if (response.statusCode == 429) {
    throw Exception('Rate limited - try again later');
  } else {
    throw Exception('Failed to check version');
  }
}
```

## Troubleshooting

### Certificate issues
```bash
# Check certificate validity
openssl s_client -connect support.drumscore.scot:443 -servername support.drumscore.scot

# Test with staging certificates first
# Edit setup-letsencrypt.sh and set STAGING=1
```

### Can't reach the API
1. Check DNS: `nslookup support.drumscore.scot`
2. Check port forwarding on router
3. Check containers: `docker compose ps`
4. Check logs: `docker compose logs -f nginx`

### Analytics not working
```bash
# Check database exists
ls -la ~/drumscore-version-api/data/

# Check database has tables (requires sqlite3 installed on host)
sqlite3 ~/drumscore-version-api/data/analytics.db ".tables"

# View recent events
sqlite3 ~/drumscore-version-api/data/analytics.db \
  "SELECT * FROM analytics_events ORDER BY timestamp DESC LIMIT 10;"

# Check for signature errors in logs
docker compose logs api | grep "Invalid signature"
```

### Rate limiting too strict/loose
Edit `nginx/nginx.conf`:
```nginx
# Change rate (currently 60r/m = 60 requests per minute)
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=120r/m;

# Analytics rate (currently 1r/m = one per minute)
limit_req_zone $http_x_client_id zone=analytics_limit:10m rate=24r/h;
```
Then: `docker compose restart nginx`

## Migration to AWS

This setup transfers directly to AWS:

1. **AWS ECS**: Upload Docker images to ECR, use same compose structure
2. **AWS EC2**: Copy entire directory, same commands
3. **AWS Lightsail**: Docker Compose works as-is
4. **Certificate**: Switch to AWS Certificate Manager or keep Let's Encrypt

The containerized approach ensures consistency across environments.

## Support

For issues or questions:
- Check logs: `docker compose logs -f`
- Verify DNS: `dig support.drumscore.scot`
- Test locally: `curl https://support.drumscore.scot/api/version`
- Review API contract: See [API_CONTRACT.md](API_CONTRACT.md) for client implementation
