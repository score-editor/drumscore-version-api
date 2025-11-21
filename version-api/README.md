# Version API Service

Production-ready HTTPS API endpoint for app version checking with DDoS protection and rate limiting.

## Architecture

- **Nginx**: Reverse proxy with TLS termination, rate limiting, DDoS protection
- **Go API**: Lightweight version service
- **Certbot**: Automatic Let's Encrypt certificate management

## Features

- ✅ HTTPS with Let's Encrypt (auto-renewal)
- ✅ Rate limiting: 60 requests/minute per IP
- ✅ DDoS protection: connection limits, timeouts, request size limits
- ✅ Zero-downtime version updates (edit config file)
- ✅ Health check endpoint
- ✅ Containerized for easy migration to AWS/cloud

## Prerequisites

1. **DNS Configuration**
   - A record: `version.drumscore.scot` → your static IP
   - Wait 5-10 minutes for DNS propagation
   - Verify: `dig version.drumscore.scot` or `nslookup version.drumscore.scot`

2. **Router Port Forwarding**
   - Forward port 80 → Odroid M1 local IP
   - Forward port 443 → Odroid M1 local IP

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
   - Request a certificate for version.drumscore.scot
   - Use email: alan@drumscore.scot
   - Store certificates in `./letsencrypt/`

5. **Start the services**
   ```bash
   docker-compose up -d
   ```

6. **Verify it's working**
   ```bash
   # Check container status
   docker-compose ps
   
   # Check logs
   docker-compose logs -f
   
   # Test the endpoint
   curl https://version.drumscore.scot/api/version
   ```

## Directory Structure

```
version-api/
├── docker-compose.yml          # Container orchestration
├── setup-letsencrypt.sh        # Certificate setup script
├── config/
│   └── version.json            # ← Edit this to update version
├── nginx/
│   └── nginx.conf              # Nginx configuration
├── api/
│   ├── Dockerfile              # Go API container build
│   └── main.go                 # API server code
└── letsencrypt/                # Let's Encrypt certificates (created by setup)
```

## Usage

### Updating Version Information

Simply edit the config file - changes take effect within 30 seconds:

```bash
nano config/version.json
```

Example:
```json
{
  "version": "1.2.3",
  "build": "2025.11.25.1",
  "releaseDate": "2025-11-25T14:30:00Z",
  "downloadUrl": "https://drumscore.scot/downloads/app-1.2.3.apk",
  "minSupportedVersion": "1.0.0",
  "releaseNotes": "Bug fixes and performance improvements"
}
```

No container restart needed! The API checks for file changes every 30 seconds.

### API Endpoints

**Version Check**
```bash
GET https://version.drumscore.scot/api/version
```

Response:
```json
{
  "version": "1.0.0",
  "build": "2025.11.20.1",
  "releaseDate": "2025-11-20T10:00:00Z",
  "downloadUrl": "https://drumscore.scot/downloads/app-1.0.0.apk",
  "minSupportedVersion": "1.0.0",
  "releaseNotes": "Initial release"
}
```

**Health Check** (no rate limiting)
```bash
GET https://version.drumscore.scot/health
```

### Rate Limiting

- **Normal rate**: 60 requests/minute per IP
- **Burst allowance**: 20 requests (for legitimate spikes)
- **Exceeded**: HTTP 429 (Too Many Requests)

### Managing Services

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f api
docker-compose logs -f nginx

# Restart a service
docker-compose restart api

# Rebuild after code changes
docker-compose up -d --build
```

### Certificate Renewal

Certificates auto-renew via the certbot container. To manually trigger renewal:

```bash
docker-compose exec certbot certbot renew
docker-compose restart nginx
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
WorkingDirectory=/home/youruser/version-api
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
User=youruser

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

## Monitoring

### Check if services are running
```bash
docker-compose ps
```

### View resource usage
```bash
docker stats
```

### Test from your Flutter app
```dart
Future<Map<String, dynamic>> checkVersion() async {
  final response = await http.get(
    Uri.parse('https://version.drumscore.scot/api/version')
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
openssl s_client -connect version.drumscore.scot:443 -servername version.drumscore.scot

# Test with staging certificates first
# Edit setup-letsencrypt.sh and set STAGING=1
```

### Can't reach the API
1. Check DNS: `nslookup version.drumscore.scot`
2. Check port forwarding on router
3. Check containers: `docker-compose ps`
4. Check logs: `docker-compose logs -f nginx`

### Rate limiting too strict/loose
Edit `nginx/nginx.conf`:
```nginx
# Change rate (currently 60r/m = 60 requests per minute)
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=120r/m;
```
Then: `docker-compose restart nginx`

## Migration to AWS

This setup transfers directly to AWS:

1. **AWS ECS**: Upload Docker images to ECR, use same compose structure
2. **AWS EC2**: Copy entire directory, same commands
3. **AWS Lightsail**: Docker Compose works as-is
4. **Certificate**: Switch to AWS Certificate Manager or keep Let's Encrypt

The containerized approach ensures consistency across environments.

## Support

For issues or questions:
- Check logs: `docker-compose logs -f`
- Verify DNS: `dig version.drumscore.scot`
- Test locally: `curl https://version.drumscore.scot/api/version`
