# Adding New Services

This guide explains how to add new services to your multi-service architecture.

## Architecture Overview

Each service gets:
- Its own subdomain (e.g., `license.drumscore.scot`, `auth.drumscore.scot`)
- Its own Let's Encrypt certificate
- Its own backend container
- Routing through the shared nginx reverse proxy

```
Client → nginx (ports 80/443)
           ├─→ support.drumscore.scot → support-api:8080
           ├─→ license.drumscore.scot → license-service:8080
           └─→ auth.drumscore.scot → auth-service:8080
```

## Adding a New Service

### 1. DNS Configuration

Add DNS records for your new subdomain:

```bash
# Example: license.drumscore.scot
A record:    license.drumscore.scot → 51.148.180.134
AAAA record: license.drumscore.scot → 2a02:8010:6979:0::10
```

Wait 5-10 minutes for DNS propagation.

### 2. Obtain Let's Encrypt Certificate

```bash
cd ~/drumscore-version-api

# Stop nginx temporarily (needed for certbot standalone mode)
docker compose stop nginx

# Request certificate for new domain
docker run -it --rm \
  -v "$(pwd)/letsencrypt:/etc/letsencrypt" \
  -v "$(pwd)/letsencrypt/www:/var/www/certbot" \
  -p 80:80 \
  certbot/certbot certonly \
  --standalone \
  --preferred-challenges http \
  --email "alan@drumscore.scot" \
  --agree-tos \
  --no-eff-email \
  -d "license.drumscore.scot"

# Restart nginx
docker compose start nginx
```

### 3. Add Service to docker-compose.yml

```yaml
services:
  # ... existing services (nginx, certbot, api) ...
  
  license-service:
    build:
      context: ./license-service
      dockerfile: Dockerfile
    container_name: license-service
    restart: unless-stopped
    volumes:
      - ./license-service/data:/app/data
    environment:
      - DB_PATH=/app/data/licenses.db
    networks:
      - version-api-network
    expose:
      - "8080"
```

### 4. Add nginx Server Block

Edit `nginx/nginx.conf` and uncomment/modify the template at the bottom:

```nginx
# License Service
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name license.drumscore.scot;

    ssl_certificate /etc/letsencrypt/live/license.drumscore.scot/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/license.drumscore.scot/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    # Apply rate limiting
    limit_req zone=api_limit burst=20 nodelay;
    limit_conn conn_limit 10;
    
    location /api/ {
        proxy_pass http://license-service:8080;
        proxy_http_version 1.1;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
    
    location /health {
        proxy_pass http://license-service:8080/health;
        access_log off;
    }
    
    location / {
        return 404;
    }
}
```

### 5. Create Your Service

```bash
mkdir -p license-service
cd license-service

# Create your service code (Go, Java, Rust, whatever)
# Create Dockerfile
# Create any config files needed
```

### 6. Deploy

```bash
cd ~/drumscore-version-api

# Rebuild and restart
docker compose up -d --build

# Check all services are running
docker compose ps

# Test your new service
curl https://license.drumscore.scot/health
```

## Certificate Renewal

All certificates (support, license, auth, etc.) will auto-renew via the certbot container. No manual intervention needed.

To manually renew all certificates:

```bash
docker compose exec certbot certbot renew
docker compose restart nginx
```

## Service-Specific Rate Limiting

If a service needs different rate limits, create a new rate limit zone:

```nginx
# In nginx.conf http block
limit_req_zone $binary_remote_addr zone=license_limit:10m rate=30r/m;

# Then in the server block
location /api/ {
    limit_req zone=license_limit burst=10 nodelay;
    proxy_pass http://license-service:8080;
}
```

## Example Services

### License Validation Service
- **Domain**: `license.drumscore.scot`
- **Function**: Validate software licenses
- **Endpoints**: `/api/validate`, `/api/activate`

### Authentication Service
- **Domain**: `auth.drumscore.scot`
- **Function**: User authentication, passkeys
- **Endpoints**: `/api/login`, `/api/register`, `/api/passkey`

### Download Service
- **Domain**: `download.drumscore.scot`
- **Function**: Serve software downloads
- **Endpoints**: `/api/latest`, `/downloads/`

## Best Practices

1. **One subdomain per service** - easier to manage, clearer architecture
2. **Health check on all services** - nginx can use for upstream checks
3. **Consistent API patterns** - all use `/api/` prefix
4. **Service isolation** - each service has own container, database, config
5. **Shared nginx** - single reverse proxy for all services
6. **Individual certificates** - one cert per subdomain (not wildcard)

## Troubleshooting

### Certificate request fails
```bash
# Check DNS propagated
nslookup license.drumscore.scot

# Verify port 80 accessible
nc -zv your-ip 80

# Check nginx is stopped during certbot standalone mode
docker compose ps
```

### Service not accessible
```bash
# Check service is running
docker compose ps

# Check service logs
docker compose logs license-service

# Check nginx logs
docker compose logs nginx

# Test service directly (from Odroid)
curl http://localhost:8080/health  # If service exposes 8080 locally
```

### Certificate not loading
```bash
# Verify certificate exists
ls -la letsencrypt/live/license.drumscore.scot/

# Check nginx config syntax
docker compose exec nginx nginx -t

# Check nginx error logs
docker compose logs nginx | grep error
```
