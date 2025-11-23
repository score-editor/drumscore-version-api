# Multi-Service Architecture Guide

## Overview

The infrastructure is designed to host multiple services under different subdomains, all managed by a single nginx reverse proxy with individual Let's Encrypt certificates per service.

## Architecture Pattern

```
Internet
    ↓
Router (ports 80, 443)
    ↓
Odroid M1
    ↓
Nginx (reverse proxy)
    ├── support.drumscore.scot  → support-api:8080
    ├── license.drumscore.scot  → license-service:8081
    └── auth.drumscore.scot     → auth-service:8082
```

## Current Services

### support.drumscore.scot
- **Container**: `support-api` (port 8080)
- **Endpoints**:
  - `GET /api/version` - Version check
  - `POST /api/analytics/batch` - Analytics collection
  - `GET /health` - Health check
- **Certificate**: `/etc/letsencrypt/live/support.drumscore.scot/`

## Adding a New Service

### Prerequisites

1. Choose a subdomain name (e.g., `license`, `auth`, `docs`)
2. Choose a unique container port (e.g., `8081`, `8082`)
3. Implement your service (any language/framework)

### Quick Start

Use the provided script:

```bash
chmod +x add-service.sh
./add-service.sh license 8081
```

This will:
1. Guide you through DNS setup
2. Request a Let's Encrypt certificate
3. Generate nginx configuration
4. Generate docker-compose service template

### Manual Setup

#### 1. DNS Configuration

Add these records to your DNS:

```
Type    Name                            Value
A       license.drumscore.scot          51.148.180.134
AAAA    license.drumscore.scot          2a02:8010:6979:0::10
```

Wait 5-10 minutes for propagation, then verify:
```bash
dig license.drumscore.scot
```

#### 2. Request SSL Certificate

Stop nginx temporarily (to free port 80):
```bash
docker compose stop nginx
```

Request certificate:
```bash
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
```

Restart nginx:
```bash
docker compose start nginx
```

#### 3. Add Nginx Configuration

Edit `nginx/nginx.conf` and add before the closing `}`:

```nginx
# License Service
server {
    listen 80;
    listen [::]:80;
    server_name license.drumscore.scot;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name license.drumscore.scot;

    ssl_certificate /etc/letsencrypt/live/license.drumscore.scot/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/license.drumscore.scot/privkey.pem;
    
    # Copy SSL settings from support.drumscore.scot server block
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers '...'; # Use same ciphers as support service
    # ... other SSL settings
    
    # Rate limiting
    limit_req zone=api_limit burst=20 nodelay;
    limit_conn conn_limit 10;

    location /api/ {
        proxy_pass http://license-service:8081;
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
        proxy_pass http://license-service:8081/health;
        access_log off;
    }

    location / {
        return 404;
    }
}
```

#### 4. Add Service to Docker Compose

Edit `docker-compose.yml` and add your service:

```yaml
  license-service:
    build:
      context: ./license-service
      dockerfile: Dockerfile
    container_name: license-service
    restart: unless-stopped
    volumes:
      - ./license-service/config:/app/config:ro
    environment:
      - SERVICE_PORT=8081
    networks:
      - version-api-network
    expose:
      - "8081"
```

#### 5. Create Your Service

```bash
mkdir -p license-service
cd license-service

# Create your service (example: Go)
# Create Dockerfile, main.go, etc.
```

#### 6. Deploy

```bash
# Reload nginx configuration
docker compose restart nginx

# Build and start new service
docker compose up -d license-service

# Verify
docker compose ps
curl https://license.drumscore.scot/health
```

## Service Implementation Guidelines

### Required Endpoints

Every service should implement:
- `GET /health` - Returns 200 OK when healthy
- Your API endpoints under `/api/`

### Port Allocation

Keep track of used ports:
- 8080: support-api (version/analytics)
- 8081: license-service (example)
- 8082: auth-service (example)
- 8083-8089: Available

### Security Considerations

1. **Never expose service ports directly** - always behind nginx
2. **Use internal Docker network** - services can't be reached from outside
3. **Individual certificates** - each subdomain has its own cert
4. **Rate limiting** - apply appropriate limits in nginx per service
5. **Authentication** - implement in each service as needed

### Service Communication

Services can communicate internally:

```yaml
# In license-service, call support-api
http://support-api:8080/api/version
```

No need for HTTPS internally - Docker network is isolated.

## Monitoring

### Check all services:
```bash
docker compose ps
```

### View logs for specific service:
```bash
docker compose logs -f license-service
```

### Check nginx routing:
```bash
docker compose logs nginx | grep "license.drumscore.scot"
```

## Certificate Management

### Auto-Renewal

Certbot container automatically renews all certificates every 12 hours.

### Manual Renewal

Renew all certificates:
```bash
docker compose exec certbot certbot renew
docker compose restart nginx
```

Renew specific certificate:
```bash
docker compose exec certbot certbot renew --cert-name license.drumscore.scot
docker compose restart nginx
```

### View Certificate Status

```bash
docker compose exec certbot certbot certificates
```

## Troubleshooting

### New service returns 502 Bad Gateway

Check:
1. Service container is running: `docker compose ps`
2. Service is listening on correct port: `docker compose logs service-name`
3. Service is on correct network: Check docker-compose.yml
4. Nginx can reach service: `docker compose exec nginx ping service-name`

### Certificate request fails

Check:
1. DNS has propagated: `dig subdomain.drumscore.scot`
2. Port 80 is available: `sudo lsof -i :80`
3. Stop nginx before requesting: `docker compose stop nginx`

### Service works but certificate is invalid

Check:
1. Nginx is using correct certificate path
2. Certificate exists: `ls -la letsencrypt/live/subdomain.drumscore.scot/`
3. Reload nginx: `docker compose restart nginx`

## Migration to Cloud

This architecture transfers directly to cloud:

**AWS**:
- Upload to ECR, deploy on ECS
- Use ALB for load balancing (replaces nginx)
- Use ACM for certificates (or keep Let's Encrypt)

**DigitalOcean/Linode**:
- Same Docker Compose setup works
- Managed load balancers available

**Kubernetes**:
- Each service becomes a deployment
- Nginx becomes an Ingress controller
- Cert-manager replaces certbot

The containerized, service-per-subdomain pattern is cloud-native and scales well.

## Best Practices

1. **One service per subdomain** - clear separation
2. **Consistent naming** - `servicename-service` for containers
3. **Health checks** - every service must have `/health`
4. **Logging** - use structured logging (JSON) for aggregation
5. **Secrets** - use `.env` files, never commit secrets
6. **Documentation** - document your service's API contract
7. **Versioning** - consider `/api/v1/` for future API versions

## Example: Complete License Service

See `examples/license-service/` for a complete working example of:
- Go service implementation
- Dockerfile
- docker-compose integration
- nginx configuration
- API documentation
