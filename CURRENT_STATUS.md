# Current Setup Status

## ✅ What's Already Configured

### Domain
- **Primary**: `support.drumscore.scot` 
- **Purpose**: Version check and analytics API
- **Migration**: Already switched from `version.drumscore.scot`

### Infrastructure
- **Platform**: Odroid M1 (8GB RAM, NVMe SSD)
- **OS**: Ubuntu 22.04
- **Network**: 
  - IPv4: `51.148.180.134`
  - IPv6: `2a02:8010:6979:0::10`
  - Ports: 80, 443 forwarded from router

### Services Running
1. **Nginx** - Reverse proxy with TLS termination
2. **Certbot** - Auto-renewing Let's Encrypt certificates
3. **Support API** - Version check + analytics (Go)

### API Endpoints
- `GET /api/version` - Version information
- `POST /api/analytics/batch` - Feature usage tracking
- `GET /health` - Health check

### Security Features
- ✅ HTTPS with Let's Encrypt
- ✅ Rate limiting (60 req/min for version, 1 req/min for analytics)
- ✅ Request signing (HMAC-SHA256)
- ✅ Feature whitelist validation
- ✅ Client ID validation
- ✅ DDoS protection
- ✅ Privacy-first (no PII collection)

### Database
- SQLite at `data/analytics.db`
- Tables: `version_checks`, `analytics_events`
- OS-specific client IDs (Windows MachineGuid, macOS IOPlatformUUID, Linux machine-id)

## 📋 Configuration Files

### Core Files
- `docker-compose.yml` - Container orchestration
- `nginx/nginx.conf` - Reverse proxy with multi-service support
- `setup-letsencrypt.sh` - Certificate setup
- `config/version-multiplatform.json` - Version info per platform (editable)

### Documentation
- `README.md` - General documentation
- `API_CONTRACT.md` - API specification for client developers
- `MULTI_SERVICE_GUIDE.md` - Adding additional services
- `UPGRADE.md` - Upgrade instructions

### Scripts
- `add-service.sh` - Helper for adding new services
- `.gitignore` - Excludes secrets and certificates

### Security
- `.env` - Analytics secret (not in git)
- `.analytics_secret` - Secret backup (not in git)

## 🚀 Multi-Service Ready

The nginx configuration includes:
- Template for additional services (commented out)
- Support for multiple subdomains
- Individual certificate per subdomain
- Isolated Docker network for services

### Adding Future Services

Example services you could add:
- `license.drumscore.scot` - License validation
- `auth.drumscore.scot` - Authentication service
- `docs.drumscore.scot` - Documentation

Process:
1. Run `./add-service.sh <name> <port>`
2. Implement your service
3. Deploy with `docker compose up -d`

## 📊 Current State

### Containers
```
version-api-nginx       nginx:alpine       Ports: 80, 443
version-api-certbot     certbot/certbot    Auto-renewal
version-api-service     Go (custom)        Port: 8080 (internal)
```

### Volumes
```
./config         → /app/config (read-only)
./data           → /app/data (SQLite database)
./nginx          → /etc/nginx
./letsencrypt    → /etc/letsencrypt
```

### Network
```
version-api-network (bridge)
  ├── nginx (public: 80, 443)
  ├── certbot
  └── api (internal: 8080)
```

## 🔄 What Changed Recently

1. **Domain Migration**: `version.drumscore.scot` → `support.drumscore.scot`
2. **Analytics Added**: Feature usage tracking with SQLite
3. **OS-Specific Client IDs**: Windows/macOS/Linux machine identification
4. **Multi-Service Architecture**: Ready for additional services
5. **Security Enhancements**: Request signing, validation, rate limiting

## 📝 Next Steps for You

### Immediate
- [x] Server configured and running
- [x] Analytics backend ready
- [ ] Implement Java client (see API_CONTRACT.md)
- [ ] Deploy client with analytics

### Future
- [ ] Add license service (`license.drumscore.scot`)
- [ ] Add authentication service (`auth.drumscore.scot`)
- [ ] Consider Grafana for analytics visualization
- [ ] Plan migration to AWS when needed

## 🔧 Management Commands

### Daily Operations
```bash
# Check status
docker compose ps

# View logs
docker compose logs -f

# Restart service
docker compose restart api

# Update version
nano config/version.json
```

### Analytics Queries
```bash
# Unique users
sqlite3 data/analytics.db "SELECT COUNT(DISTINCT client_id) FROM version_checks;"

# Most used features  
sqlite3 data/analytics.db "SELECT feature_name, COUNT(*) FROM analytics_events WHERE event_type='feature_used' GROUP BY feature_name ORDER BY COUNT(*) DESC LIMIT 10;"
```

### Certificate Management
```bash
# View certificate status
docker compose exec certbot certbot certificates

# Manual renewal
docker compose exec certbot certbot renew
docker compose restart nginx
```

## 📞 Support Resources

- **Documentation**: All `.md` files in repo
- **API Spec**: `API_CONTRACT.md`
- **Multi-Service**: `MULTI_SERVICE_GUIDE.md`
- **Troubleshooting**: Check README.md troubleshooting section

## 🎯 Design Philosophy

- **Security first**: x.509, HMAC signing, no PII
- **Privacy preserving**: Anonymous machine IDs only
- **Cloud ready**: Containerized, portable
- **Native languages**: Go for server, Java for client
- **Scalable**: Multi-service architecture from day one
