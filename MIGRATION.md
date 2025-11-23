# Migration Guide: version.drumscore.scot → support.drumscore.scot

## Overview

We're changing the domain from `version.drumscore.scot` to `support.drumscore.scot` to allow for multiple support-related APIs under one subdomain.

## Why This Change

- `version.drumscore.scot/api/version` is redundant
- `support.drumscore.scot` can host multiple endpoints:
  - `/api/version` - version checking
  - `/api/analytics` - usage analytics
  - Future: `/api/feedback`, `/api/logs`, etc.

## Migration Steps

### 1. Configure DNS

**Add new DNS records:**
- **A record**: `support.drumscore.scot` → `51.148.180.134`
- **AAAA record**: `support.drumscore.scot` → `2a02:8010:6979:0::10`

**Keep old records temporarily** (for backwards compatibility):
- `version.drumscore.scot` records remain active

Wait 5-10 minutes for DNS propagation, then verify:
```bash
nslookup support.drumscore.scot
```

### 2. Stop Current Services

```bash
cd ~/drumscore-version-api
docker compose down
```

### 3. Pull Updated Configuration

```bash
git pull origin main
```

### 4. Remove Old Certificate

```bash
# Old certificate no longer needed
rm -rf letsencrypt/live/version.drumscore.scot
rm -rf letsencrypt/archive/version.drumscore.scot
rm -rf letsencrypt/renewal/version.drumscore.scot.conf
```

### 5. Obtain New Certificate

```bash
./setup-letsencrypt.sh
```

This will request a certificate for `support.drumscore.scot`.

### 6. Start Services

```bash
docker compose up -d
```

### 7. Verify Everything Works

```bash
# Check containers
docker compose ps

# Test new domain
curl https://support.drumscore.scot/api/version

# Test analytics endpoint
curl https://support.drumscore.scot/health
```

### 8. Update Client Applications

**In your Java client code**, change:

```java
// OLD
private static final String VERSION_API_URL = 
    "https://version.drumscore.scot/api/version";
private static final String ANALYTICS_URL = 
    "https://version.drumscore.scot/api/analytics/batch";

// NEW
private static final String VERSION_API_URL = 
    "https://support.drumscore.scot/api/version";
private static final String ANALYTICS_URL = 
    "https://support.drumscore.scot/api/analytics/batch";
```

### 9. Deploy Updated Clients

Release updated version of DrumScore Editor with new domain.

### 10. Monitor Old Domain (Optional)

If you want to track how many clients are still using the old domain:

```bash
# Check nginx access logs for version.drumscore.scot
docker compose logs nginx | grep "version.drumscore.scot"
```

### 11. Decommission Old Domain (Later)

After all clients have updated (1-2 months):

1. Remove old DNS records for `version.drumscore.scot`
2. Remove old certificate if it still exists
3. Update router port forwarding if dedicated to old domain

## Backwards Compatibility (Optional)

If you want to support both domains temporarily, you can add a second server block in `nginx/nginx.conf`:

```nginx
# Keep old domain working (redirect to new)
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name version.drumscore.scot;

    ssl_certificate /etc/letsencrypt/live/version.drumscore.scot/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/version.drumscore.scot/privkey.pem;
    
    # Redirect to new domain
    location / {
        return 301 https://support.drumscore.scot$request_uri;
    }
}
```

This redirects all `version.drumscore.scot` requests to `support.drumscore.scot`.

## Rollback (If Needed)

If something goes wrong:

```bash
# Stop services
docker compose down

# Revert git changes
git revert HEAD

# Restore old certificate (if you kept a backup)
# Or re-run setup script with old domain

# Restart
docker compose up -d
```

## Testing Checklist

- [ ] DNS resolves for `support.drumscore.scot`
- [ ] Certificate obtained successfully
- [ ] HTTPS works: `https://support.drumscore.scot/api/version`
- [ ] Analytics endpoint works: `https://support.drumscore.scot/api/analytics/batch`
- [ ] Health check works: `https://support.drumscore.scot/health`
- [ ] Client application updated and tested
- [ ] Old domain redirects (if implementing backwards compatibility)

## Timeline

**Day 1**: Deploy server changes
**Day 1-3**: Deploy updated client application
**Week 2-8**: Monitor both domains
**Month 2**: Remove old domain support

## Questions?

Check the main README.md for troubleshooting, or review logs:
```bash
docker compose logs -f
```
