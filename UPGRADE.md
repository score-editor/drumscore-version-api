# Upgrading to Analytics-Enabled Version

## If you already have the version API running

### Quick Upgrade Steps

1. **Stop current services**
   ```bash
   cd ~/drumscore-version-api
   docker compose down
   ```

2. **Backup existing data** (just in case)
   ```bash
   cp config/version.json config/version.json.backup
   ```

3. **Pull latest changes** (if using git)
   ```bash
   git pull
   ```
   
   OR **replace files manually** with updated versions

4. **Create data directory**
   ```bash
   mkdir -p data
   ```

5. **Set analytics secret** (optional but recommended)
   ```bash
   # Generate secret
   openssl rand -base64 32 > .analytics_secret
   
   # Create .env file
   echo "ANALYTICS_SECRET=$(cat .analytics_secret)" > .env
   
   # IMPORTANT: Use this same secret in your Java client!
   cat .analytics_secret
   ```

6. **Rebuild and restart**
   ```bash
   docker compose build --no-cache
   docker compose up -d
   ```

7. **Verify everything works**
   ```bash
   # Check containers
   docker compose ps
   
   # Check logs
   docker compose logs -f
   
   # Test version endpoint
   curl https://version.drumscore.scot/api/version
   
   # Check database was created
   docker compose exec api ls -la /app/data/
   ```

### What's New

**New Files:**
- `API_CONTRACT.md` - Complete API documentation for client developers
- `.env.example` - Example environment variables
- `data/` directory - Will contain SQLite database (auto-created)

**Updated Files:**
- `api/main.go` - Added analytics endpoint, database, validation
- `api/Dockerfile` - Added SQLite support
- `docker-compose.yml` - Added database volume and env vars
- `nginx/nginx.conf` - Added analytics endpoint routing
- `.gitignore` - Excluded data directory
- `README.md` - Added analytics documentation

**What's Preserved:**
- Your existing `config/version.json` - unchanged
- Let's Encrypt certificates - unchanged
- All existing functionality - version check still works exactly the same

### Testing Analytics

Once your client app is updated to send analytics, test with:

```bash
# Watch for incoming events
docker compose logs -f api | grep "Received"

# Query database
docker compose exec api sqlite3 /app/data/analytics.db \
  "SELECT COUNT(*) FROM analytics_events;"
```

### Rollback (if needed)

If something goes wrong:

```bash
# Stop new version
docker compose down

# Restore backup
cp config/version.json.backup config/version.json

# If you kept old code, checkout previous commit
git checkout <previous-commit>

# Start old version
docker compose up -d
```

### Important Notes

1. **The analytics secret** in `.env` must match what you embed in your Java client
2. **Database grows over time** - plan for log rotation/cleanup
3. **Rate limiting** is per client ID for analytics (12/hour = one every 5 min)
4. **Backwards compatible** - clients without analytics will continue to work
5. **Privacy-first** - no PII collected, only anonymous machine hashes

### Next Steps

1. Update your Java client to:
   - Generate stable client ID
   - Batch analytics events
   - Sign requests with HMAC-SHA256
   - Send batches every 5 minutes

2. See `API_CONTRACT.md` for complete client implementation guide

3. After 30+ days, query analytics for sponsor metrics
