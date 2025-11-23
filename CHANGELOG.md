# Complete Changelog - All Updates

## Summary of All Changes in This Session

### 🆕 New Files Created

1. **MULTI_SERVICE_GUIDE.md** - Complete guide for adding new services
   - Architecture overview
   - Step-by-step instructions for adding services
   - Port allocation guidelines
   - Certificate management
   - Troubleshooting

2. **CURRENT_STATUS.md** - Current state snapshot
   - What's configured
   - What's running
   - Management commands
   - Next steps

3. **add-service.sh** - Automated service addition script
   - Interactive DNS setup
   - Certificate request
   - Nginx config generation
   - Docker compose template generation

4. **ADDING_SERVICES.md** - Appears to be from earlier session
5. **GIT_COMMIT_GUIDE.md** - Appears to be from earlier session
6. **MIGRATION.md** - Domain migration guide (version→support)

### 📝 Files Modified

1. **API_CONTRACT.md**
   - Updated client ID generation to use OS-specific machine IDs:
     - Windows: Registry MachineGuid
     - macOS: IOPlatformUUID
     - Linux: /etc/machine-id
   - Removed PII (user.home path)
   - Added proper test examples with valid client IDs
   - Fixed curl examples with valid 64-char hex IDs

2. **README.md**
   - Fixed sqlite3 commands (use from host, not container)
   - Updated all `docker-compose` to `docker compose`
   - Added analytics troubleshooting
   - Updated secret management instructions
   - Domain already at support.drumscore.scot

3. **UPGRADE.md**
   - Fixed sqlite3 commands
   - Updated rate limit documentation (1r/m not 12r/h)
   - Emphasized secret preservation (don't regenerate)
   - Added secret backup warnings

4. **nginx/nginx.conf**
   - Fixed rate limiting syntax (changed 12r/h to 1r/m)
   - Domain already at support.drumscore.scot
   - Already includes commented multi-service templates
   - Updated burst values for analytics

5. **setup-letsencrypt.sh**
   - Domain already at support.drumscore.scot
   - No changes needed

6. **docker-compose.yml**
   - Removed obsolete 'version' field (already done)
   - Data volume mount (already present)
   - ANALYTICS_SECRET env var (already present)

7. **.gitignore**
   - Added `.analytics_secret` exclusion

### 🔧 Technical Changes Summary

**Analytics Implementation:**
- SQLite database with two tables
- Request signing with HMAC-SHA256
- Feature whitelist validation
- Client ID validation (64-char hex SHA-256)
- Rate limiting per client ID
- Privacy-first (no PII)

**Domain Migration:**
- Changed from `version.drumscore.scot` to `support.drumscore.scot`
- Allows for future services (license, auth, etc.)

**Machine ID Generation:**
- OS-specific facilities instead of MAC enumeration
- No PII collected (removed user.home)
- Stable, anonymous identifiers

**Multi-Service Architecture:**
- Nginx ready for multiple subdomains
- Individual certificates per service
- Helper script for easy addition
- Comprehensive documentation

### 📋 Files Status

**Core Configuration:**
- ✅ `docker-compose.yml` - Up to date
- ✅ `nginx/nginx.conf` - Up to date
- ✅ `setup-letsencrypt.sh` - Up to date
- ✅ `api/main.go` - Analytics support
- ✅ `api/Dockerfile` - SQLite support

**Documentation (All Updated):**
- ✅ `README.md`
- ✅ `API_CONTRACT.md`
- ✅ `UPGRADE.md`
- ✅ `MULTI_SERVICE_GUIDE.md` (new)
- ✅ `CURRENT_STATUS.md` (new)
- ✅ `MIGRATION.md` (from earlier)
- ✅ `GIT_COMMIT_GUIDE.md` (from earlier)
- ✅ `ADDING_SERVICES.md` (from earlier)

**Scripts:**
- ✅ `add-service.sh` (new)
- ✅ `.gitignore`

**Security:**
- ✅ `.env.example`
- ⚠️ `.env` (create on server)
- ⚠️ `.analytics_secret` (create on server)

### 🎯 What You Need to Do

**Commit All Changes:**
```bash
# On your local machine
git add .
git status  # Review all changes
git commit -m "Complete analytics and multi-service architecture

- Add analytics support with SQLite and request signing
- Switch to support.drumscore.scot for multi-service expansion
- Use OS-specific machine IDs (no PII)
- Add multi-service architecture documentation and tooling
- Fix nginx rate limiting and documentation
- Add helper script for adding new services"

git push origin main
```

**On Odroid (If Not Yet Deployed):**
```bash
cd ~/drumscore-version-api
git pull

# If you haven't generated the secret yet
openssl rand -base64 32 > .analytics_secret
echo "ANALYTICS_SECRET=$(cat .analytics_secret)" > .env

# Rebuild and deploy
docker compose down
docker compose build --no-cache
docker compose up -d
```

**Note:** Some files (ADDING_SERVICES.md, GIT_COMMIT_GUIDE.md, MIGRATION.md) appear to have been created in an earlier session but are included in the archive.

### 📊 Changed Files Count

**From this session specifically:**
- New: 3 files (MULTI_SERVICE_GUIDE.md, CURRENT_STATUS.md, add-service.sh)
- Modified: 4 files (API_CONTRACT.md, README.md, UPGRADE.md, .gitignore)
- **Total this session: 7 files changed**

**From earlier sessions (already present):**
- ADDING_SERVICES.md
- GIT_COMMIT_GUIDE.md  
- MIGRATION.md
- docker-compose.yml (version removed)
- nginx/nginx.conf (support domain)
- setup-letsencrypt.sh (support domain)

**All core functionality files were updated in previous session, this session focused on:**
1. Fixing PII issue in client ID generation
2. Fixing sqlite3 commands
3. Adding multi-service documentation and tooling
4. Fixing rate limit documentation
5. Adding secret preservation warnings
