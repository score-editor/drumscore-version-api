# Platform and Architecture Support - Deployment Guide

## What Changed

The version API now supports separate platform and architecture variants, allowing different build numbers for:
- Windows x64 vs ARM64
- macOS Intel vs Apple Silicon
- Linux x64 vs ARM64

## New API Format

**Old:**
```
GET /api/version
```

**New:**
```
GET /api/version?platform=macos&arch=aarch64
```

## Deployment Steps

### 1. Update Config File

Replace `config/version.json` with the new format:

```bash
cd ~/drumscore-version-api
cp config/version.json config/version.json.backup
# Copy the new version.json.new to version.json
mv config/version.json.new config/version.json
```

**New config structure:**
```json
{
  "windows": {
    "x86_64": { version info },
    "aarch64": { version info }
  },
  "macos": {
    "x86_64": { version info },
    "aarch64": { version info }
  },
  "linux": {
    "x86_64": { version info },
    "aarch64": { version info }
  }
}
```

### 2. Rebuild and Deploy

```bash
# Stop services
docker compose down

# Rebuild API with new code
docker compose build --no-cache api

# Start services
docker compose up -d

# Check logs
docker compose logs -f api
```

You should see in the logs:
```
Loaded platform versions: Windows(x64=3.4.0,arm64=3.4.0), macOS(x64=3.4.0,arm64=3.4.0), Linux(x64=3.4.0,arm64=3.4.0)
```

### 3. Test

```bash
# Test each combination
curl "https://support.drumscore.scot/api/version?platform=macos&arch=aarch64"
curl "https://support.drumscore.scot/api/version?platform=windows&arch=x86_64"
curl "https://support.drumscore.scot/api/version?platform=linux&arch=aarch64"

# Test error handling
curl "https://support.drumscore.scot/api/version?platform=macos"  # Missing arch - should return 400
```

### 4. Update Java Client

Your Java client needs to detect and send both parameters:

```java
String platform = getPlatform(); // "windows", "macos", "linux"
String arch = getArch();         // "x86_64", "aarch64"

String url = "https://support.drumscore.scot/api/version" +
             "?platform=" + platform + 
             "&arch=" + arch;
```

See `API_CONTRACT.md` for complete implementation details.

## Updating Versions

Edit `config/version.json` and update specific platform/arch combinations:

```json
{
  "macos": {
    "aarch64": {
      "version": "3.5.0",
      "build": "2025.11.24.1",
      "releaseDate": "2025-11-24T10:00:00Z",
      "downloadUrl": "https://drumscore.scot/downloads/macos-apple-silicon/DrumScore-3.5.0.dmg",
      "minSupportedVersion": "3.3.0",
      "releaseNotes": "New features for Apple Silicon"
    }
  }
}
```

Changes apply within 30 seconds, no restart needed.

## Breaking Change

**Important:** Old clients using `/api/version` without parameters will now receive `400 Bad Request`.

You must update all clients to include both `platform` and `arch` parameters before deploying this change, or provide a transition period with both old and new clients running.

## Rollback Plan

If needed, rollback:

```bash
# Stop services
docker compose down

# Restore old config
cp config/version.json.backup config/version.json

# Checkout previous version of api/main.go from git
git checkout HEAD~1 api/main.go

# Rebuild and start
docker compose build --no-cache api
docker compose up -d
```

## Analytics Impact

Version checks are now logged as:
```
platform-arch-version
```

Example:
```
macos-aarch64-3.4.0
windows-x86_64-3.4.0
```

Query to see platform/arch breakdown:
```sql
SELECT 
  CASE 
    WHEN app_version LIKE 'windows-x86_64%' THEN 'Windows x64'
    WHEN app_version LIKE 'windows-aarch64%' THEN 'Windows ARM64'
    WHEN app_version LIKE 'macos-x86_64%' THEN 'macOS Intel'
    WHEN app_version LIKE 'macos-aarch64%' THEN 'macOS Apple Silicon'
    WHEN app_version LIKE 'linux-x86_64%' THEN 'Linux x64'
    WHEN app_version LIKE 'linux-aarch64%' THEN 'Linux ARM64'
  END as platform_arch,
  COUNT(DISTINCT client_id) as unique_users
FROM version_checks
WHERE timestamp > datetime('now', '-30 days')
GROUP BY platform_arch;
```
