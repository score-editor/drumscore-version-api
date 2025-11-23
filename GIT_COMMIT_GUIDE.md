# Git Commit Guide - Analytics Feature

## Files to Add (New)
```bash
git add API_CONTRACT.md
git add UPGRADE.md
git add .env.example
```

## Files to Update (Modified)
```bash
git add api/main.go
git add api/Dockerfile
git add docker-compose.yml
git add nginx/nginx.conf
git add .gitignore
git add README.md
```

## Commit and Push
```bash
git commit -m "Add analytics support with SQLite, request signing, and feature tracking

- Add analytics batch endpoint for feature usage tracking
- Implement SQLite database for analytics storage
- Add HMAC-SHA256 request signing for security
- Add comprehensive validation (client ID, features, timestamps)
- Add rate limiting per client ID (12/hour)
- Add feature whitelist to prevent data pollution
- Update documentation with API contract and upgrade guide
- Maintain backwards compatibility with existing version check API"

git push origin main  # or 'master' depending on your branch
```

## Alternative: Download and Copy Files

If you prefer to download the files directly:

1. Download the tarball from Claude
2. Extract it locally
3. Copy the updated files to your repo
4. Run the git commands above

## Files Changed Summary

**api/main.go** - Major changes:
- Added SQLite database support
- Added analytics batch endpoint handler
- Added request signature validation
- Added comprehensive payload validation
- Added feature name whitelist
- Enhanced version check to log client IDs

**api/Dockerfile** - Changes:
- Added SQLite build dependencies
- Enabled CGO for SQLite support
- Added sqlite-libs to runtime

**docker-compose.yml** - Changes:
- Removed obsolete 'version' field
- Added ./data volume mount
- Added ANALYTICS_SECRET environment variable

**nginx/nginx.conf** - Changes:
- Added analytics_limit rate zone
- Added /api/analytics/batch location block
- Added CORS headers for analytics endpoint

**.gitignore** - Changes:
- Added data/ directory exclusion

**README.md** - Changes:
- Updated features list
- Added analytics configuration steps
- Added API endpoints documentation
- Added analytics database queries
- Fixed docker-compose → docker compose
- Added analytics troubleshooting

**New Files:**
- API_CONTRACT.md - Complete API specification
- UPGRADE.md - Upgrade instructions
- .env.example - Environment variable template
