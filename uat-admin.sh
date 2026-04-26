#!/bin/bash
#
# UAT Admin Tool for Drum Score Editor
# Manages builds and download links on snare (via WireGuard)
#

HOST="${UAT_HOST:-https://10.77.77.1}"

if [ -z "$ADMIN_SECRET" ]; then
    echo "Error: ADMIN_SECRET not set. Run: export ADMIN_SECRET=<your-secret>"
    echo "Hint: SSH to snare and 'cat .env' if you've forgotten it"
    exit 1
fi

AUTH="Authorization: Bearer $ADMIN_SECRET"

# Run curl, validate response. On success sets API_BODY (guaranteed non-empty JSON).
# On failure prints a friendly error and returns 1.
# Usage: api_call <METHOD> <path> [extra-curl-args...]
api_call() {
    local method="$1" path="$2"
    shift 2

    local body_file stderr_file status curl_exit err
    body_file=$(mktemp)
    stderr_file=$(mktemp)

    status=$(curl -sSk -w "%{http_code}" -o "$body_file" \
        -X "$method" "$HOST$path" -H "$AUTH" "$@" 2>"$stderr_file")
    curl_exit=$?
    err=$(cat "$stderr_file")
    API_BODY=$(cat "$body_file")
    rm -f "$body_file" "$stderr_file"

    if [ "$curl_exit" -ne 0 ] || [ "$status" = "000" ]; then
        echo "Error: could not reach $HOST" >&2
        [ -n "$err" ] && echo "  $err" >&2
        echo "  Hint: admin endpoints require the WireGuard tunnel — is wg up?" >&2
        return 1
    fi

    if [ "$status" -lt 200 ] || [ "$status" -ge 300 ]; then
        case "$status" in
            401|403)
                echo "Error: HTTP $status from $HOST$path — check ADMIN_SECRET" >&2 ;;
            404)
                echo "Error: HTTP 404 from $HOST$path" >&2
                echo "  Admin endpoints are local-network only. Access via WireGuard" >&2
                echo "  (default UAT_HOST=https://10.77.77.1) — public/Cloudflare returns 404." >&2 ;;
            *)
                echo "Error: HTTP $status from $HOST$path" >&2 ;;
        esac
        [ -n "$API_BODY" ] && echo "  Body: ${API_BODY:0:300}" >&2
        return 1
    fi

    if [ -z "$API_BODY" ]; then
        echo "Error: empty response from $HOST$path (HTTP $status)" >&2
        return 1
    fi

    if ! echo "$API_BODY" | python3 -c "import sys,json; json.load(sys.stdin)" >/dev/null 2>&1; then
        echo "Error: non-JSON response from $HOST$path" >&2
        echo "  Body: ${API_BODY:0:300}" >&2
        return 1
    fi

    return 0
}

usage() {
    cat <<'EOF'
UAT Admin Tool — Drum Score Editor

Usage: uat-admin.sh <command> [options]

Commands:
  help                          Show this help
  upload <file> <version> <platform> <arch>   Upload a build
  link <name> <version> <platform> <arch>     Create a download link
  builds                        List all builds
  links [active|expired|all]    List links (default: active)
  reset <token>                 Reset download count for a link
  revoke <token>                Revoke a link
  delete-build <id>             Delete a build
  status                        Show all builds and active links

  share <file> <name> [description]           Upload a file and create a one-time link
  share-link <name> <file-id> [maxUses]       Create a link for an existing shared file
  shared-files                                List shared files
  delete-shared <id>                          Delete a shared file

Platforms: macos, windows, linux
Architectures: x86_64, aarch64

Examples:
  uat-admin.sh upload DrumScoreEditor_macOS_arm64_3.6.0.dmg 3.6.0 macos aarch64
  uat-admin.sh link "John Smith" 3.6.0 macos aarch64
  uat-admin.sh reset 4410ac59...    (reset download count)
  uat-admin.sh links
  uat-admin.sh status
  uat-admin.sh share manual.pdf "John Smith" "Drum Score Editor manual"
  uat-admin.sh shared-files
EOF
}

upload_build() {
    local file="$1" version="$2" platform="$3" arch="$4"
    if [ -z "$file" ] || [ -z "$version" ] || [ -z "$platform" ] || [ -z "$arch" ]; then
        echo "Usage: uat-admin.sh upload <file> <version> <platform> <arch>"
        exit 1
    fi
    if [ ! -f "$file" ]; then
        echo "Error: File not found: $file"
        exit 1
    fi

    local size
    size=$(du -h "$file" | cut -f1)
    echo "Uploading $file ($size) as $version/$platform/$arch..."
    echo

    api_call POST /api/admin/uat-builds \
        -F "file=@$file" \
        -F "version=$version" \
        -F "platform=$platform" \
        -F "arch=$arch" || return 1

    echo "$API_BODY" | python3 -c "
import sys, json
b = json.load(sys.stdin)
if 'id' not in b:
    print(f'Error: {b}')
    sys.exit(1)
print(f\"  Build uploaded successfully\")
print(f\"  ID:       {b['id']}\")
print(f\"  Version:  {b['version']}\")
print(f\"  Platform: {b['platform']}/{b['arch']}\")
print(f\"  Size:     {b['fileSize'] / 1048576:.1f} MB\")
"
}

create_link() {
    local name="$1" version="$2" platform="$3" arch="$4"
    if [ -z "$name" ] || [ -z "$version" ] || [ -z "$platform" ] || [ -z "$arch" ]; then
        echo "Usage: uat-admin.sh link <name> <version> <platform> <arch>"
        exit 1
    fi

    api_call POST /api/admin/uat-links \
        -H "Content-Type: application/json" \
        -d "{\"issuedTo\":\"$name\",\"version\":\"$version\",\"platform\":\"$platform\",\"arch\":\"$arch\"}" || return 1

    echo "$API_BODY" | python3 -c "
import sys, json
l = json.load(sys.stdin)
if 'token' not in l:
    print(f'Error: {l}')
    sys.exit(1)
print(f\"  Link created for {l['issuedTo']}\")
print(f\"  Version:  {l['version']} ({l['platform']}/{l['arch']})\")
print(f\"  Uses:     {l['maxUses']}\")
print(f\"  Expires:  {l['expiresAt']}\")
print()
print(f\"  Send this link:\")
print(f\"  {l['downloadLink']}\")
"
}

list_builds() {
    api_call GET /api/admin/uat-builds || return 1

    echo "$API_BODY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
builds = data.get('builds', [])
if not builds:
    print('  No builds found.')
    sys.exit(0)
print(f'  {len(builds)} build(s)')
print()
print(f'  {\"ID\":<6} {\"Version\":<16} {\"Platform\":<10} {\"Arch\":<10} {\"Size\":<10} {\"Uploaded\"}')
print(f'  {\"-\"*6} {\"-\"*16} {\"-\"*10} {\"-\"*10} {\"-\"*10} {\"-\"*19}')
for b in builds:
    size = f\"{b['fileSize'] / 1048576:.1f} MB\"
    created = b.get('createdAt', '')[:19]
    print(f\"  {b['id']:<6} {b['version']:<16} {b['platform']:<10} {b['arch']:<10} {size:<10} {created}\")
"
}

list_links() {
    local status="${1:-active}"
    api_call GET "/api/admin/uat-links?status=$status" || return 1

    echo "$API_BODY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
links = data.get('links', [])
status = '$status'
if not links:
    print(f'  No {status} links found.')
    sys.exit(0)
print(f'  {len(links)} {status} link(s)')
print()
for l in links:
    revoked = ' [REVOKED]' if l.get('revoked') else ''
    expires = l.get('expiresAt', '')[:19]
    print(f\"  {l['issuedTo']}{revoked}\")
    print(f\"    Version:  {l.get('version','?')}/{l.get('platform','?')}/{l.get('arch','?')}\")
    print(f\"    Uses:     {l['useCount']}/{l['maxUses']}\")
    print(f\"    Expires:  {expires}\")
    print(f\"    Token:    {l['token']}\")
    print()
"
}

reset_link() {
    local token="$1"
    if [ -z "$token" ]; then
        echo "Usage: uat-admin.sh reset <token>"
        exit 1
    fi

    api_call PATCH "/api/admin/uat-links/$token" || return 1

    if echo "$API_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='reset'" 2>/dev/null; then
        echo "  Download count reset: ${token:0:16}..."
    else
        echo "Error: unexpected response: $API_BODY"
    fi
}

revoke_link() {
    local token="$1"
    if [ -z "$token" ]; then
        echo "Usage: uat-admin.sh revoke <token>"
        exit 1
    fi

    api_call DELETE "/api/admin/uat-links/$token" || return 1

    if echo "$API_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='revoked'" 2>/dev/null; then
        echo "  Link revoked: ${token:0:16}..."
    else
        echo "Error: unexpected response: $API_BODY"
    fi
}

delete_build() {
    local id="$1"
    if [ -z "$id" ]; then
        echo "Usage: uat-admin.sh delete-build <id>"
        exit 1
    fi

    api_call DELETE "/api/admin/uat-builds/$id" || return 1

    if echo "$API_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='deleted'" 2>/dev/null; then
        echo "  Build $id deleted."
    else
        echo "Error: unexpected response: $API_BODY"
    fi
}

share_file() {
    local file="$1" name="$2" description="$3"
    if [ -z "$file" ] || [ -z "$name" ]; then
        echo "Usage: uat-admin.sh share <file> <name> [description]"
        exit 1
    fi
    if [ ! -f "$file" ]; then
        echo "Error: File not found: $file"
        exit 1
    fi

    local size
    size=$(du -h "$file" | cut -f1)
    echo "Uploading $file ($size)..."
    echo

    api_call POST /api/admin/shared-files \
        -F "file=@$file" \
        -F "description=$description" || return 1

    local file_id
    file_id=$(echo "$API_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)
    if [ -z "$file_id" ]; then
        echo "Error uploading file: $API_BODY"
        exit 1
    fi

    # Create a download link (3 uses to allow for link preview bots)
    api_call POST /api/admin/uat-links \
        -H "Content-Type: application/json" \
        -d "{\"issuedTo\":\"$name\",\"sharedFileId\":$file_id,\"maxUses\":3}" || return 1

    echo "$API_BODY" | python3 -c "
import sys, json
l = json.load(sys.stdin)
if 'token' not in l:
    print(f'Error creating link: {l}')
    sys.exit(1)
print(f'  File shared with {l[\"issuedTo\"]}')
print(f'  Uses:     {l[\"maxUses\"]}')
print(f'  Expires:  {l[\"expiresAt\"]}')
print()
print(f'  Send this link:')
print(f'  {l[\"downloadLink\"]}')
"
}

share_link() {
    local name="$1" file_id="$2" max_uses="${3:-1}"
    if [ -z "$name" ] || [ -z "$file_id" ]; then
        echo "Usage: uat-admin.sh share-link <name> <file-id> [maxUses]"
        exit 1
    fi

    api_call POST /api/admin/uat-links \
        -H "Content-Type: application/json" \
        -d "{\"issuedTo\":\"$name\",\"sharedFileId\":$file_id,\"maxUses\":$max_uses}" || return 1

    echo "$API_BODY" | python3 -c "
import sys, json
l = json.load(sys.stdin)
if 'token' not in l:
    print(f'Error: {l}')
    sys.exit(1)
print(f'  Link created for {l[\"issuedTo\"]}')
print(f'  Uses:     {l[\"maxUses\"]}')
print(f'  Expires:  {l[\"expiresAt\"]}')
print()
print(f'  Send this link:')
print(f'  {l[\"downloadLink\"]}')
"
}

list_shared_files() {
    api_call GET /api/admin/shared-files || return 1

    echo "$API_BODY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
files = data.get('files', [])
if not files:
    print('  No shared files found.')
    sys.exit(0)
print(f'  {len(files)} shared file(s)')
print()
print(f'  {\"ID\":<6} {\"Original Name\":<30} {\"Size\":<10} {\"Description\":<20} {\"Uploaded\"}')
print(f'  {\"-\"*6} {\"-\"*30} {\"-\"*10} {\"-\"*20} {\"-\"*19}')
for f in files:
    size = f'{f[\"fileSize\"] / 1048576:.1f} MB'
    created = f.get('createdAt', '')[:19]
    desc = f.get('description', '')[:20]
    name = f.get('originalName', '')[:30]
    print(f'  {f[\"id\"]:<6} {name:<30} {size:<10} {desc:<20} {created}')
"
}

delete_shared() {
    local id="$1"
    if [ -z "$id" ]; then
        echo "Usage: uat-admin.sh delete-shared <id>"
        exit 1
    fi

    api_call DELETE "/api/admin/shared-files/$id" || return 1

    if echo "$API_BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='deleted'" 2>/dev/null; then
        echo "  Shared file $id deleted."
    else
        echo "Error: unexpected response: $API_BODY"
    fi
}

show_status() {
    echo "=== UAT Builds ==="
    echo
    list_builds
    echo
    echo "=== Active Links ==="
    echo
    list_links active
}

# Main
case "${1:-help}" in
    help|-h|--help)   usage ;;
    upload)           upload_build "$2" "$3" "$4" "$5" ;;
    link)             create_link "$2" "$3" "$4" "$5" ;;
    builds)           list_builds ;;
    links)            list_links "$2" ;;
    reset)            reset_link "$2" ;;
    revoke)           revoke_link "$2" ;;
    delete-build)     delete_build "$2" ;;
    share)            share_file "$2" "$3" "$4" ;;
    share-link)       share_link "$2" "$3" "$4" ;;
    shared-files)     list_shared_files ;;
    delete-shared)    delete_shared "$2" ;;
    status)           show_status ;;
    *)                echo "Unknown command: $1"; echo; usage; exit 1 ;;
esac
