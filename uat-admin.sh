#!/bin/bash
#
# UAT Admin Tool for Drum Score Editor
# Manages builds and download links on droid1
#

HOST="${UAT_HOST:-https://droid1.local}"
CURL="curl -sk"

if [ -z "$ADMIN_SECRET" ]; then
    echo "Error: ADMIN_SECRET not set. Run: export ADMIN_SECRET=<your-secret>"
    echo "Hint: SSH to droid1 and 'cat .env' if you've forgotten it"
    exit 1
fi

AUTH="Authorization: Bearer $ADMIN_SECRET"

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

    local size=$(du -h "$file" | cut -f1)
    echo "Uploading $file ($size) as $version/$platform/$arch..."
    echo

    local response
    response=$($CURL -X POST "$HOST/api/admin/uat-builds" \
        -H "$AUTH" \
        -F "file=@$file" \
        -F "version=$version" \
        -F "platform=$platform" \
        -F "arch=$arch")

    if echo "$response" | python3 -c "import sys,json; json.load(sys.stdin)['id']" >/dev/null 2>&1; then
        echo "$response" | python3 -c "
import sys, json
b = json.load(sys.stdin)
print(f\"  Build uploaded successfully\")
print(f\"  ID:       {b['id']}\")
print(f\"  Version:  {b['version']}\")
print(f\"  Platform: {b['platform']}/{b['arch']}\")
print(f\"  Size:     {b['fileSize'] / 1048576:.1f} MB\")
"
    else
        echo "Error: $response"
    fi
}

create_link() {
    local name="$1" version="$2" platform="$3" arch="$4"
    if [ -z "$name" ] || [ -z "$version" ] || [ -z "$platform" ] || [ -z "$arch" ]; then
        echo "Usage: uat-admin.sh link <name> <version> <platform> <arch>"
        exit 1
    fi

    local response
    response=$($CURL -X POST "$HOST/api/admin/uat-links" \
        -H "$AUTH" \
        -H "Content-Type: application/json" \
        -d "{\"issuedTo\":\"$name\",\"version\":\"$version\",\"platform\":\"$platform\",\"arch\":\"$arch\"}")

    if echo "$response" | python3 -c "import sys,json; json.load(sys.stdin)['token']" >/dev/null 2>&1; then
        echo "$response" | python3 -c "
import sys, json
l = json.load(sys.stdin)
print(f\"  Link created for {l['issuedTo']}\")
print(f\"  Version:  {l['version']} ({l['platform']}/{l['arch']})\")
print(f\"  Uses:     {l['maxUses']}\")
print(f\"  Expires:  {l['expiresAt']}\")
print()
print(f\"  Send this link:\")
print(f\"  {l['downloadLink']}\")
"
    else
        echo "Error: $response"
    fi
}

list_builds() {
    local response
    response=$($CURL "$HOST/api/admin/uat-builds" -H "$AUTH")

    echo "$response" | python3 -c "
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
    local response
    response=$($CURL "$HOST/api/admin/uat-links?status=$status" -H "$AUTH")

    echo "$response" | python3 -c "
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

    local response
    response=$($CURL -X PATCH "$HOST/api/admin/uat-links/$token" -H "$AUTH")

    if echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='reset'" 2>/dev/null; then
        echo "  Download count reset: ${token:0:16}..."
    else
        echo "Error: $response"
    fi
}

revoke_link() {
    local token="$1"
    if [ -z "$token" ]; then
        echo "Usage: uat-admin.sh revoke <token>"
        exit 1
    fi

    local response
    response=$($CURL -X DELETE "$HOST/api/admin/uat-links/$token" -H "$AUTH")

    if echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='revoked'" 2>/dev/null; then
        echo "  Link revoked: ${token:0:16}..."
    else
        echo "Error: $response"
    fi
}

delete_build() {
    local id="$1"
    if [ -z "$id" ]; then
        echo "Usage: uat-admin.sh delete-build <id>"
        exit 1
    fi

    local response
    response=$($CURL -X DELETE "$HOST/api/admin/uat-builds/$id" -H "$AUTH")

    if echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='deleted'" 2>/dev/null; then
        echo "  Build $id deleted."
    else
        echo "Error: $response"
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

    local size=$(du -h "$file" | cut -f1)
    echo "Uploading $file ($size)..."
    echo

    # Upload the file
    local upload_response
    upload_response=$($CURL -X POST "$HOST/api/admin/shared-files" \
        -H "$AUTH" \
        -F "file=@$file" \
        -F "description=$description")

    local file_id
    file_id=$(echo "$upload_response" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)
    if [ -z "$file_id" ]; then
        echo "Error uploading file: $upload_response"
        exit 1
    fi

    # Create a download link (3 uses to allow for link preview bots)
    local link_response
    link_response=$($CURL -X POST "$HOST/api/admin/uat-links" \
        -H "$AUTH" \
        -H "Content-Type: application/json" \
        -d "{\"issuedTo\":\"$name\",\"sharedFileId\":$file_id,\"maxUses\":3}")

    if echo "$link_response" | python3 -c "import sys,json; json.load(sys.stdin)['token']" >/dev/null 2>&1; then
        echo "$link_response" | python3 -c "
import sys, json
l = json.load(sys.stdin)
print(f'  File shared with {l[\"issuedTo\"]}')
print(f'  Uses:     {l[\"maxUses\"]}')
print(f'  Expires:  {l[\"expiresAt\"]}')
print()
print(f'  Send this link:')
print(f'  {l[\"downloadLink\"]}')
"
    else
        echo "Error creating link: $link_response"
    fi
}

share_link() {
    local name="$1" file_id="$2" max_uses="${3:-1}"
    if [ -z "$name" ] || [ -z "$file_id" ]; then
        echo "Usage: uat-admin.sh share-link <name> <file-id> [maxUses]"
        exit 1
    fi

    local response
    response=$($CURL -X POST "$HOST/api/admin/uat-links" \
        -H "$AUTH" \
        -H "Content-Type: application/json" \
        -d "{\"issuedTo\":\"$name\",\"sharedFileId\":$file_id,\"maxUses\":$max_uses}")

    if echo "$response" | python3 -c "import sys,json; json.load(sys.stdin)['token']" >/dev/null 2>&1; then
        echo "$response" | python3 -c "
import sys, json
l = json.load(sys.stdin)
print(f'  Link created for {l[\"issuedTo\"]}')
print(f'  Uses:     {l[\"maxUses\"]}')
print(f'  Expires:  {l[\"expiresAt\"]}')
print()
print(f'  Send this link:')
print(f'  {l[\"downloadLink\"]}')
"
    else
        echo "Error: $response"
    fi
}

list_shared_files() {
    local response
    response=$($CURL "$HOST/api/admin/shared-files" -H "$AUTH")

    echo "$response" | python3 -c "
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

    local response
    response=$($CURL -X DELETE "$HOST/api/admin/shared-files/$id" -H "$AUTH")

    if echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status')=='deleted'" 2>/dev/null; then
        echo "  Shared file $id deleted."
    else
        echo "Error: $response"
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
