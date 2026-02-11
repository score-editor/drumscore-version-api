#!/bin/sh
set -e

CONF_FILE="/data/cloudflare-ips.conf"
TMP_FILE="/tmp/cloudflare-ips.conf.tmp"

# Fetch IP ranges first - abort if either fetch fails
IPV4=$(wget -qO- https://www.cloudflare.com/ips-v4) || { echo "ERROR: Failed to fetch Cloudflare IPv4 ranges"; exit 1; }
IPV6=$(wget -qO- https://www.cloudflare.com/ips-v6) || { echo "ERROR: Failed to fetch Cloudflare IPv6 ranges"; exit 1; }

# Validate we got actual data (expect at least 10 IPv4 ranges)
IPV4_COUNT=$(echo "$IPV4" | wc -l)
if [ "$IPV4_COUNT" -lt 10 ]; then
    echo "ERROR: Only got $IPV4_COUNT IPv4 ranges (expected 10+), aborting"
    exit 1
fi

echo "# Auto-generated Cloudflare IP ranges - $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$TMP_FILE"
echo "geo \$is_cloudflare {" >> "$TMP_FILE"
echo "    default 0;" >> "$TMP_FILE"

for ip in $IPV4; do
    echo "    $ip 1;" >> "$TMP_FILE"
done

for ip in $IPV6; do
    echo "    $ip 1;" >> "$TMP_FILE"
done

echo "}" >> "$TMP_FILE"

# Check if file changed
if [ -f "$CONF_FILE" ] && cmp -s "$TMP_FILE" "$CONF_FILE"; then
    echo "Cloudflare IPs unchanged"
    rm "$TMP_FILE"
else
    echo "Cloudflare IPs updated, reloading nginx"
    cat "$TMP_FILE" > "$CONF_FILE"
    rm "$TMP_FILE"
    # Signal nginx to reload (if nginx container is running)
    if [ -n "$NGINX_CONTAINER" ]; then
        docker kill -s HUP "$NGINX_CONTAINER" 2>/dev/null || true
    fi
fi
