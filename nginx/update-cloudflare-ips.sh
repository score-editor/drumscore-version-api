#!/bin/sh
set -e

CONF_FILE="/data/cloudflare-ips.conf"
TMP_FILE="/tmp/cloudflare-ips.conf.tmp"

echo "# Auto-generated Cloudflare IP ranges - $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$TMP_FILE"
echo "geo \$is_cloudflare {" >> "$TMP_FILE"
echo "    default 0;" >> "$TMP_FILE"

# Fetch IPv4 ranges
for ip in $(wget -qO- https://www.cloudflare.com/ips-v4); do
    echo "    $ip 1;" >> "$TMP_FILE"
done

# Fetch IPv6 ranges
for ip in $(wget -qO- https://www.cloudflare.com/ips-v6); do
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
