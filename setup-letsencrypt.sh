#!/bin/bash

# Setup script for Let's Encrypt certificates
# Run this ONCE after DNS is configured and port forwarding is set up

set -e

DOMAIN="version.drumscore.scot"
EMAIL="alan@drumscore.scot"
STAGING=0  # Set to 1 for testing, 0 for production

echo "==================================="
echo "Let's Encrypt Certificate Setup"
echo "==================================="
echo ""
echo "Domain: $DOMAIN"
echo "Email: $EMAIL"
echo ""

# Check if certificates already exist
if [ -d "./letsencrypt/live/$DOMAIN" ]; then
    echo "⚠️  Certificates already exist for $DOMAIN"
    echo ""
    read -p "Do you want to renew them? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting..."
        exit 0
    fi
fi

# Create necessary directories
mkdir -p letsencrypt/www

echo ""
echo "Prerequisites check:"
echo "1. ✓ DNS A record: $DOMAIN -> your static IP"
echo "2. ✓ Port forwarding: 80, 443 -> Odroid M1"
echo "3. ✓ Docker and Docker Compose installed"
echo ""
read -p "All prerequisites met? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Please complete prerequisites first"
    exit 1
fi

echo ""
echo "Starting certificate request..."
echo ""

# Determine staging flag
STAGING_FLAG=""
if [ $STAGING -eq 1 ]; then
    STAGING_FLAG="--staging"
    echo "⚠️  Running in STAGING mode (test certificates)"
fi

# Run certbot in standalone mode
docker run -it --rm \
    -v "$(pwd)/letsencrypt:/etc/letsencrypt" \
    -v "$(pwd)/letsencrypt/www:/var/www/certbot" \
    -p 80:80 \
    certbot/certbot certonly \
    --standalone \
    --preferred-challenges http \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    $STAGING_FLAG \
    -d "$DOMAIN"

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Certificate obtained successfully!"
    echo ""
    echo "Certificate location: ./letsencrypt/live/$DOMAIN/"
    echo ""
    echo "Next steps:"
    echo "1. Start the services: docker-compose up -d"
    echo "2. Check logs: docker-compose logs -f"
    echo "3. Test endpoint: curl https://$DOMAIN/api/version"
    echo ""
    echo "Certificates will auto-renew via the certbot container"
else
    echo ""
    echo "✗ Certificate request failed"
    echo ""
    echo "Common issues:"
    echo "- DNS not propagated yet (wait 5-10 minutes)"
    echo "- Port 80 not forwarded correctly"
    echo "- Firewall blocking port 80"
    echo ""
    echo "You can test with staging certificates by editing this script:"
    echo "Set STAGING=1 at the top"
fi
