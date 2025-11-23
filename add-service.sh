#!/bin/bash

# Script to add a new service subdomain to the drumscore infrastructure
# Usage: ./add-service.sh <service-name> <container-port>
# Example: ./add-service.sh license 8081

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <service-name> <container-port>"
    echo "Example: $0 license 8081"
    exit 1
fi

SERVICE_NAME=$1
CONTAINER_PORT=$2
DOMAIN="${SERVICE_NAME}.drumscore.scot"
EMAIL="alan@drumscore.scot"

echo "==================================="
echo "Adding New Service: $SERVICE_NAME"
echo "==================================="
echo ""
echo "Domain: $DOMAIN"
echo "Container Port: $CONTAINER_PORT"
echo ""

# Step 1: DNS Configuration
echo "Step 1: DNS Configuration"
echo "-------------------------"
echo "Add these DNS records:"
echo "  A record:    $DOMAIN -> 51.148.180.134"
echo "  AAAA record: $DOMAIN -> 2a02:8010:6979:0::10"
echo ""
read -p "DNS records added? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Please add DNS records first"
    exit 1
fi

# Step 2: Request Let's Encrypt Certificate
echo ""
echo "Step 2: Requesting Let's Encrypt Certificate"
echo "--------------------------------------------"

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
    -d "$DOMAIN"

if [ $? -ne 0 ]; then
    echo "✗ Certificate request failed"
    exit 1
fi

echo "✓ Certificate obtained for $DOMAIN"

# Step 3: Generate Nginx Configuration
echo ""
echo "Step 3: Generating Nginx Configuration"
echo "--------------------------------------"

cat >> nginx/services.conf.template << EOF

# ${SERVICE_NAME^} Service
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    limit_req zone=api_limit burst=20 nodelay;
    limit_conn conn_limit 10;
    
    limit_req_status 429;
    limit_conn_status 429;

    location /api/ {
        proxy_pass http://${SERVICE_NAME}-service:${CONTAINER_PORT};
        proxy_http_version 1.1;
        
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
        
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type' always;
        
        if (\$request_method = 'OPTIONS') {
            return 204;
        }
    }

    location /health {
        proxy_pass http://${SERVICE_NAME}-service:${CONTAINER_PORT}/health;
        access_log off;
    }

    location / {
        return 404;
    }
}
EOF

echo "✓ Nginx configuration template created at nginx/services.conf.template"

# Step 4: Docker Compose Service Template
echo ""
echo "Step 4: Docker Compose Service Template"
echo "---------------------------------------"

cat >> docker-compose.services.template << EOF

  ${SERVICE_NAME}-service:
    build:
      context: ./${SERVICE_NAME}-service
      dockerfile: Dockerfile
    container_name: ${SERVICE_NAME}-service
    restart: unless-stopped
    volumes:
      - ./${SERVICE_NAME}-service/config:/app/config:ro
    environment:
      - SERVICE_PORT=${CONTAINER_PORT}
    networks:
      - version-api-network
    expose:
      - "${CONTAINER_PORT}"
EOF

echo "✓ Docker Compose service template created"

# Step 5: Instructions
echo ""
echo "==================================="
echo "Service Setup Complete!"
echo "==================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Add the nginx configuration to nginx/nginx.conf:"
echo "   cat nginx/services.conf.template >> nginx/nginx.conf"
echo ""
echo "2. Add the service to docker-compose.yml:"
echo "   cat docker-compose.services.template >> docker-compose.yml"
echo ""
echo "3. Create the service directory:"
echo "   mkdir -p ${SERVICE_NAME}-service"
echo ""
echo "4. Implement your ${SERVICE_NAME} service in ${SERVICE_NAME}-service/"
echo ""
echo "5. Restart nginx to apply changes:"
echo "   docker compose restart nginx"
echo ""
echo "6. Start the new service:"
echo "   docker compose up -d ${SERVICE_NAME}-service"
echo ""
echo "Your service will be available at:"
echo "  https://$DOMAIN/api/"
echo ""
