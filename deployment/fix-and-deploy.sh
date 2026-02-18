#!/bin/bash

# Grounded - Fixed Deployment Script for Lightsail
# Handles existing database tables

set -e

echo "=================================="
echo "Grounded Deployment (Fixed)"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${GREEN}Step 1: Fixing database migration state...${NC}"
export PGPASSWORD=grounded2024
psql -h localhost -U grounded -d grounded -c "DELETE FROM alembic_version;" 2>/dev/null || true
psql -h localhost -U grounded -d grounded -c "INSERT INTO alembic_version (version_num) VALUES ('004_add_strategy_plans');" 2>/dev/null || true

echo -e "${GREEN}Step 2: Installing Caddy web server...${NC}"
apt install -y debian-keyring debian-archive-keyring apt-transport-https curl > /dev/null 2>&1
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' 2>/dev/null | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' 2>/dev/null | tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
apt update -qq
apt install -y caddy > /dev/null 2>&1

echo -e "${GREEN}Step 3: Configuring Caddy...${NC}"
cat > /etc/caddy/Caddyfile << 'EOF'
{
    admin off
}

:80 {
    handle /health {
        reverse_proxy localhost:8000
    }

    handle {
        reverse_proxy localhost:8000 {
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    header {
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    log {
        output file /var/log/caddy/access.log
        format json
    }
}
EOF

systemctl enable caddy > /dev/null 2>&1
systemctl restart caddy

echo -e "${GREEN}Step 4: Creating systemd service...${NC}"
cat > /etc/systemd/system/grounded.service << 'EOF'
[Unit]
Description=Grounded FastAPI Application
After=network.target postgresql.service

[Service]
Type=simple
User=deployer
Group=deployer
WorkingDirectory=/opt/grounded/app
EnvironmentFile=/etc/grounded/.env
ExecStart=/opt/grounded/app/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2 --log-level info
Restart=always
RestartSec=10
StandardOutput=append:/var/log/grounded/app.log
StandardError=append:/var/log/grounded/error.log
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/grounded/data /var/log/grounded

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable grounded > /dev/null 2>&1
systemctl restart grounded

echo -e "${GREEN}Step 5: Configuring firewall...${NC}"
ufw --force enable > /dev/null 2>&1
ufw allow 22/tcp > /dev/null 2>&1
ufw allow 80/tcp > /dev/null 2>&1
ufw allow 443/tcp > /dev/null 2>&1
ufw reload > /dev/null 2>&1

echo ""
echo -e "${GREEN}=================================="
echo "Deployment Complete! ✅"
echo "==================================${NC}"
echo ""
echo "Your Grounded application is now running!"
echo ""
echo -e "${YELLOW}Access your application:${NC}"
echo "  http://$(curl -s ifconfig.me 2>/dev/null)"
echo ""
echo -e "${YELLOW}Service commands:${NC}"
echo "  Status:  sudo systemctl status grounded"
echo "  Logs:    sudo journalctl -u grounded -f"
echo "  Restart: sudo systemctl restart grounded"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT - Update your OpenAI API key:${NC}"
echo "  sudo nano /etc/grounded/.env"
echo "  Then restart: sudo systemctl restart grounded"
echo ""
echo -e "${YELLOW}Create your first admin user:${NC}"
echo "  Visit: http://$(curl -s ifconfig.me 2>/dev/null)/register"
echo ""
echo -e "${GREEN}✅ Deployment successful!${NC}"
