#!/bin/bash
# ==============================================================================
# OPTOX SHIELD — STAGING DEPLOYMENT SCRIPT (13.126.90.199 & 13.126.7.100)
# ==============================================================================
set -e

echo "=========================================================="
echo "  OPTOX SHIELD — DEPLOYING STAGING ENVIRONMENT"
echo "=========================================================="

sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-venv sqlite3 nginx curl nodejs npm

# Copy Staging Environment configuration
if [ -d "PBX_ml_frontend" ]; then
    cp PBX_ml_frontend/.env.staging PBX_ml_frontend/.env
fi

# 2. Enable Asterisk PJSIP Live Logger
echo "[+] Ensuring Asterisk PJSIP logger is active..."
if command -v asterisk &> /dev/null; then
    sudo asterisk -rx "pjsip set logger on" || true
fi

# 3. Configure Nginx with WebSocket Upgrade headers for Socket.IO
echo "[+] Configuring Nginx Reverse Proxy with WebSocket support..."
sudo tee /etc/nginx/sites-available/optox-staging > /dev/null << 'EOF'
server {
    listen 80;
    server_name _;

    location /socket.io/ {
        proxy_pass http://127.0.0.1:5000/socket.io/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/optox-staging /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx || true

# 4. Configure Systemd Staging Backend Service
echo "[+] Configuring Optox Staging Backend Service..."
sudo cat << 'EOF' | sudo tee /etc/systemd/system/optox-backend.service
[Unit]
Description=Optox Shield AI Security Engine (Staging Backend)
After=network.target asterisk.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/PBX_ml_backend
ExecStart=/home/ubuntu/PBX_ml_backend/venv/bin/python src/monitor.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1
Environment=ENVIRONMENT=staging
Environment=PORT=5000
Environment=HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable optox-backend
sudo systemctl restart optox-backend

echo "=========================================================="
echo "  ✅ STAGING DEPLOYMENT COMPLETE (WebSockets & Telemetry Live)"
echo "=========================================================="
