#!/usr/bin/env bash
# ==============================================================================
# OPTOX SHIELD — Production Backend 1-Click Setup & Installer
# Run this directly on your Asterisk PBX server: bash setup_production.sh
# ==============================================================================

set -e

echo "======================================================================"
echo "  🚀 OPTOX SHIELD — Setting up Production Backend on $(hostname)"
echo "======================================================================"

# 1. Update system packages & install python3-venv if missing
echo "[1/5] Checking system prerequisites..."
sudo apt-get update -y -q
sudo apt-get install -y -q python3 python3-pip python3-venv git

# 2. Setup Virtual Environment
echo "[2/5] Setting up Python virtual environment..."
cd "$(dirname "$0")"
python3 -m venv venv
venv/bin/pip install --upgrade pip -q
venv/bin/pip install -r requirements.txt -q

# 3. Enable Asterisk PJSIP Logger
echo "[3/5] Enabling Asterisk PJSIP Live Logger..."
if command -v asterisk &> /dev/null; then
    sudo asterisk -rx "pjsip set logger on" || true
    echo "  ✅ Asterisk PJSIP logger enabled."
else
    echo "  ⚠️ Asterisk command not found directly in path. Ensure Asterisk is running."
fi

# 4. Configure Nginx with WebSocket Upgrade headers for Socket.IO
if command -v nginx &> /dev/null; then
    echo "[4/6] Configuring Nginx WebSocket Reverse Proxy..."
    sudo tee /etc/nginx/sites-available/optox-shield > /dev/null << 'EOF'
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
    sudo ln -sf /etc/nginx/sites-available/optox-shield /etc/nginx/sites-enabled/
    sudo nginx -t && sudo systemctl reload nginx || true
fi

# 5. Install Systemd Service (Keeps Backend Alive 24/7)
echo "[5/6] Installing optox-backend Systemd Service..."
INSTALL_DIR=$(pwd)
PYTHON_EXEC="$INSTALL_DIR/venv/bin/python"

sudo tee /etc/systemd/system/optox-backend.service > /dev/null <<EOF
[Unit]
Description=Optox Shield AI Security & Telemetry Engine (Backend)
After=network.target asterisk.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON_EXEC src/monitor.py
Restart=always
RestartSec=5
Environment=PORT=5000
Environment=HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
EOF

# 6. Start and Enable Service
echo "[6/6] Starting optox-backend service..."
sudo systemctl daemon-reload
sudo systemctl enable --now optox-backend
sleep 2
sudo systemctl status optox-backend --no-pager

echo ""
echo "======================================================================"
echo "  🎉 OPTOX SHIELD BACKEND IS LIVE & MONITORING!"
echo "  Telemetry API: http://$(curl -s https://ifconfig.me 2>/dev/null || echo '0.0.0.0'):5000"
echo "======================================================================"
