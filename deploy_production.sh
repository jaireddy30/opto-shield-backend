#!/bin/bash
# ==============================================================================
# OPTOX SHIELD — PRODUCTION AUTOMATED DEPLOYMENT SCRIPT (app.optoxcrm.com)
# ==============================================================================
set -e

echo "=========================================================="
echo "  OPTOX SHIELD — DEPLOYING PRODUCTION ENVIRONMENT (app.optoxcrm.com)"
echo "=========================================================="

sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-venv sqlite3 nginx curl nodejs npm

# 1. Copy Production Environment configuration
if [ -d "PBX_ml_frontend" ]; then
    cp PBX_ml_frontend/.env.production PBX_ml_frontend/.env
fi

# 2. Configure Systemd Production Backend Service
echo "[+] Configuring Optox Production Backend Service..."
sudo cat << 'EOF' | sudo tee /etc/systemd/system/optox-backend.service
[Unit]
Description=Optox Shield AI Security & Telemetry Engine (Production Backend)
After=network.target asterisk.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/opto-pbx-shield/PBX_ml_backend
ExecStart=/home/ubuntu/opto-pbx-shield/PBX_ml_backend/venv/bin/python src/monitor.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1
Environment=ENVIRONMENT=production

[Install]
WantedBy=multi-user.target
EOF

# 3. Configure Nginx Reverse Proxy for app.optoxcrm.com
echo "[+] Configuring Production Nginx Reverse Proxy (HTTPS / Port 443)..."
if [ -f "nginx-production.conf" ]; then
    sudo cp nginx-production.conf /etc/nginx/sites-available/app.optoxcrm.conf
    sudo ln -sf /etc/nginx/sites-available/app.optoxcrm.conf /etc/nginx/sites-enabled/default
fi

# 4. Reload services
sudo systemctl daemon-reload
sudo systemctl enable optox-backend
sudo systemctl restart optox-backend
sudo nginx -t && sudo systemctl reload nginx

echo "=========================================================="
echo "  ✅ PRODUCTION DEPLOYMENT COMPLETE (app.optoxcrm.com)"
echo "=========================================================="
