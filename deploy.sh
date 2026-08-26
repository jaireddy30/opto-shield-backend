#!/bin/bash
# ==============================================================================
# OPTOX SHIELD — PRODUCTION AUTOMATED DEPLOYMENT SCRIPT
# ==============================================================================
set -e

echo "=========================================================="
echo "  OPTOX SHIELD — STARTING PRODUCTION DEPLOYMENT"
echo "=========================================================="

# 1. Update system & install prerequisites
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip python3-venv sqlite3 nginx curl nodejs npm

# 2. Setup Systemd Backend Service
echo "[+] Configuring Optox Backend Systemd Service..."
sudo cat << 'EOF' | sudo tee /etc/systemd/system/optox-backend.service
[Unit]
Description=Optox Shield AI Security & Telemetry Engine (Backend)
After=network.target asterisk.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/PBX_ml_backend
ExecStart=/home/ubuntu/PBX_ml_backend/venv/bin/python src/monitor.py
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# 3. Setup Systemd Frontend Service
echo "[+] Configuring Optox Frontend Systemd Service..."
sudo cat << 'EOF' | sudo tee /etc/systemd/system/optox-frontend.service
[Unit]
Description=Optox Shield SOC Console (Frontend)
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/PBX_ml_frontend
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# 4. Enable and Restart Services
sudo systemctl daemon-reload
sudo systemctl enable optox-backend.service
sudo systemctl enable optox-frontend.service

sudo systemctl restart optox-backend.service
sudo systemctl restart optox-frontend.service

echo "=========================================================="
echo "  ✅ OPTOX SHIELD DEPLOYMENT COMPLETE!"
echo "  [+] Production HTTPS Console: https://app.optoxcrm.com"
echo "  [+] Direct Frontend Port:     http://$(curl -s ifconfig.me):9000"
echo "  [+] Direct Backend Port:      http://$(curl -s ifconfig.me):5000"
echo "  [+] Database:                 SQLite (optox_events.db)"
echo "=========================================================="
