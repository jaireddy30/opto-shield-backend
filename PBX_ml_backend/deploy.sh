#!/usr/bin/env bash
# PBX Shield — Full EC2 Deploy & Restart Script
# Run this script from your local machine to update and restart the monitor in one shot.
# Usage: bash deploy.sh

set -e

EC2_HOST="ubuntu@13.126.90.199"
SSH_KEY="$HOME/.ssh/id_rsa.pem"
SSH_OPTS="-o StrictHostKeyChecking=no -i $SSH_KEY"

echo "======================================================"
echo "  PBX SHIELD — One-Shot Deploy & Restart"
echo "======================================================"

ssh $SSH_OPTS $EC2_HOST << 'REMOTE'
set -e

echo "[1/4] Pulling latest code from GitHub..."
cd ~/PBX_ml
git pull origin main

echo "[2/4] Installing/updating Python dependencies..."
venv/bin/pip install -r requirements.txt -q

echo "[3/4] Stopping any existing monitor process..."
pkill -f "python src/monitor.py" || true
sleep 2

echo "[4/4] Starting PBX Shield monitor in background..."
nohup venv/bin/python src/monitor.py > monitor.log 2>&1 &
MONITOR_PID=$!
echo "  Monitor started with PID=$MONITOR_PID"

sleep 3
echo ""
echo "======================================================"
echo "  STARTUP LOG (last 20 lines):"
echo "======================================================"
tail -20 monitor.log

echo ""
echo "======================================================"
echo "  DONE! Dashboard is live at: http://13.126.90.199:5000"
echo "======================================================"
REMOTE
