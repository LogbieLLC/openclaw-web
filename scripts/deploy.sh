#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/home/bsbyrd/.openclaw/workspace/openclaw-web"
SERVICE_NAME="openclaw-web.service"
USER_SYSTEMD_DIR="$HOME/.config/systemd/user"

cd "$APP_DIR"

echo "[1/5] Installing dependencies..."
npm install

echo "[2/5] Running tests..."
npm test

echo "[3/5] Installing/refreshing user service..."
mkdir -p "$USER_SYSTEMD_DIR"
cp "$APP_DIR/deploy/$SERVICE_NAME" "$USER_SYSTEMD_DIR/$SERVICE_NAME"

echo "[4/5] Reloading systemd and enabling service..."
systemctl --user daemon-reload
systemctl --user enable "$SERVICE_NAME"

echo "[5/5] Restarting service..."
systemctl --user restart "$SERVICE_NAME"

echo "Done. Service status:"
systemctl --user --no-pager --full status "$SERVICE_NAME" || true

echo "\nRedeploy complete."
