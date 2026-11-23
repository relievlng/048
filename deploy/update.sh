#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Void bots - pull the latest code and restart every bot.
# Run on the VPS after new changes are pushed to GitHub:
#   sudo bash /opt/voidbots/deploy/update.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

APP_DIR=/opt/voidbots
APP_USER=voidbots
SERVICES="voidbot-main voidbot-void voidbot-customer voidbot-staff"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo bash /opt/voidbots/deploy/update.sh" >&2
  exit 1
fi

# Avoid git "dubious ownership" by pulling as the owning user.
git config --global --add safe.directory "$APP_DIR" 2>/dev/null || true

echo "==> Pulling latest code"
sudo -u "$APP_USER" git -C "$APP_DIR" pull --ff-only

echo "==> Updating dependencies (if requirements changed)"
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "==> Restarting bots"
systemctl restart $SERVICES

echo "==> Done. Status:"
systemctl --no-pager --lines=0 status $SERVICES | grep -E "voidbot|Active:" || true
echo "Tail a bot:  journalctl -u voidbot-customer -f"
