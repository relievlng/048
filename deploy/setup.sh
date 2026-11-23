#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Void bots - VPS setup script (Ubuntu / Debian).
# Installs system deps, a Python venv, the code, env templates and the
# systemd services. Safe to re-run: it updates in place and never overwrites
# an env file you have already edited.
#
# Usage:
#   sudo bash deploy/setup.sh
#   # then edit /opt/voidbots/env/*.env with your tokens and IDs
#   # then: sudo systemctl enable --now voidbot-main voidbot-void voidbot-customer voidbot-staff
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

APP_DIR=/opt/voidbots
APP_USER=voidbots
REPO_URL="${REPO_URL:-https://github.com/relievlng/048.git}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this with sudo: sudo bash deploy/setup.sh" >&2
  exit 1
fi

echo "==> Installing system packages"
apt-get update -y
# libcairo2 is required by cairosvg (emoji rendering).
apt-get install -y python3 python3-venv python3-pip git libcairo2

echo "==> Creating service user and directories"
id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR" "$APP_DIR/data" "$APP_DIR/env"

echo "==> Fetching code into $APP_DIR"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" pull --ff-only
else
  # If the repo is private, clone it yourself first, or scp the files up,
  # then re-run this script. A non-empty non-git dir is left untouched.
  if [ -z "$(ls -A "$APP_DIR" 2>/dev/null | grep -v '^\(data\|env\)$' || true)" ]; then
    git clone "$REPO_URL" "$APP_DIR" || {
      echo "Clone failed (private repo?). Copy the files into $APP_DIR and re-run." >&2
      exit 1
    }
  fi
fi

echo "==> Python virtualenv + dependencies"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

echo "==> Installing env templates (existing ones are kept)"
for b in main customer staff void; do
  if [ ! -f "$APP_DIR/env/$b.env" ]; then
    cp "$APP_DIR/deploy/env/$b.env.example" "$APP_DIR/env/$b.env"
    echo "   created env/$b.env (fill it in)"
  fi
done

echo "==> Permissions"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
chmod 600 "$APP_DIR"/env/*.env

echo "==> Installing systemd services"
cp "$APP_DIR"/deploy/systemd/voidbot-*.service /etc/systemd/system/
systemctl daemon-reload

cat <<'DONE'

Setup complete.

NEXT STEPS
  1. Put your old database in place (keep your license data):
       cp /path/to/your/keylock.db /opt/voidbots/data/keylock.db
       chown voidbots:voidbots /opt/voidbots/data/keylock.db
  2. Edit each env file with your tokens and IDs:
       sudo nano /opt/voidbots/env/main.env
       sudo nano /opt/voidbots/env/customer.env
       sudo nano /opt/voidbots/env/staff.env
       sudo nano /opt/voidbots/env/void.env
     Use the SAME INTERNAL_API_KEY in customer, staff and void.
  3. Start everything on boot:
       sudo systemctl enable --now voidbot-main voidbot-void voidbot-customer voidbot-staff
  4. Watch the logs:
       journalctl -u voidbot-customer -f
DONE
