#!/bin/bash
# pvefw-neo upgrade script
# Usage: bash upgrade.sh
set -e

INSTALL_DIR="/usr/local/lib/pvefw_neo"

echo "═══ pvefw-neo upgrade ═══"

if [ ! -d "$INSTALL_DIR" ]; then
    echo "ERROR: $INSTALL_DIR not found. Run install.sh first."
    exit 1
fi

# Check if it's a symlink (dev mode) or real git repo
if [ -L "$INSTALL_DIR" ]; then
    REAL_DIR=$(readlink -f "$INSTALL_DIR")
    echo "[=] Dev mode: $INSTALL_DIR → $REAL_DIR"
    echo "[=] Pull from real directory"
    cd "$REAL_DIR"
else
    cd "$INSTALL_DIR"
fi

if [ -d .git ]; then
    echo "[+] git pull..."
    git pull
else
    echo "[=] Not a git repo, skipping pull"
fi

# Reload systemd in case service file changed
systemctl daemon-reload

# Restart daemon if running
if systemctl is-active pvefw-neo.service &>/dev/null; then
    echo "[+] Restarting pvefw-neo daemon..."
    systemctl restart pvefw-neo.service
fi

echo ""
echo "═══ Upgrade complete ═══"
