#!/bin/bash
# pvefw-neo uninstall script
# Usage: bash uninstall.sh
set -e

INSTALL_DIR="/usr/local/lib/pvefw_neo"

echo "═══ pvefw-neo uninstall ═══"

# ── 1. Stop and disable service ──
if systemctl is-active pvefw-neo.service &>/dev/null; then
    echo "[+] Stopping pvefw-neo service..."
    systemctl stop pvefw-neo.service
fi
systemctl disable pvefw-neo.service 2>/dev/null || true

# ── 2. Flush nftables rules ──
if [ -x /usr/local/bin/pvefw-neo ]; then
    echo "[+] Flushing nftables rules..."
    /usr/local/bin/pvefw-neo --flush 2>/dev/null || true
fi

# ── 3. Remove symlinks ──
echo "[+] Removing symlinks..."
rm -f /usr/local/bin/pvefw-neo
rm -f /etc/systemd/system/pvefw-neo.service
systemctl daemon-reload

# ── 4. Remove install directory ──
if [ -L "$INSTALL_DIR" ]; then
    echo "[+] Removing symlink $INSTALL_DIR (dev mode, source not deleted)"
    rm -f "$INSTALL_DIR"
elif [ -d "$INSTALL_DIR" ]; then
    echo "[+] Removing $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
fi

# ── 5. Clean runtime ──
rm -rf /run/pvefw-neo

echo ""
echo "═══ Uninstall complete ═══"
echo "  Note: /etc/pve/firewall/*.fw files are NOT removed."
echo "  Note: python3-nftables and python3-inotify are NOT removed."
