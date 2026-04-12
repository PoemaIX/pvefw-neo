#!/bin/bash
# pvefw-neo install script
# Usage: bash install.sh
set -e

INSTALL_DIR="/usr/local/lib/pvefw_neo"
REPO_URL="https://github.com/PoemaIX/pvefw-neo.git"

echo "═══ pvefw-neo install ═══"

# ── 1. Dependencies ──
echo "[+] Installing dependencies..."
apt install -y python3-nftables python3-inotify

# ── 2. Clone or link ──
if [ -d "$INSTALL_DIR" ]; then
    echo "[=] $INSTALL_DIR already exists, skipping clone"
else
    if [ -n "$DEV_LINK" ]; then
        # Development mode: symlink instead of clone
        echo "[+] DEV_LINK mode: linking $DEV_LINK → $INSTALL_DIR"
        ln -sfn "$DEV_LINK" "$INSTALL_DIR"
    else
        echo "[+] Cloning $REPO_URL → $INSTALL_DIR"
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
fi

# ── 3. Launcher symlink ──
echo "[+] Linking launcher → /usr/local/bin/pvefw-neo"
ln -sfn "$INSTALL_DIR/pvefw-neo" /usr/local/bin/pvefw-neo
chmod +x "$INSTALL_DIR/pvefw-neo"

# ── 4. systemd service ──
echo "[+] Linking systemd service"
ln -sfn "$INSTALL_DIR/pvefw-neo.service" /etc/systemd/system/pvefw-neo.service
systemctl daemon-reload

# ── 5. Runtime directory ──
mkdir -p /run/pvefw-neo

# ── 6. Verify ──
echo "[+] Verifying..."
pvefw-neo --dry-run >/dev/null 2>&1 && echo "[+] pvefw-neo --dry-run OK" || echo "[!] pvefw-neo --dry-run failed (may be normal if no .fw files have enable:1)"

echo ""
echo "═══ Install complete ═══"
echo "  Installed to: $INSTALL_DIR"
echo "  Launcher:     /usr/local/bin/pvefw-neo"
echo "  Service:      /etc/systemd/system/pvefw-neo.service"
echo ""
echo "Usage:"
echo "  pvefw-neo --dry-run          # Preview generated nftables rules"
echo "  pvefw-neo --dump-ir          # Show intermediate representation"
echo "  pvefw-neo --apply            # Apply rules once"
echo "  systemctl start pvefw-neo    # Start daemon (auto-reload on .fw changes)"
