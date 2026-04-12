#!/bin/bash
# pvefw-neo test environment teardown
# Destroys test CTs, removes vmbr1, flushes nftables
# Usage: bash tests/teardown.sh
set -e

echo "═══ pvefw-neo test teardown ═══"

# ── 1. Flush pvefw-neo nftables ──
echo "[+] Flushing pvefw-neo rules"
/usr/local/bin/pvefw-neo --flush 2>/dev/null || true

# ── 2. Destroy test CTs ──
for CTID in 2003 2004; do
    if pct status $CTID &>/dev/null; then
        echo "[+] Destroying CT $CTID"
        pct stop $CTID 2>/dev/null || true
        pct destroy $CTID --purge 2>/dev/null || true
    fi
done

# ── 3. Destroy test VMs ──
for VMID in 2001 2002; do
    if qm status $VMID &>/dev/null; then
        echo "[+] Destroying VM $VMID"
        qm stop $VMID 2>/dev/null || true
        qm destroy $VMID --purge 2>/dev/null || true
    fi
done

# ── 4. Remove test .fw files ──
for f in 2001 2002 2003 2004; do
    rm -f "/etc/pve/firewall/${f}.fw"
done
echo "[+] Removed test .fw files"

# ── 5. Remove NAT rule ──
iptables -t nat -D POSTROUTING -s 10.99.0.0/24 -o vmbr0 -j MASQUERADE 2>/dev/null || true

# ── 6. Remove vmbr1 (optional — uncomment if desired) ──
# ifdown vmbr1 2>/dev/null || true
# sed -i '/^auto vmbr1$/,/^$/d' /etc/network/interfaces
# echo "[+] Removed vmbr1"

# ── 7. Restart PVE firewall services ──
echo "[+] Restarting PVE firewall services"
systemctl start pve-firewall.service 2>/dev/null || true
systemctl start proxmox-firewall.service 2>/dev/null || true

echo ""
echo "═══ Teardown complete ═══"
