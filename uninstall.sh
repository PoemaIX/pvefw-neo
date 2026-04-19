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

# ═══════════════════════════════════════════════════════════════
# 3. Optional reverse migration: restore firewall=1 on NICs that
#    weren't explicitly unfiltered via @neo:disable.
# ═══════════════════════════════════════════════════════════════
#
# Symmetric inverse of install.sh's migration A:
#   Install flipped firewall=1 → firewall=0 so pvefw-neo could manage.
#   Uninstall offers to flip firewall=0 → firewall=1 on NICs that
#   *don't* carry a @neo:disable marker (those the user wanted
#   unfiltered pre-install, we leave them alone).
#
# Scope: only VMs whose <vmid>.fw has [OPTIONS] enable: 1 — i.e. VMs
# the user explicitly wanted firewalled. VMs without that get skipped
# entirely, same as in install.sh.
#
# `.fw` contents are never touched here. @neo:disable / any other
# @neo: extension lines stay in place. They're inert once pvefw-neo
# is gone (Finger macro = TCP/79, harmless in practice).

echo ""
echo "[+] Checking existing VM/CT NIC firewall flags for reverse migration..."

nic_has_neo_disable() {
    # True if <vmid>.fw contains a @neo:disable line applicable to <nic>.
    # Applicable means: the line either has no `-i`/`-iface` (fans out to
    # all NICs) or names this specific NIC.
    local vmid=$1 nic=$2
    local fw="/etc/pve/firewall/${vmid}.fw"
    [ -f "$fw" ] || return 1
    awk -v nic="$nic" '
        /@neo:disable/ {
            iface=""
            n = split($0, parts, " ")
            for (i=1; i<=n; i++) {
                if (parts[i] == "-i" || parts[i] == "-iface") {
                    iface = parts[i+1]
                    break
                }
            }
            if (iface == "" || iface == nic) { found=1; exit }
        }
        END { exit !found }
    ' "$fw"
}

vm_has_enabled_fw() {
    local vmid=$1
    local fw="/etc/pve/firewall/${vmid}.fw"
    [ -f "$fw" ] || return 1
    awk '
        /^\[/{o=0}
        /^\[OPTIONS\]/{o=1; next}
        o && /^enable:[[:space:]]*1[[:space:]]*$/ {found=1; exit}
        END{exit !found}
    ' "$fw"
}

tmpfile=$(mktemp)
trap "rm -f $tmpfile" EXIT

for conf in /etc/pve/qemu-server/*.conf /etc/pve/lxc/*.conf; do
    [ -f "$conf" ] || continue
    vmid=$(basename "$conf" .conf)
    type=$(case "$conf" in */qemu-server/*) echo qm;; */lxc/*) echo pct;; esac)
    vm_has_enabled_fw "$vmid" || continue

    awk '
        /^\[/ { exit }
        /^net[0-9]+:/ {
            key=$1; sub(":","",key);
            val=substr($0, index($0, ":")+2);
            fw_val="";
            n=split(val, parts, ",");
            for (i=1; i<=n; i++) {
                if (parts[i] ~ /^firewall=/) {
                    split(parts[i], kv, "=");
                    fw_val=kv[2];
                }
            }
            print fw_val "|" key;
        }
    ' "$conf" | while IFS='|' read fw_val nic; do
        # Only NICs currently at firewall=0 are candidates (install flipped
        # them down; we might flip them back). firewall=1 or already unset
        # are already "PVE native" in effect.
        [ "$fw_val" = "0" ] || continue
        if nic_has_neo_disable "$vmid" "$nic"; then
            echo "skip|$type|$vmid|$nic" >> "$tmpfile"
        else
            echo "flip|$type|$vmid|$nic" >> "$tmpfile"
        fi
    done
done

n_flip=$(awk -F'|' '$1=="flip" {n++} END {print n+0}' "$tmpfile")
n_skip=$(awk -F'|' '$1=="skip" {n++} END {print n+0}' "$tmpfile")

if [ "$n_flip" -gt 0 ] || [ "$n_skip" -gt 0 ]; then
    echo ""
    echo "────────────────────────────────────────────────────────────"
    echo "Reverse migration plan"
    echo ""
    if [ "$n_flip" -gt 0 ]; then
        echo "  Restore firewall=1 on $n_flip NIC(s) (no @neo:disable marker):"
        awk -F'|' '$1=="flip" {printf "    %s %s %s\n", $2, $3, $4}' "$tmpfile"
        echo ""
    fi
    if [ "$n_skip" -gt 0 ]; then
        echo "  Left untouched: $n_skip NIC(s) carry @neo:disable — staying at firewall=0."
        awk -F'|' '$1=="skip" {printf "    %s %s %s\n", $2, $3, $4}' "$tmpfile"
        echo ""
    fi
fi

if [ "$n_flip" -gt 0 ]; then
    read -p "Restore firewall=1 on the $n_flip NIC(s) above? [y/N] " -r yn
    echo
    if [[ $yn =~ ^[Yy]$ ]]; then
        awk -F'|' '$1=="flip" {print $2, $3, $4}' "$tmpfile" | while read type vmid nic; do
            conf=$(case "$type" in
                qm)  echo "/etc/pve/qemu-server/$vmid.conf" ;;
                pct) echo "/etc/pve/lxc/$vmid.conf" ;;
            esac)
            current=$(awk "/^\\[/{exit} /^${nic}:/ {print; exit}" "$conf" | sed "s/^${nic}: //")
            if echo "$current" | grep -q '\bfirewall=0\b'; then
                new=$(echo "$current" | sed 's/\bfirewall=0\b/firewall=1/')
            else
                # firewall key absent — append
                new="${current},firewall=1"
            fi
            echo "    $type $vmid $nic: firewall=0 → firewall=1"
            $type set $vmid --$nic "$new" >/dev/null 2>&1 || echo "      [!] failed"
        done
        echo "  [+] Reverse migration applied."
        echo "      Re-enable PVE native firewall yourself if desired:"
        echo "        Host → Firewall → Options → enable: 1 (and nftables back to default)"
    else
        echo "  [=] Reverse migration skipped. firewall flags untouched."
    fi
fi

# ── 4. Remove symlinks ──
echo "[+] Removing symlinks..."
rm -f /usr/local/bin/pvefw-neo
rm -f /etc/systemd/system/pvefw-neo.service
systemctl daemon-reload

# ── 5. Remove install directory ──
if [ -L "$INSTALL_DIR" ]; then
    echo "[+] Removing symlink $INSTALL_DIR (dev mode, source not deleted)"
    rm -f "$INSTALL_DIR"
elif [ -d "$INSTALL_DIR" ]; then
    echo "[+] Removing $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
fi

# ── 6. Clean runtime ──
rm -rf /run/pvefw-neo

echo ""
echo "═══ Uninstall complete ═══"
echo "  Note: /etc/pve/firewall/*.fw files are NOT removed (user data)."
echo "  Note: @neo: extension rules in .fw files are NOT removed."
echo "  Note: python3-nftables and python3-inotify are NOT removed."
