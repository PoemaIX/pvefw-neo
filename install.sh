#!/bin/bash
# pvefw-neo install script
# Usage: bash install.sh
set -e

INSTALL_DIR="/usr/local/lib/pvefw_neo"
REPO_URL="https://github.com/PoemaIX/pvefw-neo.git"
NODENAME=$(hostname)
HOST_FW="/etc/pve/nodes/$NODENAME/host.fw"

echo "═══════════════════════════════════════════════════════════════"
echo " pvefw-neo install"
echo "═══════════════════════════════════════════════════════════════"
echo ""
cat <<'EOF'
pvefw-neo coexists with PVE's native firewall using the
"node off + nftables mode" model:

  • This node must have host.fw: enable=0, nftables=1
    - PVE's Rust proxmox-firewall daemon skips nodes with host.enable=0
    - PVE's Perl pve-firewall daemon defers in nftables mode
    → no PVE native rules are installed on this node
    → pvefw-neo gets exclusive nftables control for VMs on this host

  • Other nodes in the cluster can still use PVE native firewall
    normally. You do NOT need to disable datacenter-level firewall.

  • NIC-level firewall flag MUST be 0 or unset on this node:

      firewall=1 → PVE auto-builds a fwbr (firewall bridge), breaking
                   pvefw-neo's direct-attach model. pvefw-neo will skip
                   (warn + ignore) any NIC with firewall=1.
      firewall=0 → tap/veth attaches directly to vmbr, pvefw-neo manages it
      firewall unset → same as 0 (also managed by pvefw-neo)

    This script offers to bulk-flip existing firewall=1 NICs to
    firewall=0 so they become manageable by pvefw-neo.

  • Per-port debug: use  `@neo:disable`  in a .fw rule comment to
    temporarily bypass all pvefw-neo rules on one port, without
    touching VM config. Example:

        |OUT Finger(DROP) -enable 0 -i net0 # @neo:disable

EOF

read -p "Continue with install? [Y/n] " -n 1 -r yn
echo
if [[ $yn =~ ^[Nn]$ ]]; then
    echo "Aborted."
    exit 1
fi

# ═══════════════════════════════════════════════════════════════
# 1. Dependencies
# ═══════════════════════════════════════════════════════════════
echo ""
echo "[1/7] Installing dependencies..."
apt install -y python3-nftables python3-inotify

# ═══════════════════════════════════════════════════════════════
# 2. Clone or symlink the repo
# ═══════════════════════════════════════════════════════════════
echo ""
echo "[2/7] Installing to $INSTALL_DIR..."
if [ -d "$INSTALL_DIR" ] || [ -L "$INSTALL_DIR" ]; then
    echo "  $INSTALL_DIR already exists, skipping."
else
    if [ -n "$DEV_LINK" ]; then
        echo "  DEV_LINK mode: $DEV_LINK → $INSTALL_DIR"
        ln -sfn "$DEV_LINK" "$INSTALL_DIR"
    else
        echo "  Cloning $REPO_URL"
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
fi

# ═══════════════════════════════════════════════════════════════
# 3. Launcher and systemd symlinks
# ═══════════════════════════════════════════════════════════════
echo ""
echo "[3/7] Linking launcher and systemd unit..."
ln -sfn "$INSTALL_DIR/pvefw-neo" /usr/local/bin/pvefw-neo
chmod +x "$INSTALL_DIR/pvefw-neo"
ln -sfn "$INSTALL_DIR/pvefw-neo.service" /etc/systemd/system/pvefw-neo.service
systemctl daemon-reload
mkdir -p /run/pvefw-neo

# ═══════════════════════════════════════════════════════════════
# 4. Configure host.fw for pvefw-neo model
# ═══════════════════════════════════════════════════════════════
echo ""
echo "[4/7] Checking $HOST_FW..."

current_enable=""
current_nftables=""
if [ -f "$HOST_FW" ]; then
    current_enable=$(awk '/^\[/{o=0} /^\[OPTIONS\]/{o=1; next} o && /^enable:/ {print $2}' "$HOST_FW" | tail -1)
    current_nftables=$(awk '/^\[/{o=0} /^\[OPTIONS\]/{o=1; next} o && /^nftables:/ {print $2}' "$HOST_FW" | tail -1)
fi

needs_update=0
if [ "$current_enable" != "0" ] || [ "$current_nftables" != "1" ]; then
    needs_update=1
fi

if [ "$needs_update" -eq 1 ]; then
    echo "  Current state:"
    echo "    enable:   ${current_enable:-<unset>}   (required: 0)"
    echo "    nftables: ${current_nftables:-<unset>}   (required: 1)"
    echo ""
    read -p "  Update $HOST_FW now? [Y/n] " -n 1 -r yn
    echo
    if [[ ! $yn =~ ^[Nn]$ ]]; then
        mkdir -p "$(dirname "$HOST_FW")"
        if [ -f "$HOST_FW" ]; then
            cp "$HOST_FW" "${HOST_FW}.bak-$(date +%s)"
            python3 - "$HOST_FW" <<'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f:
    lines = f.read().splitlines()
out = []
in_options = False
saw_options = False
set_enable = False
set_nftables = False
for line in lines:
    if line.strip().lower().startswith("[options]"):
        saw_options = True
        in_options = True
        out.append(line)
        continue
    if line.strip().startswith("["):
        # Exiting [OPTIONS], inject any missing keys before section change
        if in_options:
            if not set_enable:
                out.append("enable: 0")
                set_enable = True
            if not set_nftables:
                out.append("nftables: 1")
                set_nftables = True
        in_options = False
        out.append(line)
        continue
    if in_options and re.match(r"^\s*enable\s*:", line, re.I):
        out.append("enable: 0")
        set_enable = True
        continue
    if in_options and re.match(r"^\s*nftables\s*:", line, re.I):
        out.append("nftables: 1")
        set_nftables = True
        continue
    out.append(line)

# If file ended while still in [OPTIONS], append missing keys
if in_options:
    if not set_enable:
        out.append("enable: 0")
    if not set_nftables:
        out.append("nftables: 1")

# If [OPTIONS] never existed, prepend one
if not saw_options:
    out = ["[OPTIONS]", "", "enable: 0", "nftables: 1", ""] + out

with open(path, "w") as f:
    f.write("\n".join(out).rstrip() + "\n")
PYEOF
            echo "  [+] Updated $HOST_FW (backup in ${HOST_FW}.bak-*)"
        else
            cat > "$HOST_FW" <<'HOSTFW'
[OPTIONS]

enable: 0
nftables: 1

[RULES]

HOSTFW
            echo "  [+] Created $HOST_FW"
        fi
    else
        echo "  [!] Skipped. pvefw-neo will refuse to start until this is fixed."
    fi
else
    echo "  [=] Already configured correctly."
fi

# ═══════════════════════════════════════════════════════════════
# 5. Offer to flip firewall=1 NICs to firewall=0 (remove fwbr)
# ═══════════════════════════════════════════════════════════════
echo ""
echo "[5/7] Checking existing VM/CT NIC firewall flags..."

# Collect NICs with firewall=1 (which pvefw-neo can't manage due to fwbr)
tmpfile=$(mktemp)
trap "rm -f $tmpfile" EXIT

for conf in /etc/pve/qemu-server/*.conf /etc/pve/lxc/*.conf; do
    [ -f "$conf" ] || continue
    vmid=$(basename "$conf" .conf)
    type=$(case "$conf" in */qemu-server/*) echo qm;; */lxc/*) echo pct;; esac)
    # Parse net lines (stop at section markers to avoid [special:...] etc.)
    awk '
        /^\[/ { exit }
        /^net[0-9]+:/ {
            key=$1; sub(":","",key);
            val=substr($0, index($0, ":")+2);
            has_fw=0; fw_val="";
            n=split(val, parts, ",");
            for (i=1; i<=n; i++) {
                if (parts[i] ~ /^firewall=/) {
                    has_fw=1;
                    split(parts[i], kv, "=");
                    fw_val=kv[2];
                }
            }
            print has_fw "|" fw_val "|" key;
        }
    ' "$conf" | while IFS='|' read has_fw fw_val nic; do
        echo "$type|$vmid|$nic|$has_fw|$fw_val" >> "$tmpfile"
    done
done

n_fw1=$(awk -F'|' '$4==1 && $5==1 {n++} END {print n+0}' "$tmpfile")
n_fw0=$(awk -F'|' '$4==1 && $5==0 {n++} END {print n+0}' "$tmpfile")
n_unset=$(awk -F'|' '$4==0 {n++} END {print n+0}' "$tmpfile")

echo "  Found:"
echo "    firewall=1 (PVE fwbr, skipped by pvefw-neo):  $n_fw1"
echo "    firewall=0 (direct-attach, pvefw-neo OK):     $n_fw0"
echo "    firewall unset (direct-attach, pvefw-neo OK): $n_unset"

if [ "$n_fw1" -gt 0 ]; then
    echo ""
    echo "  You have $n_fw1 NIC(s) with firewall=1. These will be skipped"
    echo "  by pvefw-neo (warn + ignore) because PVE builds a fwbr around"
    echo "  them. Flip to firewall=0 so pvefw-neo can manage them?"
    echo ""
    read -p "  Flip all firewall=1 → firewall=0 on this host? [y/N] " -n 1 -r yn
    echo
    if [[ $yn =~ ^[Yy]$ ]]; then
        awk -F'|' '$4==1 && $5==1 {print $1, $2, $3}' "$tmpfile" | while read type vmid nic; do
            conf=$(case "$type" in
                qm)  echo "/etc/pve/qemu-server/$vmid.conf" ;;
                pct) echo "/etc/pve/lxc/$vmid.conf" ;;
            esac)
            # Read current net value and replace firewall=1 with firewall=0
            current=$(awk "/^\\[/{exit} /^${nic}:/ {print; exit}" "$conf" | sed "s/^${nic}: //")
            new=$(echo "$current" | sed 's/\bfirewall=1\b/firewall=0/')
            echo "    $type $vmid $nic: $current  →  $new"
            $type set $vmid --$nic "$new" >/dev/null 2>&1 || echo "      [!] failed"
        done
        echo "  [+] Done. Changes are live (takes effect on next VM start for stopped VMs)."
    else
        echo "  [=] Skipped. Ports with firewall=1 will be warned + skipped by pvefw-neo."
    fi
fi

# ═══════════════════════════════════════════════════════════════
# 6. Verify
# ═══════════════════════════════════════════════════════════════
echo ""
echo "[6/7] Verifying..."
if pvefw-neo --preflight-check 2>&1; then
    echo "  [+] preflight check OK"
else
    echo "  [!] preflight check failed — see errors above"
fi

# ═══════════════════════════════════════════════════════════════
# 7. Next steps
# ═══════════════════════════════════════════════════════════════
echo ""
echo "[7/7] Next steps"
echo ""
echo "  Start the daemon:"
echo "    systemctl enable --now pvefw-neo"
echo "    journalctl -u pvefw-neo -f"
echo ""
echo "  Useful commands:"
echo "    pvefw-neo --apply            # Apply once"
echo "    pvefw-neo --dry-run          # Preview nftables text"
echo "    pvefw-neo --dump-ir          # Intermediate representation (debug)"
echo "    pvefw-neo --dump-ovs <br>    # Preview OVS flows for an OVS bridge"
echo "    pvefw-neo --flush            # Remove all pvefw-neo state"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " Install complete"
echo "═══════════════════════════════════════════════════════════════"
