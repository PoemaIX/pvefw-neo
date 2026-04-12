#!/bin/bash
# pvefw-neo test environment setup
# Creates vmbr1, test VMs/CTs, installs tools, writes .fw rules
# Usage: bash tests/setup.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "═══ pvefw-neo test environment setup ═══"

# ── 1. Internal bridge ──
if ! ip link show vmbr1 &>/dev/null; then
    echo "[+] Creating vmbr1 (internal test bridge, 10.99.0.1/24)"
    cat >> /etc/network/interfaces << 'EOF'

auto vmbr1
iface vmbr1 inet static
	address 10.99.0.1/24
	bridge-ports none
	bridge-stp off
	bridge-fd 0
EOF
    ifup vmbr1
else
    echo "[=] vmbr1 already exists"
fi

# Enable NAT for CT/VM internet access via vmbr0
if ! iptables -t nat -C POSTROUTING -s 10.99.0.0/24 -o vmbr0 -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o vmbr0 -j MASQUERADE
    echo "[+] NAT enabled: vmbr1 → vmbr0"
fi
echo 1 > /proc/sys/net/ipv4/ip_forward

# ── 2. Create test CTs (using LXC template) ──
TEMPLATE=$(ls /var/lib/vz/template/cache/*.tar.zst 2>/dev/null | head -1)
if [ -z "$TEMPLATE" ]; then
    echo "ERROR: No LXC template found in /var/lib/vz/template/cache/"
    exit 1
fi

for CTID in 2003 2004; do
    if pct status $CTID &>/dev/null; then
        echo "[=] CT $CTID already exists"
    else
        IP_LAST=$((CTID - 2003 + 13))  # 2003→13, 2004→14
        MAC_LAST=$(printf '%02X' $((CTID - 2003 + 3)))
        echo "[+] Creating CT $CTID (10.99.0.$IP_LAST, MAC 02:00:00:AA:${MAC_LAST}:00)"
        pct create $CTID "$TEMPLATE" \
            --hostname "test-fw-ct$((CTID-2002))" \
            --memory 256 --swap 0 --cores 1 \
            --net0 "name=eth0,bridge=vmbr1,hwaddr=02:00:00:AA:${MAC_LAST}:00,ip=10.99.0.${IP_LAST}/24,gw=10.99.0.1" \
            --rootfs local-lvm:1 \
            --password changeme \
            --unprivileged 1
    fi
done

# ── 3. Start CTs ──
for CTID in 2003 2004; do
    STATUS=$(pct status $CTID 2>&1 | awk '{print $2}')
    if [ "$STATUS" != "running" ]; then
        echo "[+] Starting CT $CTID"
        pct start $CTID
    else
        echo "[=] CT $CTID already running"
    fi
done

# ── 4. Install tools ──
echo "[+] Installing test tools in CTs..."
for CTID in 2003 2004; do
    pct exec $CTID -- bash -c '
        if ! which hping3 &>/dev/null || ! which ncat &>/dev/null || ! which socat &>/dev/null; then
            apt update -qq 2>/dev/null
            apt install -y -qq hping3 ncat socat 2>/dev/null
        fi
    '
done
echo "[+] Tools installed"

# ── 5. Write cluster.fw ──
echo "[+] Writing cluster.fw"
cat > /etc/pve/firewall/cluster.fw << 'FWEOF'
[group security_group_1]

|IN SSH(ACCEPT) -log nolog
|IN Ping(ACCEPT) -log nolog

[group sg_web]

|IN HTTP(ACCEPT) -log nolog
|IN HTTPS(ACCEPT) -log nolog

[ALIASES]

trusted_net 10.99.0.0/24

[IPSET cluster_blocked]

192.168.99.0/24
FWEOF

# ── 6. Write per-VM .fw files ──
echo "[+] Writing 2003.fw"
cat > /etc/pve/firewall/2003.fw << 'FWEOF'
[OPTIONS]

enable: 1
policy_in: DROP
policy_out: ACCEPT

[ALIASES]

my_ip 10.99.0.13
peer 10.99.0.14

[IPSET allowed_sources]

10.99.0.0/24

[RULES]

# ═══ Sugar tags ═══
|OUT Finger(DROP) -enable 0 -i net0 # @neo:macspoof
|OUT Finger(DROP) -enable 0 -i net0 # @neo:ipspoof 10.99.0.13/32
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nodhcp
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nora

# ═══ Notrack + mac primitive ═══
|OUT ACCEPT -i net0 -source 10.99.0.13/32 # @neo:notrack @neo:mac 02:00:00:AA:03:00
|OUT DROP   -i net0                       # @neo:notrack

# ═══ Security Group reference ═══
|GROUP security_group_1 -i net0

# ═══ Alias as source (port 8080) ═══
|IN ACCEPT -source trusted_net -p tcp -dport 8080 -i net0

# ═══ Alias as dest (block peer:4444 outbound) ═══
|OUT DROP -dest peer -p tcp -dport 4444 -i net0

# ═══ IPSet as source (port 9090) ═══
|IN ACCEPT -source +guest/allowed_sources -p tcp -dport 9090 -i net0

# ═══ Multi-entry macro: DNS (udp/53 + tcp/53) ═══
|IN DNS(ACCEPT) -source trusted_net -i net0

# ═══ Multi-entry macro: BitTorrent (DROP) ═══
|IN BitTorrent(DROP) -i net0

# ═══ Bare proto + port range ═══
|IN ACCEPT -p udp -dport 5000:5100 -source 10.99.0.0/24 -i net0

# ═══ sport rule ═══
|IN ACCEPT -p tcp -sport 1024:65535 -dport 3000 -i net0

# ═══ Catch-all OUT ═══
|OUT ACCEPT -i net0
FWEOF

echo "[+] Writing 2004.fw"
cat > /etc/pve/firewall/2004.fw << 'FWEOF'
[OPTIONS]

enable: 1
policy_in: DROP
policy_out: ACCEPT

[ALIASES]

my_ip 10.99.0.14
peer 10.99.0.13

[RULES]

# ═══ Sugar tags ═══
|OUT Finger(DROP) -enable 0 -i net0 # @neo:macspoof
|OUT Finger(DROP) -enable 0 -i net0 # @neo:ipspoof 10.99.0.14/32
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nodhcp
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nora

# ═══ Security Group: sg_web ═══
|GROUP sg_web -i net0

# ═══ Alias in stateful rule ═══
|IN SSH(ACCEPT) -source peer -i net0
|IN Ping(ACCEPT) -source trusted_net -i net0

# ═══ Catch-all OUT ═══
|OUT ACCEPT -i net0
FWEOF

# ── 7. Stop conflicting services ──
for svc in pve-firewall proxmox-firewall; do
    if systemctl is-active $svc.service &>/dev/null; then
        echo "[+] Stopping $svc"
        systemctl stop $svc.service
    fi
done

# ── 8. Apply pvefw-neo ──
echo "[+] Applying pvefw-neo ruleset..."
/usr/local/bin/pvefw-neo --apply

echo ""
echo "═══ Setup complete ═══"
echo "  CT 2003: 10.99.0.13 (MAC 02:00:00:AA:03:00)"
echo "  CT 2004: 10.99.0.14 (MAC 02:00:00:AA:04:00)"
echo "  Run: bash tests/run_tests.sh"
