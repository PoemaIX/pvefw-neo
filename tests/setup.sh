#!/bin/bash
# pvefw-neo test suite — environment setup.
# Creates bridges, guests, NICs, installs tools. Does NOT run tests.
#
# Usage:
#   bash tests/setup.sh                       # defaults
#   CI_PASS=mypass N_SLOTS=3 bash tests/setup.sh
#
# See tests/lib.sh for all env var defaults.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

log "═══ pvefw-neo test environment setup ═══"
log "BR_MGMT=$BR_MGMT  BR_LINUX=$BR_LINUX  BR_OVS=$BR_OVS  N_SLOTS=$N_SLOTS"
log "VM=$VMID_VM (clone of $TEMPLATE_VMID)  CT=$VMID_CT"

# ─────────────── 1. Bridges ───────────────

ensure_linux_bridge() {
    local br=$1 addr=$2
    if ip link show "$br" &>/dev/null; then
        log "[=] $br already exists"
        return
    fi
    log "[+] Creating Linux bridge $br ($addr)"
    cat >> /etc/network/interfaces <<EOF

auto $br
iface $br inet static
	address $addr
	bridge-ports none
	bridge-stp off
	bridge-fd 0
EOF
    ifup "$br"
}

ensure_ovs_bridge() {
    local br=$1
    if ovs-vsctl br-exists "$br" 2>/dev/null; then
        log "[=] $br already exists (OVS)"
        return
    fi
    if ! command -v ovs-vsctl >/dev/null; then
        log "[!] openvswitch-switch not installed — skipping $br"
        log "    install with:  apt install -y openvswitch-switch"
        return 1
    fi
    log "[+] Creating OVS bridge $br"
    cat >> /etc/network/interfaces <<EOF

auto $br
iface $br inet manual
	ovs_type OVSBridge
EOF
    ovs-vsctl add-br "$br"
}

ensure_linux_bridge "$BR_MGMT"  "$MGMT_HOST_IP/24"
ensure_linux_bridge "$BR_LINUX" "0.0.0.0/32"   # no host IP; guests talk peer-to-peer
ensure_ovs_bridge   "$BR_OVS"

# NAT for mgmt net (guests reach upstream via host's default route)
if ! iptables -t nat -C POSTROUTING -s "$MGMT_NET" ! -d "$MGMT_NET" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$MGMT_NET" ! -d "$MGMT_NET" -j MASQUERADE
    log "[+] NAT: $MGMT_NET → upstream"
fi
echo 1 > /proc/sys/net/ipv4/ip_forward

# ─────────────── 2. VM (clone from template) ───────────────

if qm status "$VMID_VM" &>/dev/null; then
    log "[=] VM $VMID_VM already exists"
else
    log "[+] Cloning VM $TEMPLATE_VMID → $VMID_VM"
    qm clone "$TEMPLATE_VMID" "$VMID_VM" --name "pvefw-neo-test-vm" --full 1
    qm set "$VMID_VM" --ciuser "$CI_USER" --cipassword "$CI_PASS" >/dev/null
fi

# Rewrite all NICs on VM: net0 mgmt, net1..N linux, net(N+1)..2N ovs
log "[+] Configuring VM $VMID_VM NICs + ipconfig (2*$N_SLOTS+1 = $((2*N_SLOTS+1)) ifaces)"
# net0: mgmt
qm set "$VMID_VM" \
    --net0 "virtio,bridge=$BR_MGMT,firewall=0" \
    --ipconfig0 "ip=10.99.0.$VM_HOST_OCTET/24,gw=$MGMT_HOST_IP" >/dev/null
for slot in $(seq 1 "$N_SLOTS"); do
    # linux slot
    lif="net$slot"
    lip=$(slot_ip linux $slot $VM_HOST_OCTET)
    qm set "$VMID_VM" \
        --$lif "virtio,bridge=$BR_LINUX,firewall=0" \
        --ipconfig$slot "ip=$lip/24" >/dev/null
    # ovs slot
    oif="net$((slot + N_SLOTS))"
    oip=$(slot_ip ovs $slot $VM_HOST_OCTET)
    qm set "$VMID_VM" \
        --$oif "virtio,bridge=$BR_OVS,firewall=0" \
        --ipconfig$((slot + N_SLOTS)) "ip=$oip/24" >/dev/null
done

if [ "$(qm status "$VMID_VM" | awk '{print $2}')" != "running" ]; then
    log "[+] Starting VM $VMID_VM"
    qm start "$VMID_VM"
fi

# ─────────────── 3. CT (from LXC template cache) ───────────────

if pct status "$VMID_CT" &>/dev/null; then
    log "[=] CT $VMID_CT already exists"
else
    TEMPLATE=$(ls /var/lib/vz/template/cache/*.tar.zst 2>/dev/null | head -1)
    if [ -z "$TEMPLATE" ]; then
        echo "ERROR: no LXC template in /var/lib/vz/template/cache/"
        echo "       pveam update && pveam download local debian-13-standard"
        exit 1
    fi
    log "[+] Creating CT $VMID_CT from $TEMPLATE"
    # Build --netN args dynamically (net0..net(2N))
    NET_ARGS=(--net0 "name=eth0,bridge=$BR_MGMT,ip=10.99.0.$CT_HOST_OCTET/24,gw=$MGMT_HOST_IP,firewall=0")
    for slot in $(seq 1 "$N_SLOTS"); do
        lip=$(slot_ip linux $slot $CT_HOST_OCTET)
        oip=$(slot_ip ovs   $slot $CT_HOST_OCTET)
        NET_ARGS+=(--net$slot "name=eth$slot,bridge=$BR_LINUX,ip=$lip/24,firewall=0")
        NET_ARGS+=(--net$((slot + N_SLOTS)) "name=eth$((slot + N_SLOTS)),bridge=$BR_OVS,ip=$oip/24,firewall=0")
    done
    pct create "$VMID_CT" "$TEMPLATE" \
        --hostname pvefw-neo-test-ct \
        --memory 256 --swap 0 --cores 1 \
        --rootfs local-lvm:1 \
        --password "$CT_PASS" \
        --unprivileged 1 \
        "${NET_ARGS[@]}"
fi

if [ "$(pct status "$VMID_CT" | awk '{print $2}')" != "running" ]; then
    log "[+] Starting CT $VMID_CT"
    pct start "$VMID_CT"
fi

# ─────────────── 4. Wait for guests ───────────────

log "[*] Waiting for VM qemu-guest-agent..."
if ! wait_for_guest vm 90; then
    log "[!] VM not responding via qga — tests that exercise VM will fail"
fi

log "[*] Waiting for CT..."
if ! wait_for_guest ct 30; then
    log "[!] CT not responding — tests that exercise CT will fail"
fi

# ─────────────── 5. Install test tools (via mgmt NAT) ───────────────

TOOLS="hping3 ncat socat tcpdump iproute2 iputils-ping"
log "[+] Installing tools in guests: $TOOLS"

install_cmd="
export DEBIAN_FRONTEND=noninteractive
if ! which hping3 >/dev/null 2>&1 || ! which ncat >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq $TOOLS >/dev/null 2>&1
fi
echo DONE
"
exec_vm "$install_cmd" | tail -1
exec_ct "$install_cmd" | tail -1

log "═══ Setup complete — run tests/test.sh ═══"
