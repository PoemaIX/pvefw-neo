#!/bin/bash
# pvefw-neo test suite — teardown.
# Destroys the test VM/CT, removes cluster-level test ipsets/aliases,
# flushes pvefw-neo state, removes NAT rule. Leaves the bridges in
# place (remove them manually from /etc/network/interfaces if desired).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

log "═══ pvefw-neo test teardown ═══"

# ── VM ──
if qm status "$VMID_VM" &>/dev/null; then
    log "[-] Stopping + destroying VM $VMID_VM"
    qm stop "$VMID_VM" --skiplock 1 >/dev/null 2>&1 || true
    qm destroy "$VMID_VM" --purge 1 --destroy-unreferenced-disks 1 >/dev/null 2>&1 || true
fi

# ── CT ──
if pct status "$VMID_CT" &>/dev/null; then
    log "[-] Stopping + destroying CT $VMID_CT"
    pct stop "$VMID_CT" >/dev/null 2>&1 || true
    pct destroy "$VMID_CT" --purge 1 >/dev/null 2>&1 || true
fi

# ── Cluster-level test artifacts (name prefix tst_) ──
log "[-] Removing cluster test ipsets/aliases"
for name in $(pvesh get /cluster/firewall/ipset --output-format json 2>/dev/null | jq -r '.[].name' 2>/dev/null); do
    if [[ $name == tst_* ]]; then
        pvesh delete "/cluster/firewall/ipset/$name" --force 1 >/dev/null 2>&1 || true
    fi
done
for name in $(pvesh get /cluster/firewall/aliases --output-format json 2>/dev/null | jq -r '.[].name' 2>/dev/null); do
    if [[ $name == tst_* ]]; then
        pvesh delete "/cluster/firewall/aliases/$name" >/dev/null 2>&1 || true
    fi
done

# ── Flush pvefw-neo state ──
log "[-] Flushing pvefw-neo state"
pvefw-neo --flush >/dev/null 2>&1 || true

# ── NAT rule ──
if iptables -t nat -C POSTROUTING -s "$MGMT_NET" ! -d "$MGMT_NET" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -D POSTROUTING -s "$MGMT_NET" ! -d "$MGMT_NET" -j MASQUERADE
    log "[-] Removed NAT: $MGMT_NET"
fi

log "═══ Teardown complete ═══"
log "Bridges $BR_MGMT / $BR_LINUX / $BR_OVS left in place."
log "Remove them manually from /etc/network/interfaces if no longer needed."
