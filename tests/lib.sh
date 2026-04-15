#!/bin/bash
# pvefw-neo test suite — shared library. Source this from setup/test/clean.
# Exports env var defaults, bridge/IP scheme helpers, guest exec wrappers,
# and pvesh-based firewall rule helpers.

# ── Env vars (override by exporting before invoking scripts) ──
: "${BR_MGMT:=vmbr1}"              # mgmt bridge (NAT out, not exercised by tests)
: "${BR_LINUX:=vmbr2}"             # Linux bridge under test (nft backend)
: "${BR_OVS:=vmbr3}"               # OVS bridge under test (of backend)
: "${MGMT_NET:=10.99.0.0/24}"      # mgmt subnet; host is .1, guests .10/.11
: "${MGMT_HOST_IP:=10.99.0.1}"     # host IP on BR_MGMT
: "${N_SLOTS:=3}"                  # parallel rule slots per backend
: "${VMID_VM:=2010}"               # test VM (cloned from TEMPLATE_VMID)
: "${VMID_CT:=2011}"               # test CT (from LXC template cache)
: "${TEMPLATE_VMID:=90013}"        # VM clone source (Cloudinit Debian)
: "${CI_USER:=debian}"
: "${CI_PASS:=changeme}"
: "${CT_PASS:=changeme}"
: "${NODE:=$(hostname)}"           # pvesh node name

# Host-side dep check. jq is used to parse qga JSON + pvesh output.
if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: 'jq' not found on host. Install with: apt install -y jq" >&2
    exit 1
fi

# ── IP scheme ──
# mgmt       : 10.99.0.<host>/24
# linux slot : 172.20.<slot>.<host>/24   (slot = 1..N_SLOTS)
# ovs   slot : 172.30.<slot>.<host>/24
# host octet : 10 for VM, 11 for CT
VM_HOST_OCTET=10
CT_HOST_OCTET=11

slot_subnet() {
    local backend=$1 slot=$2
    case $backend in
        linux) echo "172.20.$slot" ;;
        ovs)   echo "172.30.$slot" ;;
    esac
}

slot_ip() {
    local backend=$1 slot=$2 host=$3
    echo "$(slot_subnet $backend $slot).$host"
}

# netN on each guest:
#   net0              : mgmt
#   net1..N_SLOTS     : linux slots
#   net(N+1)..2N      : ovs slots
slot_iface() {
    local backend=$1 slot=$2
    case $backend in
        linux) echo "net$slot" ;;
        ovs)   echo "net$((slot + N_SLOTS))" ;;
    esac
}

# ── Logging ──
log()  { printf '\033[36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { printf '\033[32m  ✓\033[0m %s\n' "$*"; }
fail() { printf '\033[31m  ✗\033[0m %s\n' "$*"; FAILS=$((FAILS+1)); }
warn() { printf '\033[33m  !\033[0m %s\n' "$*"; }

# ── Guest exec ──
# exec_vm <cmd...>   — run a command inside VM via qemu-guest-agent
exec_vm() {
    local pid
    pid=$(qm guest exec "$VMID_VM" --timeout 20 -- /bin/sh -c "$*" 2>/dev/null) \
        || { echo "qga failed"; return 1; }
    echo "$pid" | jq -r '.["out-data"] // ""'
}

# exec_ct <cmd...>   — run a command inside CT
exec_ct() {
    pct exec "$VMID_CT" -- /bin/sh -c "$*" 2>/dev/null
}

# Uniform runner: exec_on vm|ct <cmd...>
exec_on() {
    local kind=$1; shift
    case $kind in
        vm) exec_vm "$*" ;;
        ct) exec_ct "$*" ;;
    esac
}

# Wait until guest answers via exec
wait_for_guest() {
    local kind=$1 tries=${2:-60}
    for i in $(seq 1 $tries); do
        if exec_on "$kind" "echo READY" 2>/dev/null | grep -q READY; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# ── PVE API resource paths ──
vm_fw_base()    { echo "/nodes/$NODE/qemu/$VMID_VM/firewall"; }
ct_fw_base()    { echo "/nodes/$NODE/lxc/$VMID_CT/firewall"; }
guest_fw_base() {
    case $1 in
        vm) vm_fw_base ;;
        ct) ct_fw_base ;;
    esac
}
guest_vmid() {
    case $1 in
        vm) echo $VMID_VM ;;
        ct) echo $VMID_CT ;;
    esac
}

# ── pvesh firewall helpers ──
# fw_rule <kind> <action> <type> <extra-opts...>
#   kind   : vm | ct
#   action : ACCEPT | DROP | REJECT | <security-group-name>
#   type   : in | out | forward
# extras pass through to pvesh (e.g. --iface net1 --proto tcp --dport 22).
# IMPORTANT: pvesh create on firewall rules always PREPENDS (inserts at
# position 0, shifting existing rules down). Its --pos parameter is
# ignored for create. Tests that care about rule order must create
# rules from LAST to FIRST (bottom-up), e.g. catchall-drop before the
# allow-specific rule that should evaluate earlier.
fw_rule() {
    local kind=$1 action=$2 type=$3; shift 3
    pvesh create "$(guest_fw_base $kind)/rules" \
        --action "$action" --type "$type" --enable 1 "$@" >/dev/null
}

# fw_rule_disabled : carrier rule for @neo: extensions (enable=0).
fw_rule_disabled() {
    local kind=$1 action=$2 type=$3; shift 3
    pvesh create "$(guest_fw_base $kind)/rules" \
        --action "$action" --type "$type" --enable 0 "$@" >/dev/null
}

# fw_clear <kind>  — delete every rule from the guest's firewall.
fw_clear() {
    local kind=$1 base
    base=$(guest_fw_base "$kind")
    while pvesh get "$base/rules" --output-format json 2>/dev/null \
        | jq -e '.[0]' >/dev/null; do
        pvesh delete "$base/rules/0" >/dev/null 2>&1 || break
    done
}

# fw_enable <kind> [policy_in] [policy_out]
fw_enable() {
    local kind=$1 pin=${2:-ACCEPT} pout=${3:-ACCEPT}
    pvesh set "$(guest_fw_base $kind)/options" \
        --enable 1 --policy_in "$pin" --policy_out "$pout" >/dev/null
}

fw_disable() {
    pvesh set "$(guest_fw_base $1)/options" --enable 0 >/dev/null 2>&1 || true
}

# Cluster-wide helpers ────
cluster_ipset_create()  { pvesh create /cluster/firewall/ipset --name "$1" >/dev/null; }
cluster_ipset_add()     { pvesh create "/cluster/firewall/ipset/$1" --cidr "$2" ${3:+--nomatch 1} >/dev/null; }
cluster_ipset_del()     { pvesh delete "/cluster/firewall/ipset/$1" >/dev/null 2>&1 || true; }
cluster_alias_create()  { pvesh create /cluster/firewall/aliases --name "$1" --cidr "$2" >/dev/null; }
cluster_alias_del()     { pvesh delete "/cluster/firewall/aliases/$1" >/dev/null 2>&1 || true; }

# Per-VM/CT ipset + alias
guest_ipset_create()  { pvesh create "$(guest_fw_base $1)/ipset" --name "$2" >/dev/null; }
guest_ipset_add()     { pvesh create "$(guest_fw_base $1)/ipset/$2" --cidr "$3" ${4:+--nomatch 1} >/dev/null; }
guest_alias_create()  { pvesh create "$(guest_fw_base $1)/aliases" --name "$2" --cidr "$3" >/dev/null; }

# ── Apply pvefw-neo after any firewall mutation (deterministic) ──
fw_apply() { /root/gitrs/pvefw-neo/pvefw-neo --apply >/dev/null 2>&1 || pvefw-neo --apply >/dev/null 2>&1; }

# ── Full reset between tests ──
fw_full_reset() {
    fw_clear vm
    fw_clear ct
    fw_disable vm
    fw_disable ct
    # Drop VM/CT-local ipsets + aliases (names prefixed tst_)
    for kind in vm ct; do
        local base; base=$(guest_fw_base "$kind")
        for name in $(pvesh get "$base/ipset" --output-format json 2>/dev/null | jq -r '.[].name' 2>/dev/null); do
            [[ $name == tst_* ]] && pvesh delete "$base/ipset/$name" --force 1 >/dev/null 2>&1
        done
        for name in $(pvesh get "$base/aliases" --output-format json 2>/dev/null | jq -r '.[].name' 2>/dev/null); do
            [[ $name == tst_* ]] && pvesh delete "$base/aliases/$name" >/dev/null 2>&1
        done
    done
    # Drop any cluster ipset/alias from a previous test run
    for name in $(pvesh get /cluster/firewall/ipset --output-format json 2>/dev/null | jq -r '.[].name' 2>/dev/null); do
        [[ $name == tst_* ]] && pvesh delete "/cluster/firewall/ipset/$name" --force 1 >/dev/null 2>&1
    done
    for name in $(pvesh get /cluster/firewall/aliases --output-format json 2>/dev/null | jq -r '.[].name' 2>/dev/null); do
        [[ $name == tst_* ]] && pvesh delete "/cluster/firewall/aliases/$name" >/dev/null 2>&1
    done
    fw_apply
    # Flush conntrack so residual ct state from prior tests doesn't let
    # `ct state established,related accept` mask the new ruleset.
    conntrack -F >/dev/null 2>&1 || true
}

# ── Packet tests (between VM and CT) ──
# ping_between <from-kind> <from-iface> <to-ip>  → 0 on success, 1 on loss
ping_between() {
    local from=$1 iface=$2 to=$3
    exec_on "$from" "ping -c 1 -W 2 -I $iface $to" \
        | grep -q ' 0% packet loss' && return 0 || return 1
}

# tcp_check <from-kind> <to-ip> <port>  → echoes "OPEN" or "CLOSED"
tcp_check() {
    local from=$1 to=$2 port=$3
    exec_on "$from" "ncat -z -w 2 $to $port && echo OPEN || echo CLOSED" \
        | tr -d '\r\n'
}

# Start a TCP listener on kind/iface/port (background, auto-killed on clean)
start_listener() {
    local kind=$1 port=$2
    exec_on "$kind" "pkill -f 'ncat.*-l.*$port' 2>/dev/null; ncat -l -k $port -e /bin/cat >/dev/null 2>&1 &"
    sleep 0.5
}

# ── Test runner scaffolding ──
PASSES=0
FAILS=0
check() {
    local name=$1 expect=$2 got=$3
    if [ "$expect" = "$got" ]; then
        ok "$name"
        PASSES=$((PASSES+1))
    else
        fail "$name — expected [$expect], got [$got]"
    fi
}
