#!/bin/bash
# pvefw-neo comprehensive test suite
# Prerequisites: run tests/setup.sh first
# Usage: bash tests/run_tests.sh
set -u

PASS=0; FAIL=0; SKIP=0

# ── Helpers ──
check() {
    local name="$1" expect="$2" actual="$3"
    if [ "$actual" = "$expect" ]; then
        echo "  ✓ $name"
        PASS=$((PASS+1))
    else
        echo "  ✗ $name"
        echo "    expect: '$expect'"
        echo "    actual: '$actual'"
        FAIL=$((FAIL+1))
    fi
}

# Start a TCP listener in a CT, returns immediately
# Usage: start_listener <ctid> <port>
start_listener() {
    local ctid=$1 port=$2
    pct exec $ctid -- bash -c "(echo RESPONSE_${port} | setsid ncat -l $port -w 10) &>/dev/null &"
    sleep 0.5
}

# Start a UDP listener in a CT (uses socat for reliable UDP)
start_udp_listener() {
    local ctid=$1 port=$2
    pct exec $ctid -- bash -c "setsid socat -u UDP-LISTEN:$port,reuseaddr SYSTEM:'echo RESPONSE_${port}' &>/dev/null &"
    sleep 0.5
}

# Connect to a TCP port from a CT, return first line of response
# Usage: tcp_connect <ctid> <dest_ip> <port>
tcp_connect() {
    local ctid=$1 ip=$2 port=$3
    pct exec $ctid -- bash -c "echo t | ncat -w 2 $ip $port 2>/dev/null | head -1"
}

# Check if TCP port is open (nc -z)
tcp_check() {
    local ctid=$1 ip=$2 port=$3
    pct exec $ctid -- bash -c "nc -zw 2 $ip $port 2>/dev/null && echo OPEN || echo CLOSED"
}

# Connect to UDP port
udp_connect() {
    local ctid=$1 ip=$2 port=$3
    pct exec $ctid -- bash -c "echo t | ncat -w 2 -u $ip $port 2>/dev/null | head -1"
}

# ── Preflight ──
echo "═══════════════════════════════════════"
echo " pvefw-neo Comprehensive Test Suite"
echo "═══════════════════════════════════════"

for CTID in 2003 2004; do
    S=$(pct status $CTID 2>&1 | awk '{print $2}')
    if [ "$S" != "running" ]; then
        echo "ERROR: CT $CTID not running. Run tests/setup.sh first."
        exit 1
    fi
done

# Verify pvefw-neo is applied
if ! nft list table bridge pvefw-neo &>/dev/null; then
    echo "ERROR: pvefw-neo rules not applied. Run tests/setup.sh first."
    exit 1
fi

# Kill stale listeners
for CTID in 2003 2004; do
    pct exec $CTID -- bash -c "pkill -f ncat 2>/dev/null; true"
done

echo ""
echo "── 1. Sugar Tags (@neo:macspoof, @neo:ipspoof, @neo:nodhcp, @neo:nora) ──"

# 1a. macspoof + ipspoof: legitimate traffic passes
R=$(pct exec 2003 -- ping -c 1 -W 2 10.99.0.14 2>&1 | grep -c "1 received")
check "macspoof+ipspoof: legitimate traffic passes" "1" "$R"

# 1b. ipspoof: forged source IP → dropped
R=$(pct exec 2003 -- hping3 -c 1 -1 -a 10.99.0.99 10.99.0.14 -I eth0 2>&1 | grep -oP '\d+(?=% packet loss)')
check "ipspoof: forged source IP dropped" "100" "$R"

# 1c. ipspoof: correct source IP → passes
R=$(pct exec 2003 -- hping3 -c 1 -1 10.99.0.14 -I eth0 2>&1 | grep -oP '\d+(?=% packet loss)')
check "ipspoof: correct source IP passes" "0" "$R"

# 1d. nodhcp: DHCP server packets (sport 67 → dport 68) → dropped
R=$(pct exec 2003 -- hping3 -c 1 -2 -s 67 -p 68 10.99.0.14 -I eth0 2>&1 | grep -oP '\d+(?=% packet loss)')
check "nodhcp: DHCP reply dropped" "100" "$R"

# 1e. nora: RA packets are in the ruleset (structural check)
R=$(nft list chain bridge pvefw-neo raw_prerouting 2>&1 | grep -c "nd-router-advert drop")
[ "$R" -ge 1 ] && R="yes" || R="no"
check "nora: RA drop rules present in raw_prerouting" "yes" "$R"


echo ""
echo "── 2. Macros (single-entry + multi-entry) ──"

# 2a. SSH macro (tcp/22) — CT2004 allows SSH from peer alias (10.99.0.13)
R=$(tcp_check 2003 10.99.0.14 22)
check "Macro SSH(ACCEPT): CT2003→CT2004:22" "OPEN" "$R"

# 2b. HTTP macro via security group sg_web — CT2004 allows port 80
start_listener 2004 80
R=$(tcp_connect 2003 10.99.0.14 80)
check "Macro HTTP(ACCEPT) via sg_web: CT2003→CT2004:80" "RESPONSE_80" "$R"

# 2c. HTTPS macro via security group sg_web — CT2004 allows port 443
start_listener 2004 443
R=$(tcp_connect 2003 10.99.0.14 443)
check "Macro HTTPS(ACCEPT) via sg_web: CT2003→CT2004:443" "RESPONSE_443" "$R"

# 2d. DNS macro (multi-entry: udp/53 + tcp/53) on CT2003
# UDP: verify rule is in nftables (functional UDP test unreliable with ncat)
R=$(nft list chain bridge pvefw-neo vm_veth2003i0_in 2>&1 | grep -c "udp dport 53 accept")
[ "$R" -ge 1 ] && R="yes" || R="no"
check "Macro DNS(ACCEPT): UDP/53 rule present" "yes" "$R"

start_listener 2003 53
R=$(tcp_connect 2004 10.99.0.13 53)
check "Macro DNS(ACCEPT): TCP/53 functional" "RESPONSE_53" "$R"

# 2e. BitTorrent(DROP) — port 6881 blocked on CT2003
R=$(tcp_check 2004 10.99.0.13 6881)
check "Macro BitTorrent(DROP): port 6881 blocked" "CLOSED" "$R"

# 2f. Ping macro via security_group_1 — CT2003 accepts Ping
R=$(pct exec 2004 -- ping -c 1 -W 2 10.99.0.13 2>&1 | grep -c "1 received")
check "Macro Ping(ACCEPT) via SG: CT2004→CT2003" "1" "$R"


echo ""
echo "── 3. Aliases ──"

# 3a. trusted_net alias → CT2003 IN port 8080
start_listener 2003 8080
R=$(tcp_connect 2004 10.99.0.13 8080)
check "Alias trusted_net: IN ACCEPT port 8080" "RESPONSE_8080" "$R"

# 3b. peer alias → CT2004 SSH from peer=10.99.0.13
R=$(tcp_check 2003 10.99.0.14 22)
check "Alias peer: SSH from CT2003(=peer) to CT2004" "OPEN" "$R"

# 3c. peer alias → CT2003 OUT DROP to peer:4444 (outbound block)
start_listener 2004 4444
R=$(tcp_connect 2003 10.99.0.14 4444)
check "Alias peer: OUT DROP to peer:4444 (blocked)" "" "$R"


echo ""
echo "── 4. IPSet ──"

# 4a. IPSet allowed_sources → CT2003 IN port 9090
start_listener 2003 9090
R=$(tcp_connect 2004 10.99.0.13 9090)
check "IPSet allowed_sources: IN ACCEPT port 9090" "RESPONSE_9090" "$R"

# 4b. Verify set is defined in nftables
R=$(nft list set bridge pvefw-neo vm2003_allowed_sources 2>&1 | grep -c "10.99.0.0/24")
check "IPSet: nft set contains 10.99.0.0/24" "1" "$R"


echo ""
echo "── 5. Security Groups ──"

# 5a. security_group_1: SSH + Ping (tested above via macros, verify inline expansion)
R=$(nft list chain bridge pvefw-neo vm_veth2003i0_in 2>&1 | grep -c "dport 22 accept")
[ "$R" -ge 1 ] && R="yes" || R="no"
check "SG security_group_1: SSH rule inlined in vm_veth2003i0_in" "yes" "$R"

# 5b. sg_web: HTTP + HTTPS
R=$(nft list chain bridge pvefw-neo vm_veth2004i0_in 2>&1 | grep -c "dport 80 accept")
[ "$R" -ge 1 ] && R="yes" || R="no"
check "SG sg_web: HTTP rule inlined in vm_veth2004i0_in" "yes" "$R"

R=$(nft list chain bridge pvefw-neo vm_veth2004i0_in 2>&1 | grep -c "dport 443 accept")
[ "$R" -ge 1 ] && R="yes" || R="no"
check "SG sg_web: HTTPS rule inlined in vm_veth2004i0_in" "yes" "$R"


echo ""
echo "── 6. @neo:notrack + @neo:mac primitive ──"

# 6a. Verify notrack+mac rule in raw_prerouting
R=$(nft list chain bridge pvefw-neo raw_prerouting 2>&1 | grep -c "ether saddr 02:00:00:aa:03:00.*saddr 10.99.0.13")
[ "$R" -ge 1 ] && R="yes" || R="no"
check "notrack+mac: MAC+IP rule in raw_prerouting" "yes" "$R"

# 6b. notrack DROP-all rule present
R=$(nft list chain bridge pvefw-neo raw_prerouting 2>&1 | grep 'iifname "veth2003i0" drop' | wc -l)
[ "$R" -ge 1 ] && R="yes" || R="no"
check "notrack: DROP-all fallback in raw_prerouting" "yes" "$R"

# 6c. Functional: traffic still works (combined sugar+notrack allow the right packets)
R=$(pct exec 2003 -- ping -c 1 -W 2 10.99.0.14 2>&1 | grep -c "1 received")
check "notrack+mac: legitimate traffic still passes" "1" "$R"


echo ""
echo "── 7. Bare proto + port rules ──"

# 7a. UDP 5000-5100 range — verify rule present + packet reaches (nft trace confirmed)
R=$(nft list chain bridge pvefw-neo vm_veth2003i0_in 2>&1 | grep -c "udp dport 5000-5100 accept")
[ "$R" -ge 1 ] && R="yes" || R="no"
check "Bare rule: UDP/5000-5100 rule present" "yes" "$R"

# 7b. TCP 3000 with sport 1024:65535
start_listener 2003 3000
R=$(tcp_connect 2004 10.99.0.13 3000)
check "Bare rule: TCP/3000 (sport 1024-65535)" "RESPONSE_3000" "$R"


echo ""
echo "── 8. Policy enforcement ──"

# 8a. Unlisted IN port → DROPped (policy_in: DROP)
R=$(tcp_check 2004 10.99.0.13 12345)
check "Policy DROP: unlisted port 12345 blocked" "CLOSED" "$R"

# 8b. OUT default ACCEPT → passes (policy_out: ACCEPT)
R=$(pct exec 2003 -- ping -c 1 -W 2 10.99.0.1 2>&1 | grep -c "1 received")
check "Policy ACCEPT: outbound to host passes" "1" "$R"


echo ""
echo "── 9. Chain structure ──"

# 9a. OUT chains use 'jump' (not goto)
R=$(nft list chain bridge pvefw-neo forward 2>&1 | grep -c "jump vm_veth2003i0_out")
check "OUT dispatch: uses 'jump' (not goto)" "1" "$R"

# 9b. IN chains use 'goto'
R=$(nft list chain bridge pvefw-neo forward 2>&1 | grep -c "goto vm_veth2003i0_in")
check "IN dispatch: uses 'goto'" "1" "$R"

# 9c. OUT chain rules use 'return' (not accept)
R=$(nft list chain bridge pvefw-neo vm_veth2003i0_out 2>&1 | grep -c "return")
[ "$R" -ge 1 ] && R="yes" || R="no"
check "OUT chain: ACCEPT rules rendered as 'return'" "yes" "$R"

# 9d. ARP pass-through in forward chain
R=$(nft list chain bridge pvefw-neo forward 2>&1 | grep -c "ether type arp accept")
check "Forward chain: ARP pass-through rule" "1" "$R"

# 9e. conntrack in forward chain
R=$(nft list chain bridge pvefw-neo forward 2>&1 | grep -c "ct state established,related accept")
check "Forward chain: conntrack established,related" "1" "$R"


echo ""
echo "── 10. Netdev ingress (macspoof) ──"

# 10a. Per-device netdev table exists
R=$(nft list tables netdev 2>&1 | grep -c "pvefw-neo-veth2003i0")
check "Netdev table: pvefw-neo-veth2003i0 exists" "1" "$R"

# 10b. MAC filter rule present
R=$(nft list chain netdev pvefw-neo-veth2003i0 ingress 2>&1 | grep -c "02:00:00:aa:03:00 drop")
check "Netdev ingress: MAC filter for CT2003" "1" "$R"

R=$(nft list chain netdev pvefw-neo-veth2004i0 ingress 2>&1 | grep -c "02:00:00:aa:04:00 drop")
check "Netdev ingress: MAC filter for CT2004" "1" "$R"


echo ""
echo "── 11. Dry-run syntax check ──"

R=$(/usr/local/bin/pvefw-neo --dry-run 2>&1 | nft -c -f - 2>&1; echo $?)
check "Dry-run nft syntax check" "0" "$R"


# ── Cleanup listeners ──
for CTID in 2003 2004; do
    pct exec $CTID -- bash -c "pkill -f ncat 2>/dev/null; true"
done

echo ""
echo "═══════════════════════════════════════"
echo " Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "═══════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
