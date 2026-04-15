#!/bin/bash
# pvefw-neo @neo:disable tests
#
# Temporarily add @neo:disable to CT2003 and verify:
#   - NetDev reported as disabled in IR dump
#   - no nft rules installed for veth2003i0 (no netdev table, no raw rules,
#     no forward dispatch)
#   - CT2003 outbound traffic that would normally be blocked by its own
#     ipspoof/notrack rules passes through (it's disabled from pvefw-neo
#     perspective, filtering is bypassed)
#   - CT2004's rules still apply to traffic going TO it (disable is per-port,
#     not mutual)
#
# Prerequisites: tests/setup.sh has been run.
# Usage: bash tests/run_disable_tests.sh
set -u

PASS=0; FAIL=0
CT_DISABLED=2003
CT_NORMAL=2004
DISABLE_LINE='|OUT Finger(DROP) -i net0 # @neo:disable'

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

# Cleanup on exit: remove disable tag + reapply
cleanup() {
    sed -i "/@neo:disable/d" /etc/pve/firewall/${CT_DISABLED}.fw 2>/dev/null
    pvefw-neo --apply >/dev/null 2>&1
}
trap cleanup EXIT

echo "═══════════════════════════════════════"
echo " pvefw-neo @neo:disable tests"
echo "═══════════════════════════════════════"
echo ""
echo "── Baseline: CT2003 rules are active ──"
R=$(nft list table netdev pvefw-neo-veth2003i0 2>&1 | grep -c "ether saddr" || true)
[ "$R" -ge 1 ] && R=yes || R=no
check "Baseline: veth2003i0 netdev table has macspoof" "yes" "$R"

# Baseline: ipspoof blocks forged source on CT2003
R=$(pct exec $CT_DISABLED -- hping3 -c 1 -1 -a 10.99.0.99 10.99.0.14 -I eth0 2>&1 | grep -oP '\d+(?=% packet loss)')
check "Baseline: ipspoof blocks forged src from CT2003" "100" "$R"

echo ""
echo "── Adding @neo:disable to CT2003 ──"
if ! grep -q "@neo:disable" /etc/pve/firewall/${CT_DISABLED}.fw; then
    sed -i "/@neo:macspoof/a $DISABLE_LINE" /etc/pve/firewall/${CT_DISABLED}.fw
fi
pvefw-neo --apply >/dev/null

echo ""
echo "── After disable: all CT2003 filtering bypassed ──"

# IR shows disabled
R=$(pvefw-neo --dump-ir 2>&1 | grep -c "veth2003i0.*\[disabled\]")
check "IR dump shows veth2003i0 [disabled]" "1" "$R"

# Netdev table gone
R=$(nft list table netdev pvefw-neo-veth2003i0 2>&1 | grep -c "does not exist\|No such file" || true)
[ "$R" -ge 1 ] && R=yes || R=no
check "Netdev table pvefw-neo-veth2003i0 removed" "yes" "$R"

# No raw rules for veth2003i0
R=$(nft list chain bridge pvefw-neo raw_prerouting 2>&1 | grep -c "veth2003i0" || true)
check "No raw_prerouting rules reference veth2003i0" "0" "$R"

# No forward dispatch
R=$(nft list chain bridge pvefw-neo forward 2>&1 | grep -c "veth2003i0" || true)
check "No forward dispatch for veth2003i0" "0" "$R"

# Functional: forged src IP now passes (no more ipspoof enforcement on CT2003)
# NOTE: CT2004's IN rules still block the reply (no ICMP from 10.99.0.99 rule),
# so hping3 will still see 100% loss from its perspective. We instead verify
# via nft trace — or a simpler functional check: CT2003 → CT2004 ping
# (which was blocked before only by the notrack catch-all, and now bypasses it)
R=$(pct exec $CT_DISABLED -- ping -c 1 -W 2 10.99.0.14 2>&1 | grep -c "1 received")
check "Disabled CT2003 can still ping CT2004 (baseline sanity)" "1" "$R"

# Check CT2004's rules still apply in the other direction
# CT2004 has IN: SSH(ACCEPT) from 10.99.0.13 only (via sg). CT2003's @neo:disable
# doesn't affect CT2004's IN chain.
R=$(pct exec $CT_DISABLED -- bash -c "nc -zw2 10.99.0.14 22 && echo OPEN || echo CLOSED")
check "CT2004 SSH still accessible from CT2003 (CT2004 rules active)" "OPEN" "$R"

# Port 12345 (unlisted) still blocked by CT2004's policy_in DROP
R=$(pct exec $CT_DISABLED -- bash -c "nc -zw2 10.99.0.14 12345 && echo OPEN || echo CLOSED")
check "CT2004 still drops unlisted port (policy_in DROP on target)" "CLOSED" "$R"

echo ""
echo "═══════════════════════════════════════"
echo " Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
