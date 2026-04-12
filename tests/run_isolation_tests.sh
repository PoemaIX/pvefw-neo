#!/bin/bash
# pvefw-neo isolation tests (semantic A: two isolated ports cannot communicate)
#
# This test temporarily adds @neo:isolated to all 4 test CTs (2003-2006),
# applies the ruleset, runs assertions, then removes the isolation tags
# and re-applies. NOTE: cannot run in parallel with run_tests.sh since
# both modify the same .fw files.
#
# Prerequisites: tests/setup.sh has been run.
# Usage: bash tests/run_isolation_tests.sh
set -u

PASS=0; FAIL=0
ISOLATION_LINE='|OUT Finger(DROP) -enable 0 -i net0 # @neo:isolated'

# Cleanup on exit: remove isolation tags
cleanup() {
    for ct in 2003 2004 2005 2006; do
        sed -i "/@neo:isolated/d" /etc/pve/firewall/${ct}.fw 2>/dev/null
    done
    pvefw-neo --apply >/dev/null 2>&1
}
trap cleanup EXIT

# Add @neo:isolated to all 4 CTs (idempotent)
for ct in 2003 2004 2005 2006; do
    if ! grep -q "@neo:isolated" /etc/pve/firewall/${ct}.fw 2>/dev/null; then
        # Insert after macspoof line
        sed -i "/@neo:macspoof/a $ISOLATION_LINE" /etc/pve/firewall/${ct}.fw
    fi
done
pvefw-neo --apply >/dev/null
sleep 1

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

echo "═══════════════════════════════════════"
echo " pvefw-neo Isolation Tests"
echo " (semantic A: two isolated ports cannot communicate)"
echo "═══════════════════════════════════════"

# Verify isolation is applied
echo ""
echo "── Pre-flight: verify isolation state ──"
for ct in 2003 2004 2005 2006; do
    dev=$(case $ct in 2003) echo veth2003i0;; 2004) echo veth2004i0;;
                       2005) echo veth2005i0;; 2006) echo veth2006i0;; esac)
    if [ "$ct" = "2003" ] || [ "$ct" = "2004" ]; then
        # Linux bridge: check kernel flag
        iso=$(ip -d link show $dev 2>/dev/null | grep -oP 'isolated \K\w+' | head -1)
        check "$dev kernel isolated flag" "on" "$iso"
    else
        # OVS bridge: check reg0 + drop flow
        cnt=$(ovs-ofctl dump-flows vmbr2 2>&1 | grep -c "reg0=0x1.*$(case $ct in 2005) echo bb:01:00;; 2006) echo bb:02:00;; esac)" || true)
        [ "$cnt" -ge 1 ] && r="yes" || r="no"
        check "$dev OVS reg0+drop flow present" "yes" "$r"
    fi
done

echo ""
echo "── Linux bridge (vmbr1) ──"

# Clear ARP caches
pct exec 2003 -- ip neigh flush all 2>/dev/null
pct exec 2004 -- ip neigh flush all 2>/dev/null

R=$(pct exec 2003 -- ping -c 2 -W 2 10.99.0.14 2>&1 | grep -oE "[0-9]+ received")
check "CT2003(iso)→CT2004(iso) blocked" "0 received" "$R"

R=$(pct exec 2004 -- ping -c 2 -W 2 10.99.0.13 2>&1 | grep -oE "[0-9]+ received")
check "CT2004(iso)→CT2003(iso) blocked" "0 received" "$R"

R=$(ping -c 1 -W 2 10.99.0.13 2>&1 | grep -c "1 received")
check "Host(non-iso)→CT2003(iso) allowed" "1" "$R"

R=$(ping -c 1 -W 2 10.99.0.14 2>&1 | grep -c "1 received")
check "Host(non-iso)→CT2004(iso) allowed" "1" "$R"

echo ""
echo "── OVS bridge (vmbr2) ──"

pct exec 2005 -- ip neigh flush all 2>/dev/null
pct exec 2006 -- ip neigh flush all 2>/dev/null
sleep 1

R=$(pct exec 2005 -- ping -c 2 -W 2 10.98.0.12 2>&1 | grep -oE "[0-9]+ received")
check "CT2005(iso)→CT2006(iso) blocked" "0 received" "$R"

R=$(pct exec 2006 -- ping -c 2 -W 2 10.98.0.11 2>&1 | grep -oE "[0-9]+ received")
check "CT2006(iso)→CT2005(iso) blocked" "0 received" "$R"

R=$(ping -c 1 -W 2 10.98.0.11 2>&1 | grep -c "1 received")
check "Host(non-iso)→CT2005(iso) allowed" "1" "$R"

R=$(ping -c 1 -W 2 10.98.0.12 2>&1 | grep -c "1 received")
check "Host(non-iso)→CT2006(iso) allowed" "1" "$R"

echo ""
echo "═══════════════════════════════════════"
echo " Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
