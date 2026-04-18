#!/bin/bash
# pvefw-neo test suite — functional tests.
# Does NOT edit .fw directly: every rule / ipset / alias mutation goes
# through pvesh (the same API the WebUI uses). Packet tests use
# qemu-guest-agent (VM) and pct exec (CT).
#
# Prereq:  bash tests/setup.sh
# Cleanup: bash tests/clean.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

# Per-test reset wrapper. Usage: run_test <name> <body-function>
run_test() {
    local name=$1; shift
    log "── $name ──"
    fw_full_reset
    "$@"
}

# Reach-test helpers. Both guests must have ifaces on the same bridge.
# Slot 1 is the default probe slot; other slots reserved for multi-port
# scenarios (isolation, multi-MAC, ...).
probe_ping() {
    local backend=$1 slot=${2:-1}
    local off=0
    [ "$backend" = "ovs" ] && off=$N_SLOTS
    local vm_iface="eth$((slot + off))"
    local ct_ip
    ct_ip=$(slot_ip "$backend" "$slot" "$CT_HOST_OCTET")
    ping_between vm "$vm_iface" "$ct_ip" && echo PASS || echo FAIL
}

# probe_ping_rev — initiate ping from CT toward VM. Use for IN-direction
# rule tests: VM→CT replies ride `ct state established,related accept`
# in the forward chain and bypass per-iface IN rules, so the rule never
# actually evaluates. CT-initiated pings create NEW connections that
# hit VM's IN chain as intended.
probe_ping_rev() {
    local backend=$1 slot=${2:-1}
    local off=0
    [ "$backend" = "ovs" ] && off=$N_SLOTS
    local ct_iface="eth$((slot + off))"
    local vm_ip
    vm_ip=$(slot_ip "$backend" "$slot" "$VM_HOST_OCTET")
    ping_between ct "$ct_iface" "$vm_ip" && echo PASS || echo FAIL
}

probe_tcp() {
    local backend=$1 slot=${2:-1} port=$3
    local ct_ip
    ct_ip=$(slot_ip "$backend" "$slot" "$CT_HOST_OCTET")
    start_listener ct "$port" >/dev/null
    tcp_check vm "$ct_ip" "$port"
}

# ─────────────── Sanity: host / baseline ───────────────

baseline() {
    log "Baseline reachability (no firewall)"
    check "linux slot1 ping VM→CT" "PASS" "$(probe_ping linux 1)"
    check "ovs   slot1 ping VM→CT" "PASS" "$(probe_ping ovs   1)"
}

# ─────────────── 1. Extension rule: macspoof ───────────────

test_macspoof_linux() {
    # Set a rule that allows only the VM's real MAC (no args = auto-read)
    local iface; iface=$(slot_iface linux 1)
    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" --comment "@neo:macspoof"
    fw_apply
    check "macspoof: legitimate VM→CT ping passes"     "PASS" "$(probe_ping linux 1)"

    # Now inject an additional allowed MAC list that does NOT include the VM's
    # real MAC (only two bogus MACs) → all traffic from this iface should drop.
    fw_clear vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" \
        --comment "@neo:macspoof aa:bb:cc:dd:ee:ff,aa:bb:cc:dd:ee:00"
    fw_apply
    check "macspoof: forged src MAC → dropped"         "FAIL" "$(probe_ping linux 1)"
}

# ─────────────── 2. Extension rule: ipspoof (via Source field) ───────────────

test_ipspoof_linux() {
    local iface vm_ip ct_ip
    iface=$(slot_iface linux 1)
    vm_ip=$(slot_ip linux 1 $VM_HOST_OCTET)
    ct_ip=$(slot_ip linux 1 $CT_HOST_OCTET)

    fw_enable vm
    # Put the VM's legit source IP in Source — @neo:ipspoof reads from there.
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" \
        --source "$vm_ip" --comment "@neo:ipspoof"
    fw_apply
    check "ipspoof: legit src IP passes"  "PASS" "$(probe_ping linux 1)"

    # Rule that only allows an unrelated IP → VM's real traffic drops.
    fw_clear vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" \
        --source "198.51.100.42/32" --comment "@neo:ipspoof"
    fw_apply
    check "ipspoof: unlisted src IP → dropped" "FAIL" "$(probe_ping linux 1)"
}

# ─────────────── 3. Extension rule: nodhcp ───────────────

test_nodhcp_linux() {
    local iface ct_ip
    iface=$(slot_iface linux 1)
    ct_ip=$(slot_ip linux 1 $CT_HOST_OCTET)
    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" --comment "@neo:nodhcp"
    fw_apply
    # Regular traffic still works
    check "nodhcp: normal traffic unaffected" "PASS" "$(probe_ping linux 1)"
    # Forge DHCP reply packet (UDP src=67 dst=68) from VM → CT
    local got
    got=$(exec_vm "hping3 -c 1 -2 -s 67 -k -p 68 -I eth1 $ct_ip 2>&1 | grep -oE '[0-9]+% packet loss'")
    check "nodhcp: DHCP-shaped UDP 67→68 dropped" "100% packet loss" "$got"
}

# ─────────────── 4. Extension rule: nora (IPv6 RA drop) ───────────────

test_nora_linux() {
    local iface; iface=$(slot_iface linux 1)
    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" --comment "@neo:nora"
    fw_apply
    # Structural: an RA-drop rule should be present in the netdev/raw chain
    local got
    got=$(nft list ruleset 2>/dev/null | grep -c "nd-router-advert drop")
    [ "$got" -ge 1 ] && got=yes || got=no
    check "nora: RA drop rule present in ruleset" "yes" "$got"
    # IPv4 traffic unaffected
    check "nora: IPv4 traffic still passes" "PASS" "$(probe_ping linux 1)"
}

# ─────────────── 5. Extension rule: nondp (IPv6 NDP drop) ───────────────

test_nondp_linux() {
    local iface; iface=$(slot_iface linux 1)
    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" --comment "@neo:nondp"
    fw_apply
    local got
    got=$(nft list ruleset 2>/dev/null | grep -c "nd-neighbor-solicit.*nd-neighbor-advert")
    [ "$got" -ge 1 ] && got=yes || got=no
    check "nondp: NS/NA drop rule present" "yes" "$got"
}

# ─────────────── 6. Extension rule: mcast_limit ───────────────

test_mcast_limit_linux() {
    local iface; iface=$(slot_iface linux 1)
    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" \
        --comment "@neo:mcast_limit 100"
    fw_apply
    # Structural: expect a limit rule with multicast mac mask
    local got
    got=$(nft list ruleset 2>/dev/null | grep -c "ether daddr & 01:00:00:00:00:00.*limit rate over 100")
    [ "$got" -ge 1 ] && got=yes || got=no
    check "mcast_limit: rule present with rate limit" "yes" "$got"
    # Regular unicast passes
    check "mcast_limit: unicast traffic unaffected" "PASS" "$(probe_ping linux 1)"
}

# ─────────────── 7. Extension rule: isolated (needs 2 ports) ───────────────

test_isolated_linux() {
    # Put VM net1 and net2 both on BR_LINUX with @neo:isolated → they can't
    # reach each other peer-to-peer, but both can still reach CT (which is
    # NOT isolated).
    local if1 if2
    if1=$(slot_iface linux 1)
    if2=$(slot_iface linux 2)
    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$if1" --comment "@neo:isolated"
    fw_apply
    # Structural check: bridge port for VM net1 (= tap<VMID>i1) should be marked
    # `isolated on` after pvefw-neo applies @neo:isolated.
    local devname="tap${VMID_VM}i1"
    local iso; iso=$(ip -d link show "$devname" 2>/dev/null | grep -o "isolated on" | head -1)
    check "isolated: bridge port marked isolated on" "isolated on" "$iso"
}

# ─────────────── 8. Decorator: @neo:srcmac bitmask ───────────────

test_srcmac_bitmask_linux() {
    local iface; iface=$(slot_iface linux 1)
    fw_enable vm
    # bitmask 00:00:00:00:00:00 never matches → rule inert, traffic passes
    fw_rule vm DROP out --iface "$iface" \
        --comment "@neo:noct @neo:srcmac bitmask 00:00:00:00:00:00"
    fw_apply
    local got
    got=$(nft list ruleset 2>/dev/null | grep -c "ether saddr & 00:00:00:00:00:00")
    [ "$got" -ge 1 ] && got=yes || got=no
    check "srcmac bitmask: rule rendered with & mask" "yes" "$got"
}

# ─────────────── 9. Decorator: @neo:dstmac ───────────────

test_dstmac_linux() {
    local iface; iface=$(slot_iface linux 1)
    fw_enable vm
    fw_rule vm DROP out --iface "$iface" \
        --comment "@neo:noct @neo:dstmac in ff:ff:ff:ff:ff:ff"
    fw_apply
    local got
    got=$(nft list ruleset 2>/dev/null | grep -c "ether daddr ff:ff:ff:ff:ff:ff")
    [ "$got" -ge 1 ] && got=yes || got=no
    check "dstmac in: rule rendered" "yes" "$got"
}

# ─────────────── 10. Decorator: @neo:vlan ───────────────

test_vlan_linux() {
    local iface; iface=$(slot_iface linux 1)
    fw_enable vm
    fw_rule vm ACCEPT out --iface "$iface" --comment "@neo:noct @neo:vlan 20"
    fw_apply
    local got
    got=$(nft list ruleset 2>/dev/null | grep -c "vlan id 20")
    [ "$got" -ge 1 ] && got=yes || got=no
    check "vlan 20: vlan match rendered" "yes" "$got"
}

# ─────────────── 11. Decorator: @neo:rateexceed ───────────────

test_rateexceed_linux() {
    local iface; iface=$(slot_iface linux 1)
    fw_enable vm
    fw_rule vm DROP out --iface "$iface" \
        --comment "@neo:noct @neo:rateexceed 50"
    fw_apply
    local got
    got=$(nft list ruleset 2>/dev/null | grep -c "limit rate over 50")
    [ "$got" -ge 1 ] && got=yes || got=no
    check "rateexceed: limit rate over 50 present" "yes" "$got"
}

# ─────────────── 12. Cross: only ipspoof enabled → forged MAC still passes ───────────────

test_cross_ipspoof_only_mac_forge() {
    local iface_vm vm_ip ct_ip eth
    iface_vm=$(slot_iface linux 1)
    eth="eth1"
    vm_ip=$(slot_ip linux 1 $VM_HOST_OCTET)
    ct_ip=$(slot_ip linux 1 $CT_HOST_OCTET)

    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface_vm" \
        --source "$vm_ip" --comment "@neo:ipspoof"
    fw_apply

    # The "real" MAC is what PVE config says (authoritative, not what /sys
    # currently reports — that could already be wrong from a prior failed
    # restore). Forge → ping → restore → verify.
    local orig_mac
    orig_mac=$(qm config "$VMID_VM" | awk '$1=="net1:"{print}' \
        | grep -oE '[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}' | head -1 | tr 'A-F' 'a-f')
    exec_vm "ip link set dev $eth down && ip link set dev $eth address 02:aa:bb:cc:dd:ee && ip link set dev $eth up && sleep 1" >/dev/null
    local res; res=$(probe_ping linux 1)
    exec_vm "ip link set dev $eth down && ip link set dev $eth address $orig_mac && ip link set dev $eth up && sleep 1" >/dev/null
    # Verify restore — fail loudly if eth1 didn't come back up with the
    # original MAC, otherwise subsequent tests silently misbehave.
    local now_mac
    now_mac=$(exec_vm "cat /sys/class/net/$eth/address" | tr -d '\r\n ')
    if [ "$now_mac" != "$orig_mac" ]; then
        warn "MAC restore FAILED: eth1=$now_mac expected=$orig_mac — retrying"
        exec_vm "ip link set dev $eth down && ip link set dev $eth address $orig_mac && ip link set dev $eth up && sleep 1" >/dev/null
    fi

    check "cross: ipspoof-only + forged MAC → passes (macspoof inert)" "PASS" "$res"
}

# ─────────────── 13. Cross: only macspoof enabled → forged src IP still passes ───────────────

test_cross_macspoof_only_ip_forge() {
    local iface_vm ct_ip ct_eth fake_src
    iface_vm=$(slot_iface linux 1)
    ct_ip=$(slot_ip linux 1 $CT_HOST_OCTET)
    ct_eth="eth1"
    # Fake src inside same /24 to avoid CT-side rp_filter dropping it.
    fake_src="$(slot_subnet linux 1).99"

    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface_vm" \
        --comment "@neo:macspoof"
    fw_apply

    # CT runs tcpdump in its OWN background using `nohup … &`. Polling
    # `/tmp/cross_cap` afterwards is race-free: we don't rely on bash's
    # `wait` propagating through pct-exec. A 2-second arm delay gives
    # tcpdump time to attach to eth1 before hping3 fires.
    exec_ct "rm -f /tmp/cross_cap; nohup sh -c 'tcpdump -i $ct_eth -nn -c 1 \"icmp and src host $fake_src\" > /tmp/cross_cap 2>&1' >/dev/null 2>&1 & disown" >/dev/null
    sleep 2
    exec_vm "hping3 -a $fake_src -1 -c 1 -I eth1 $ct_ip >/dev/null 2>&1" >/dev/null
    # Give tcpdump up to 3s to see the packet + write the file.
    sleep 3
    exec_ct "pkill -f 'tcpdump.*$fake_src' 2>/dev/null; true" >/dev/null
    local caught; caught=$(exec_ct "grep -c '$fake_src' /tmp/cross_cap 2>/dev/null || echo 0" | tr -d '\r\n ')
    local res=FAIL
    [ "${caught:-0}" -ge 1 ] && res=PASS

    check "cross: macspoof-only + forged src IP → passes (ipspoof inert)" "PASS" "$res"
}

# ─────────────── 14. Extension combo: macspoof + ipspoof ───────────────

test_spoof_combo_linux() {
    local iface vm_ip
    iface=$(slot_iface linux 1)
    vm_ip=$(slot_ip linux 1 $VM_HOST_OCTET)
    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" --comment "@neo:macspoof"
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" \
        --source "$vm_ip" --comment "@neo:ipspoof"
    fw_apply
    check "macspoof+ipspoof: legit traffic passes" "PASS" "$(probe_ping linux 1)"
}

# ─────────────── 4. Extension rule: disable ───────────────

test_disable_linux() {
    local iface; iface=$(slot_iface linux 1)
    # Per-iface OUT catch-all DROP replaces the old policy_out DROP baseline
    # (pvefw-neo no longer reads VM-level policies — per-port is the only way).
    fw_enable vm
    fw_rule vm DROP out --iface "$iface"
    fw_apply
    check "per-iface OUT DROP: outbound dropped" "FAIL" "$(probe_ping linux 1)"

    # @neo:disable → pvefw-neo skips the port entirely, catch-all doesn't apply
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" --comment "@neo:disable"
    fw_apply
    check "disable: traffic flows through untouched" "PASS" "$(probe_ping linux 1)"
}

# ─────────────── 5. Decorator: stateless + srcmac ───────────────

test_stateless_srcmac_linux() {
    local iface vm_mac
    iface=$(slot_iface linux 1)
    vm_mac=$(qm config "$VMID_VM" | awk -v n="net1" '$1==n":"{print $0}' \
              | grep -oE '[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}' | head -1)

    fw_enable vm
    # pvesh prepends: create bottom-up so final order is ACCEPT (pos 0) then DROP.
    fw_rule vm DROP out --iface "$iface" --comment "@neo:noct"
    fw_rule vm ACCEPT out --iface "$iface" \
        --comment "@neo:noct @neo:srcmac in $vm_mac"
    fw_apply
    check "stateless+srcmac in: matching MAC passes" "PASS" "$(probe_ping linux 1)"
}

# ─────────────── 6. PVE native: basic allow/drop ───────────────

test_native_basic_linux() {
    local iface; iface=$(slot_iface linux 1)
    fw_enable vm
    fw_rule vm DROP in --iface "$iface"   # catch-all; allow rules prepend above
    fw_rule vm ACCEPT in --iface "$iface" --proto icmp
    fw_apply
    # CT→VM ping: creates a NEW flow into VM, exercises IN chain.
    check "native IN ACCEPT icmp: CT→VM ping passes" "PASS" "$(probe_ping_rev linux 1)"
}

# ─────────────── 7. PVE native: SSH macro ───────────────

test_native_ssh_macro_linux() {
    local iface; iface=$(slot_iface linux 1)
    # listener inside VM, probe from CT side. We flip direction for variety.
    start_listener vm 22
    fw_enable vm
    fw_rule vm DROP in --iface "$iface"   # catch-all; allow rules prepend above
    fw_rule vm ACCEPT in --iface "$iface" --macro SSH
    fw_apply
    local ct_vm_ip; ct_vm_ip=$(slot_ip linux 1 $VM_HOST_OCTET)
    # Use CT→VM TCP 22 via the linux slot iface (default route via eth0 wouldn't
    # reach). Probe via `tcp_check` but from CT side:
    local got; got=$(exec_ct "ncat -z -w 2 $ct_vm_ip 22 && echo OPEN || echo CLOSED" | tr -d '\r\n')
    check "native IN ACCEPT SSH macro: port 22 open" "OPEN" "$got"
}

# ─────────────── 8. PVE native: local ipset with match + nomatch ───────────────

test_native_ipset_match_nomatch_linux() {
    local iface ct_ip ct_subnet
    iface=$(slot_iface linux 1)
    ct_ip=$(slot_ip linux 1 $CT_HOST_OCTET)
    ct_subnet="$(slot_subnet linux 1).0/24"

    # VM-local ipset: allow whole /24 except CT's specific IP (nomatch)
    guest_ipset_create vm tst_whitelist
    guest_ipset_add    vm tst_whitelist "$ct_subnet"
    guest_ipset_add    vm tst_whitelist "$ct_ip" 1     # nomatch

    fw_enable vm
    fw_rule vm DROP in --iface "$iface"   # catch-all; allow rules prepend above
    fw_rule vm ACCEPT in --iface "$iface" --proto icmp --source "+tst_whitelist"
    fw_apply
    # CT→VM ping: CT is excluded from whitelist via nomatch → rule doesn't match → drop
    check "ipset match+nomatch: CT excluded → ping drops" "FAIL" "$(probe_ping_rev linux 1)"
}

# ─────────────── 9. PVE native: cluster alias + ipset cross-ref ───────────────

test_native_cluster_alias_linux() {
    local iface ct_ip
    iface=$(slot_iface linux 1)
    ct_ip=$(slot_ip linux 1 $CT_HOST_OCTET)

    # Datacenter alias → VM-local rule references it via dc/<name>
    cluster_alias_create tst_peer "$ct_ip"

    fw_enable vm
    fw_rule vm DROP in --iface "$iface"   # catch-all; allow rules prepend above
    fw_rule vm ACCEPT in --iface "$iface" --proto icmp --source "dc/tst_peer"
    fw_apply
    # CT→VM ping: rule allows src matching dc/tst_peer = CT's IP → passes
    check "native dc/ alias: CT→VM ping passes" "PASS" "$(probe_ping_rev linux 1)"
}

# ─────────────── 10. PVE native: cluster ipset referencing dc alias ───────────────

test_native_complex_ipset_linux() {
    local iface ct_ip ct_subnet
    iface=$(slot_iface linux 1)
    ct_ip=$(slot_ip linux 1 $CT_HOST_OCTET)
    ct_subnet="$(slot_subnet linux 1).0/24"

    cluster_alias_create tst_ct "$ct_ip"
    cluster_ipset_create tst_dc_set
    # Positive: whole subnet; nomatch: alias-resolved CT
    cluster_ipset_add tst_dc_set "$ct_subnet"
    cluster_ipset_add tst_dc_set "$ct_ip" 1
    fw_enable vm
    fw_rule vm DROP in --iface "$iface"   # catch-all; allow rules prepend above
    fw_rule vm ACCEPT in --iface "$iface" --proto icmp --source "+dc/tst_dc_set"
    fw_apply
    # CT→VM ping: CT excluded via nomatch → rule doesn't match → drop
    check "cluster ipset match+nomatch via dc ref: CT excluded" "FAIL" "$(probe_ping_rev linux 1)"
}

# ─────────────── 11. OVS backend parity: basic native rule ───────────────

test_native_basic_ovs() {
    local iface; iface=$(slot_iface ovs 1)
    fw_enable vm
    fw_rule vm DROP in --iface "$iface"   # catch-all; allow rules prepend above
    fw_rule vm ACCEPT in --iface "$iface" --proto icmp
    fw_apply
    check "OVS native IN ACCEPT icmp: CT→VM ping passes" "PASS" "$(probe_ping_rev ovs 1)"
}

# ─────────────── 12. OVS backend: macspoof + ipspoof combo ───────────────

test_spoof_combo_ovs() {
    local iface vm_ip
    iface=$(slot_iface ovs 1)
    vm_ip=$(slot_ip ovs 1 $VM_HOST_OCTET)
    fw_enable vm
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" --comment "@neo:macspoof"
    fw_rule_extension vm DROP out --macro Finger --iface "$iface" \
        --source "$vm_ip" --comment "@neo:ipspoof"
    fw_apply
    check "OVS macspoof+ipspoof: legit traffic passes" "PASS" "$(probe_ping ovs 1)"
    # Negative: forged IP should be DROPPED (ipspoof pure-nomatch flows)
    local ct_ip; ct_ip=$(slot_ip ovs 1 $CT_HOST_OCTET)
    exec_ct "rm -f /tmp/ovs_spoof_cap; nohup sh -c 'tcpdump -i eth4 -nn -c 1 \"icmp and src host 172.30.1.99\" > /tmp/ovs_spoof_cap 2>&1' >/dev/null 2>&1 & disown" >/dev/null
    sleep 2
    exec_vm "hping3 -a 172.30.1.99 -1 -c 1 -I eth4 $ct_ip >/dev/null 2>&1" >/dev/null
    sleep 3
    exec_ct "pkill -f 'tcpdump.*172.30.1.99' 2>/dev/null; true" >/dev/null
    local caught; caught=$(exec_ct "grep -c '172.30.1.99' /tmp/ovs_spoof_cap 2>/dev/null || echo 0" | tr -d '\r\n ')
    local res=PASS
    [ "${caught:-0}" -ge 1 ] && res=FAIL
    check "OVS ipspoof: forged src IP → dropped" "PASS" "$res"
}

# ─────────────── 13. OVS backend: ipset with nomatch (CIDR pre-subtraction) ───────────────

test_ipset_nomatch_ovs() {
    local iface ct_ip ct_subnet
    iface=$(slot_iface ovs 1)
    ct_ip=$(slot_ip ovs 1 $CT_HOST_OCTET)
    ct_subnet="$(slot_subnet ovs 1).0/24"
    guest_ipset_create vm tst_ovs_set
    guest_ipset_add    vm tst_ovs_set "$ct_subnet"
    guest_ipset_add    vm tst_ovs_set "$ct_ip" 1
    fw_enable vm
    fw_rule vm DROP in --iface "$iface"   # catch-all; allow rules prepend above
    fw_rule vm ACCEPT in --iface "$iface" --proto icmp --source "+tst_ovs_set"
    fw_apply
    check "OVS ipset match+nomatch: CT excluded" "FAIL" "$(probe_ping_rev ovs 1)"
}

# ─────────────── 14. Quarantine: OVS rejects ether/proto family mismatch ───────────────
#
# Rule forces ether_type=ip but proto/icmp-type require ipv6. ovs-ofctl
# must reject with "icmpv6_type requires ipv6"; quarantine flips the
# rule's enable=1→0 in .fw and writes a firewall-log entry. Baseline
# traffic on the same bridge stays unaffected.
test_quarantine_ovs_icmp_family() {
    local iface; iface=$(slot_iface ovs 1)
    fw_enable vm
    # Bottom rule first (pvesh prepends), so the bad rule ends up at pos 0.
    fw_rule vm DROP out --iface "$iface" --proto icmpv6 \
        --icmp-type echo-request --comment "@neo:noct @neo:ether ip"
    fw_apply

    check "OVS ether/proto quarantine: rule #0 auto-disabled" \
          "0" "$(fw_rule_enabled vm 0)"
    check "OVS ether/proto quarantine: log entry present" \
          "YES" "$(fw_log_has_quarantine vm 0)"
    check "OVS ether/proto quarantine: baseline ping on same bridge intact" \
          "PASS" "$(probe_ping ovs 1)"
}

# ─────────────── 15. Quarantine: nft rejects ipset family mismatch ───────────────
#
# An ipv6-only ipset referenced from a rule forced to ether_type=ip yields
# `ether type ip ip saddr @v6set_...` — nft refuses at load time with a
# datatype mismatch. Same observable outcome as OVS test: rule disabled +
# log entry.
test_quarantine_nft_set_family() {
    local iface; iface=$(slot_iface linux 1)
    guest_ipset_create vm tst_qnft_v6
    guest_ipset_add    vm tst_qnft_v6 "2001:db8::/64"
    fw_enable vm
    # @neo:noct + @neo:ether ip forces ether=ipv4, but set is ipv6-only.
    fw_rule vm DROP out --iface "$iface" --source "+tst_qnft_v6" \
        --comment "@neo:noct @neo:ether ip"
    fw_apply

    check "nft set-family quarantine: rule #0 auto-disabled" \
          "0" "$(fw_rule_enabled vm 0)"
    check "nft set-family quarantine: log entry present" \
          "YES" "$(fw_log_has_quarantine vm 0)"
    check "nft set-family quarantine: baseline ping on same bridge intact" \
          "PASS" "$(probe_ping linux 1)"
}

# ─────────────── 16. Quarantine: self-heal after user fixes + re-enables ───────────────
#
# After quarantine disables the rule, the user fixes the contradiction
# (removes @neo:ether ip) and re-enables. Next apply should leave the
# rule enabled and no new quarantine log entry should appear for it.
test_quarantine_self_heal() {
    local iface; iface=$(slot_iface ovs 1)
    fw_enable vm
    fw_rule vm DROP out --iface "$iface" --proto icmpv6 \
        --icmp-type echo-request --comment "@neo:noct @neo:ether ip"
    fw_apply
    check "self-heal prep: quarantine fired" "0" "$(fw_rule_enabled vm 0)"

    # User repairs: drop the contradictory ether tag, put it back to @neo:noct
    # only, and re-enable. Delete + re-add is cleanest via pvesh.
    pvesh delete "$(vm_fw_base)/rules/0" >/dev/null
    fw_rule vm DROP out --iface "$iface" --proto icmpv6 \
        --icmp-type echo-request --comment "@neo:noct"
    fw_apply

    check "self-heal: rule stays enabled after fix" \
          "1" "$(fw_rule_enabled vm 0)"
}

# ─────────────── Main ───────────────

log "═══ pvefw-neo test suite ═══"
log "node=$NODE VM=$VMID_VM CT=$VMID_CT"
log "BR_LINUX=$BR_LINUX BR_OVS=$BR_OVS N_SLOTS=$N_SLOTS"
echo

# Baseline first (no firewall rules) to confirm ifaces + tooling OK.
fw_full_reset
baseline

# ─── Pass 1: each pvefw-neo feature in isolation ───
# Extension rules (one at a time)
run_test "Ext:macspoof"        test_macspoof_linux
run_test "Ext:ipspoof"         test_ipspoof_linux
run_test "Ext:nodhcp"          test_nodhcp_linux
run_test "Ext:nora"            test_nora_linux
run_test "Ext:nondp"           test_nondp_linux
run_test "Ext:mcast_limit"     test_mcast_limit_linux
run_test "Ext:isolated"        test_isolated_linux
run_test "Ext:disable"         test_disable_linux

# Decorators (one at a time)
run_test "Dec:stateless+srcmac in" test_stateless_srcmac_linux
run_test "Dec:srcmac bitmask"       test_srcmac_bitmask_linux
run_test "Dec:dstmac"               test_dstmac_linux
run_test "Dec:vlan"                 test_vlan_linux
run_test "Dec:rateexceed"           test_rateexceed_linux

# ─── Pass 2: cross tests (only one feature enabled ⇒ others must not block) ───
# Run the non-destructive one first; mac-forge mutates VM eth1 state and has
# to restore, so it goes last to avoid polluting subsequent tests if restore
# flakes.
run_test "Cross:macspoof-only + forged IP"  test_cross_macspoof_only_ip_forge
run_test "Cross:ipspoof-only + forged MAC"  test_cross_ipspoof_only_mac_forge

# ─── Pass 3: combinations of pvefw-neo features ───
run_test "Ext:macspoof+ipspoof" test_spoof_combo_linux

# PVE native (Linux)
run_test "Native:basic ICMP"           test_native_basic_linux
run_test "Native:SSH macro"            test_native_ssh_macro_linux
run_test "Native:ipset match+nomatch"  test_native_ipset_match_nomatch_linux
run_test "Native:cluster alias dc/"    test_native_cluster_alias_linux
run_test "Native:cluster ipset mix"    test_native_complex_ipset_linux

# OVS backend parity
run_test "OVS:basic ICMP"             test_native_basic_ovs
run_test "OVS:macspoof+ipspoof"       test_spoof_combo_ovs
run_test "OVS:ipset match+nomatch"    test_ipset_nomatch_ovs

# ─── Pass 4: quarantine (bad rules auto-disabled + firewall log) ───
run_test "Quarantine:OVS icmp family" test_quarantine_ovs_icmp_family
run_test "Quarantine:nft set family"  test_quarantine_nft_set_family
run_test "Quarantine:self-heal"       test_quarantine_self_heal

# Final reset so the env ends clean
fw_full_reset

echo
log "═══ Results: $PASSES passed, $FAILS failed ═══"
exit $FAILS
