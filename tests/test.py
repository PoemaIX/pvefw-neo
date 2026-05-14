#!/usr/bin/env python3
"""pvefw-neo test suite — functional tests.

Every rule / ipset / alias mutation goes through pvesh (the same API the WebUI
uses); packet tests run inside the guests. Each feature is exercised in BOTH
directions:

  * OFF  — with no protecting rule, the packet that *should* be blocked still
           gets through (proves the test actually moves traffic).
  * ON   — the rule is applied: the bad packet is now dropped, and traffic that
           should still be allowed is verified to pass.

Parallelism — slot job-pool
---------------------------
Each backend has N_SLOTS lanes (= guest NICs), each on its own /24. A lane is a
(backend, slot) pair; a test owns its lane exclusively while it runs, so two
tests never share an L2 broadcast domain. Capture-based checks additionally
scope their BPF to the expected sender's MAC, so a frame leaked onto the shared
bridge can never be miscounted. MAC-mutating and rule-position-sensitive tests
run in a short serial phase afterwards.

Prereq:  python3 tests/setup.py
Cleanup: python3 tests/clean.py
"""

import queue
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib import (
    CFG, log, ok, fail, warn,
    sh, slot_iface, slot_ip, slot_subnet, slot_cidr, slot_netindex,
    slot_mac, guest_ifname, vm_tap,
    fw_rule, fw_ext, fw_enable, fw_disable, fw_apply, fw_global_reset,
    slot_clear, slot_ct_flush,
    fw_rule_enabled, fw_log_has_quarantine,
    guest_ipset_create, guest_ipset_add, guest_ipset_del,
    cluster_ipset_create, cluster_ipset_add, cluster_ipset_del,
    cluster_alias_create, cluster_alias_set, cluster_alias_del,
    pvesh_json, fw_base,
    probe_ping, probe_ping_rev, tcp_check, start_listener,
    cap_start, cap_count, exec_vm, agent_send,
)


# ─────────────────────────── Test context ───────────────────────────
class TestCtx:
    """Per-(test, lane) handle. Carries the lane's addressing and a check()
    that records results for the runner to print after the lane joins."""

    def __init__(self, name, backend, slot):
        self.name = name
        self.backend = backend
        self.slot = slot
        self.iface = slot_iface(backend, slot)            # netN
        self.netindex = slot_netindex(backend, slot)
        self.vm_eth = guest_ifname("vm", backend, slot)    # in-guest ifname
        self.ct_eth = guest_ifname("ct", backend, slot)
        self.vm_ip = slot_ip(backend, slot, CFG.vm_octet)
        self.ct_ip = slot_ip(backend, slot, CFG.ct_octet)
        self.vm_mac = slot_mac("vm", backend, slot)
        self.ct_mac = slot_mac("ct", backend, slot)
        self.subnet = slot_subnet(backend, slot)
        self.cidr = slot_cidr(backend, slot)
        self.suffix = f"_{backend}_{slot}"                 # unique ipset/alias suffix
        self.results = []                                  # (passed: bool, label, detail)

    # ── assertions ──
    def check(self, label, expect, got):
        passed = str(expect) == str(got)
        detail = "" if passed else f"expected [{expect}] got [{got}]"
        self.results.append((passed, f"{self.name}: {label}", detail))

    # ── convenience ──
    def ping(self):
        return probe_ping(self.backend, self.slot)

    def ping_rev(self):
        return probe_ping_rev(self.backend, self.slot)

    def reset(self):
        """Clear this lane's rules and re-apply — used between phases of a test."""
        slot_clear("vm", self.backend, self.slot)
        slot_clear("ct", self.backend, self.slot)
        fw_apply()
        slot_ct_flush(self.backend, self.slot)


def nft_ruleset():
    return sh(["nft", "list", "ruleset"]).stdout


# ─────────────────────────── Extension / sugar tests ───────────────────────────
def test_macspoof(t):
    """macspoof: only whitelisted source MACs may egress."""
    t.check("off: traffic escapes when unmanaged", "PASS", t.ping())
    # ON, bogus allow-list (VM's real MAC NOT listed) → all VM traffic dropped.
    fw_ext("vm", t.iface, "@neo:macspoof aa:bb:cc:dd:ee:ff,aa:bb:cc:dd:ee:00")
    fw_apply()
    t.check("on: non-whitelisted src MAC dropped", "FAIL", t.ping())
    # ON, auto-read (= VM's real MAC) → legit traffic passes.
    t.reset()
    fw_ext("vm", t.iface, "@neo:macspoof")
    fw_apply()
    t.check("on: whitelisted src MAC passes", "PASS", t.ping())


def test_ipspoof(t):
    """ipspoof: only listed source IPs may egress."""
    t.check("off: traffic escapes when unmanaged", "PASS", t.ping())
    fw_ext("vm", t.iface, "@neo:ipspoof", source="198.51.100.42/32")
    fw_apply()
    t.check("on: unlisted src IP dropped", "FAIL", t.ping())
    t.reset()
    fw_ext("vm", t.iface, "@neo:ipspoof", source=t.vm_ip)
    fw_apply()
    t.check("on: listed src IP passes", "PASS", t.ping())


def test_nodhcp(t):
    """nodhcp: drop DHCP-server-shaped frames (UDP 67→68)."""
    tag = f"nodhcp{t.netindex}"
    bpf = f"ether src {t.vm_mac} and udp and src port 67 and dst port 68"

    def fire():
        agent_send("vm", "dhcp", t.vm_eth, t.vm_mac, eth_dst=t.ct_mac,
                   ip_src=t.vm_ip, ip_dst=t.ct_ip)

    # OFF — the DHCP-shaped frame escapes to the CT.
    cap_start("ct", t.ct_eth, tag, bpf, secs=3)
    fire()
    time.sleep(3)
    t.check("off: DHCP-shaped UDP 67→68 escapes", True, cap_count("ct", tag) >= 1)
    # ON — frame is dropped, ordinary traffic still flows.
    fw_ext("vm", t.iface, "@neo:nodhcp")
    fw_apply()
    cap_start("ct", t.ct_eth, tag, bpf, secs=3)
    fire()
    time.sleep(3)
    t.check("on: DHCP-shaped UDP 67→68 dropped", True, cap_count("ct", tag) == 0)
    t.check("on: ordinary traffic still passes", "PASS", t.ping())


def test_nora(t):
    """nora: drop outbound IPv6 Router Advertisement (real packet test)."""
    tag = f"nora{t.netindex}"
    bpf = f"ether src {t.vm_mac} and icmp6 and ip6[40] == 134"
    # OFF — the forged RA escapes to the CT.
    cap_start("ct", t.ct_eth, tag, bpf, secs=3)
    agent_send("vm", "ra", t.vm_eth, t.vm_mac)
    time.sleep(3)
    t.check("off: Router Advertisement escapes", True, cap_count("ct", tag) >= 1)
    # ON — RA dropped, IPv4 traffic still flows.
    fw_ext("vm", t.iface, "@neo:nora")
    fw_apply()
    cap_start("ct", t.ct_eth, tag, bpf, secs=3)
    agent_send("vm", "ra", t.vm_eth, t.vm_mac)
    time.sleep(3)
    t.check("on: Router Advertisement dropped", True, cap_count("ct", tag) == 0)
    t.check("on: IPv4 traffic unaffected", "PASS", t.ping())


def test_nondp(t):
    """nondp: drop outbound IPv6 NS + NA (real packet test)."""
    tag = f"nondp{t.netindex}"
    bpf = f"ether src {t.vm_mac} and icmp6 and (ip6[40] == 135 or ip6[40] == 136)"

    def fire():
        agent_send("vm", "ns", t.vm_eth, t.vm_mac)
        agent_send("vm", "na", t.vm_eth, t.vm_mac)

    # OFF — both NS and NA escape to the CT.
    cap_start("ct", t.ct_eth, tag, bpf, secs=3)
    fire()
    time.sleep(3)
    t.check("off: NS + NA escape", True, cap_count("ct", tag) >= 2)
    # ON — both dropped, IPv4 traffic still flows.
    fw_ext("vm", t.iface, "@neo:nondp")
    fw_apply()
    cap_start("ct", t.ct_eth, tag, bpf, secs=3)
    fire()
    time.sleep(3)
    t.check("on: NS + NA dropped", True, cap_count("ct", tag) == 0)
    t.check("on: IPv4 traffic unaffected", "PASS", t.ping())


def test_mcast_limit(t):
    """mcast_limit: rate-limit multicast frames (structural)."""
    rate = 4200 + t.slot
    pat = f"limit rate over {rate}"
    t.check("off: mcast rate-limit rule absent", True, pat not in nft_ruleset())
    fw_ext("vm", t.iface, f"@neo:mcast_limit {rate}")
    fw_apply()
    rs = nft_ruleset()
    t.check("on: mcast rate-limit rule present", True,
            pat in rs and "ether daddr & 01:00:00:00:00:00" in rs)
    t.check("on: unicast traffic unaffected", "PASS", t.ping())


def test_disable(t):
    """disable: @neo:disable un-manages the port entirely."""
    t.check("off: traffic escapes when unmanaged", "PASS", t.ping())
    fw_rule("vm", "DROP", "out", iface=t.iface)
    fw_apply()
    t.check("on: per-iface OUT DROP blocks traffic", "FAIL", t.ping())
    fw_ext("vm", t.iface, "@neo:disable")
    fw_apply()
    t.check("disable: port un-managed, traffic flows", "PASS", t.ping())


def test_ctinvdrop(t):
    """ctinvdrop: drop ct-state=invalid on both IN and OUT (structural)."""
    t.check("off: ct-invalid drop absent", True, "ct state invalid" not in nft_ruleset())
    fw_ext("vm", t.iface, "@neo:ctinvdrop")
    fw_apply()
    t.check("on: ct-invalid drop present on IN + OUT", True,
            nft_ruleset().count("ct state invalid") >= 2)
    t.check("on: ordinary traffic unaffected", "PASS", t.ping())


def test_isolated(t):
    """isolated: @neo:isolated marks the bridge port `isolated on` (structural;
    a real two-port test would need both ports in one subnet)."""
    tap = vm_tap(t.backend, t.slot)

    def is_isolated():
        return "isolated on" in sh(["ip", "-d", "link", "show", tap]).stdout

    t.check("off: bridge port not isolated", True, not is_isolated())
    fw_ext("vm", t.iface, "@neo:isolated")
    fw_apply()
    t.check("on: bridge port marked isolated", True, is_isolated())


# ─────────────────────────── Decorator tests ───────────────────────────
def test_srcmac_in(t):
    """@neo:srcmac in — rule scoped to a source-MAC whitelist."""
    t.check("off: traffic escapes when unmanaged", "PASS", t.ping())
    # catch-all DROP, then ACCEPT scoped to the VM's real src MAC (on top).
    fw_rule("vm", "DROP", "out", iface=t.iface, comment="@neo:noct")
    fw_rule("vm", "ACCEPT", "out", iface=t.iface,
            comment=f"@neo:noct @neo:srcmac in {t.vm_mac}")
    fw_apply()
    t.check("on: matching src MAC passes", "PASS", t.ping())
    # ACCEPT scoped to a bogus MAC → VM traffic falls through to the DROP.
    t.reset()
    fw_rule("vm", "DROP", "out", iface=t.iface, comment="@neo:noct")
    fw_rule("vm", "ACCEPT", "out", iface=t.iface,
            comment="@neo:noct @neo:srcmac in aa:bb:cc:dd:ee:ff")
    fw_apply()
    t.check("on: non-matching src MAC dropped", "FAIL", t.ping())


def test_srcmac_bitmask(t):
    """@neo:srcmac bitmask — match when (src_mac & mask) == mask."""
    t.check("off: traffic escapes when unmanaged", "PASS", t.ping())
    # mask = the VM's own MAC → (mac & mac) == mac is always true → ACCEPT hits.
    fw_rule("vm", "DROP", "out", iface=t.iface, comment="@neo:noct")
    fw_rule("vm", "ACCEPT", "out", iface=t.iface,
            comment=f"@neo:noct @neo:srcmac bitmask {t.vm_mac}")
    fw_apply()
    t.check("on: bitmask satisfied by src MAC → passes", "PASS", t.ping())
    # mask = all-ones → only an all-ff MAC satisfies it → never matches.
    t.reset()
    fw_rule("vm", "DROP", "out", iface=t.iface, comment="@neo:noct")
    fw_rule("vm", "ACCEPT", "out", iface=t.iface,
            comment="@neo:noct @neo:srcmac bitmask ff:ff:ff:ff:ff:ff")
    fw_apply()
    t.check("on: bitmask not satisfied → dropped", "FAIL", t.ping())


def test_dstmac(t):
    """@neo:dstmac in — rule scoped to a destination-MAC whitelist."""
    t.check("off: traffic escapes when unmanaged", "PASS", t.ping())
    # VM→CT echo-request carries the CT's MAC as dst → matches.
    fw_rule("vm", "DROP", "out", iface=t.iface, comment="@neo:noct")
    fw_rule("vm", "ACCEPT", "out", iface=t.iface,
            comment=f"@neo:noct @neo:dstmac in {t.ct_mac}")
    fw_apply()
    t.check("on: matching dst MAC passes", "PASS", t.ping())
    t.reset()
    fw_rule("vm", "DROP", "out", iface=t.iface, comment="@neo:noct")
    fw_rule("vm", "ACCEPT", "out", iface=t.iface,
            comment="@neo:noct @neo:dstmac in aa:bb:cc:dd:ee:ff")
    fw_apply()
    t.check("on: non-matching dst MAC dropped", "FAIL", t.ping())


def test_vlan(t):
    """@neo:vlan — rule scoped to a VLAN id (structural; real trunk untested)."""
    vid = 100 + t.slot
    pat = f"vlan id {vid}"
    t.check("off: vlan match absent", True, pat not in nft_ruleset())
    fw_rule("vm", "ACCEPT", "out", iface=t.iface, comment=f"@neo:noct @neo:vlan {vid}")
    fw_apply()
    t.check("on: vlan match rendered", True, pat in nft_ruleset())
    t.check("on: untagged traffic unaffected", "PASS", t.ping())


def test_rateexceed(t):
    """@neo:rateexceed — DROP only the portion of traffic above <pps>
    (structural; sustained-flood test would be slow)."""
    rate = 5300 + t.slot
    pat = f"limit rate over {rate}"
    t.check("off: rate-limit rule absent", True, pat not in nft_ruleset())
    fw_rule("vm", "DROP", "out", iface=t.iface, comment=f"@neo:noct @neo:rateexceed {rate}")
    fw_apply()
    t.check("on: rate-limit rule rendered", True, pat in nft_ruleset())
    t.check("on: traffic within budget unaffected", "PASS", t.ping())


def test_ct_new(t):
    """@neo:ct new — IN DROP that only matches ct-state=new flows."""
    t.check("off: inbound NEW flow reaches VM", "PASS", t.ping_rev())
    fw_rule("vm", "DROP", "in", iface=t.iface, comment="@neo:ct new")
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: inbound NEW flow dropped", "FAIL", t.ping_rev())
    slot_ct_flush(t.backend, t.slot)
    t.check("on: VM-initiated flow still works (established replies)", "PASS", t.ping())


# ─────────────────────────── PVE-native rule tests ───────────────────────────
def test_native_basic(t):
    """Native IN DROP catch-all + IN ACCEPT icmp."""
    t.check("off: inbound flow reaches guest", "PASS", t.ping_rev())
    fw_rule("vm", "DROP", "in", iface=t.iface)
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: IN DROP blocks inbound", "FAIL", t.ping_rev())
    fw_rule("vm", "ACCEPT", "in", iface=t.iface, proto="icmp")
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: IN ACCEPT icmp permits ping", "PASS", t.ping_rev())


def test_native_ssh(t):
    """Native SSH macro — the VM's own sshd is the listener on port 22."""
    t.check("off: SSH port reachable", "OPEN", tcp_check("ct", t.ct_ip, t.vm_ip, 22))
    fw_rule("vm", "DROP", "in", iface=t.iface)
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: IN DROP closes SSH port", "CLOSED", tcp_check("ct", t.ct_ip, t.vm_ip, 22))
    fw_rule("vm", "ACCEPT", "in", iface=t.iface, macro="SSH")
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: SSH macro reopens port 22", "OPEN", tcp_check("ct", t.ct_ip, t.vm_ip, 22))
    start_listener("vm", 9999)
    t.check("on: non-SSH port stays closed", "CLOSED",
            tcp_check("ct", t.ct_ip, t.vm_ip, 9999))


def test_native_ipset_nomatch(t):
    """VM-local ipset: a /24 member is permitted, then a nomatch entry
    carves the CT back out."""
    name = f"tst_set{t.suffix}"
    t.check("off: inbound flow reaches guest", "PASS", t.ping_rev())
    guest_ipset_create("vm", name)
    guest_ipset_add("vm", name, t.cidr)
    fw_rule("vm", "DROP", "in", iface=t.iface)
    fw_rule("vm", "ACCEPT", "in", iface=t.iface, proto="icmp", source=f"+{name}")
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: ipset /24 member permitted", "PASS", t.ping_rev())
    guest_ipset_add("vm", name, t.ct_ip, nomatch=True)
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: ipset nomatch excludes CT", "FAIL", t.ping_rev())


def test_native_cluster_alias(t):
    """Datacenter alias referenced from a VM-local rule via dc/<name>."""
    name = f"tst_peer{t.suffix}"
    t.check("off: inbound flow reaches guest", "PASS", t.ping_rev())
    cluster_alias_create(name, t.ct_ip)
    fw_rule("vm", "DROP", "in", iface=t.iface)
    fw_rule("vm", "ACCEPT", "in", iface=t.iface, proto="icmp", source=f"dc/{name}")
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: dc/ alias permits CT", "PASS", t.ping_rev())
    cluster_alias_set(name, "198.51.100.7")
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: dc/ alias excludes non-listed IP", "FAIL", t.ping_rev())


def test_native_cluster_ipset(t):
    """Cluster ipset with a /24 member then a nomatch carve-out."""
    name = f"tst_dcset{t.suffix}"
    t.check("off: inbound flow reaches guest", "PASS", t.ping_rev())
    cluster_ipset_create(name)
    cluster_ipset_add(name, t.cidr)
    fw_rule("vm", "DROP", "in", iface=t.iface)
    fw_rule("vm", "ACCEPT", "in", iface=t.iface, proto="icmp", source=f"+dc/{name}")
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: cluster ipset /24 member permitted", "PASS", t.ping_rev())
    cluster_ipset_add(name, t.ct_ip, nomatch=True)
    fw_apply()
    slot_ct_flush(t.backend, t.slot)
    t.check("on: cluster ipset nomatch excludes CT", "FAIL", t.ping_rev())


def test_spoof_combo(t):
    """macspoof + ipspoof together: legit traffic passes both filters; a
    forged source IP is dropped (capture MAC-scoped to the VM's real MAC)."""
    t.check("off: traffic escapes when unmanaged", "PASS", t.ping())
    fw_ext("vm", t.iface, "@neo:macspoof")
    fw_ext("vm", t.iface, "@neo:ipspoof", source=t.vm_ip)
    fw_apply()
    t.check("on: legit traffic passes both filters", "PASS", t.ping())
    fake = f"{t.subnet}.99"
    tag = f"spoof{t.netindex}"
    bpf = f"ether src {t.vm_mac} and icmp and src host {fake}"
    cap_start("ct", t.ct_eth, tag, bpf, secs=3)
    agent_send("vm", "icmp", t.vm_eth, t.vm_mac, eth_dst=t.ct_mac,
               ip_src=fake, ip_dst=t.ct_ip)
    time.sleep(3)
    t.check("on: forged src IP dropped", True, cap_count("ct", tag) == 0)


def test_cross_macspoof_only_ip(t):
    """Only macspoof enabled ⇒ a forged source IP must NOT be blocked
    (ipspoof is inert). Capture is MAC-scoped to the VM's real MAC."""
    fw_ext("vm", t.iface, "@neo:macspoof")
    fw_apply()
    fake = f"{t.subnet}.99"
    tag = f"xmac{t.netindex}"
    bpf = f"ether src {t.vm_mac} and icmp and src host {fake}"
    cap_start("ct", t.ct_eth, tag, bpf, secs=3)
    agent_send("vm", "icmp", t.vm_eth, t.vm_mac, eth_dst=t.ct_mac,
               ip_src=fake, ip_dst=t.ct_ip)
    time.sleep(3)
    t.check("macspoof-only: forged src IP still escapes (ipspoof inert)",
            True, cap_count("ct", tag) >= 1)


# ─────────────────────────── Serial-phase tests ───────────────────────────
# These can't share the .fw with concurrent tests: cross_ipspoof mutates a NIC
# MAC, and the quarantine tests assert on rule position 0 (which is only stable
# when the .fw holds nothing else).

def test_cross_ipspoof_only_mac(t):
    """Only ipspoof enabled ⇒ a forged source MAC must NOT be blocked
    (macspoof is inert). Mutates + restores the VM NIC's MAC."""
    fw_ext("vm", t.iface, "@neo:ipspoof", source=t.vm_ip)
    fw_apply()
    eth, orig = t.vm_eth, t.vm_mac
    forged = "02:aa:bb:cc:dd:ee"
    exec_vm(f"ip link set dev {eth} down && ip link set dev {eth} address {forged} "
            f"&& ip link set dev {eth} up && sleep 1")
    res = t.ping()
    exec_vm(f"ip link set dev {eth} down && ip link set dev {eth} address {orig} "
            f"&& ip link set dev {eth} up && sleep 1")
    now = exec_vm(f"cat /sys/class/net/{eth}/address").strip()
    if now != orig:
        warn(f"MAC restore failed: {eth}={now} expected={orig} — retrying")
        exec_vm(f"ip link set dev {eth} down && ip link set dev {eth} address {orig} "
                f"&& ip link set dev {eth} up && sleep 1")
    t.check("ipspoof-only: forged src MAC still passes (macspoof inert)", "PASS", res)


def test_quarantine_ovs_icmp(t):
    """OVS rejects an ether/proto family contradiction → rule auto-disabled,
    log entry written, baseline traffic on the same bridge intact."""
    fw_rule("vm", "DROP", "out", iface=t.iface, proto="icmpv6",
            icmp_type="echo-request", comment="@neo:noct @neo:ether ip")
    fw_apply()
    t.check("rule #0 auto-disabled", "0", str(fw_rule_enabled("vm", 0)))
    t.check("quarantine log entry present", "YES",
            "YES" if fw_log_has_quarantine("vm", 0) else "NO")
    t.check("baseline ping on same bridge intact", "PASS", t.ping())


def test_quarantine_nft_set(t):
    """nft rejects an ipset family mismatch → rule auto-disabled + logged."""
    name = f"tst_qv6{t.suffix}"
    guest_ipset_create("vm", name)
    guest_ipset_add("vm", name, "2001:db8::/64")
    fw_rule("vm", "DROP", "out", iface=t.iface, source=f"+{name}",
            comment="@neo:noct @neo:ether ip")
    fw_apply()
    t.check("rule #0 auto-disabled", "0", str(fw_rule_enabled("vm", 0)))
    t.check("quarantine log entry present", "YES",
            "YES" if fw_log_has_quarantine("vm", 0) else "NO")
    t.check("baseline ping on same bridge intact", "PASS", t.ping())


def test_quarantine_self_heal(t):
    """After the user fixes a quarantined rule and re-enables it, the next
    apply leaves it enabled."""
    fw_rule("vm", "DROP", "out", iface=t.iface, proto="icmpv6",
            icmp_type="echo-request", comment="@neo:noct @neo:ether ip")
    fw_apply()
    t.check("prep: quarantine fired", "0", str(fw_rule_enabled("vm", 0)))
    # User repairs: drop the contradictory @neo:ether tag, re-enable.
    sh(["pvesh", "delete", f"{fw_base('vm')}/rules/0"])
    fw_rule("vm", "DROP", "out", iface=t.iface, proto="icmpv6",
            icmp_type="echo-request", comment="@neo:noct")
    fw_apply()
    t.check("rule stays enabled after fix", "1", str(fw_rule_enabled("vm", 0)))


# ─────────────────────────── Registry ───────────────────────────
# (name, func, [backends])  — a test is instantiated once per listed backend.
PARALLEL_TESTS = [
    ("Ext:macspoof",            test_macspoof,              ["linux"]),
    ("Ext:ipspoof",             test_ipspoof,               ["linux"]),
    ("Ext:nodhcp",              test_nodhcp,                ["linux"]),
    ("Ext:nora",                test_nora,                  ["linux"]),
    ("Ext:nondp",               test_nondp,                 ["linux"]),
    ("Ext:mcast_limit",         test_mcast_limit,           ["linux"]),
    ("Ext:disable",             test_disable,               ["linux"]),
    ("Ext:ctinvdrop",           test_ctinvdrop,             ["linux"]),
    ("Ext:isolated",            test_isolated,              ["linux"]),
    ("Dec:srcmac in",           test_srcmac_in,             ["linux"]),
    ("Dec:srcmac bitmask",      test_srcmac_bitmask,        ["linux"]),
    ("Dec:dstmac in",           test_dstmac,                ["linux"]),
    ("Dec:vlan",                test_vlan,                  ["linux"]),
    ("Dec:rateexceed",          test_rateexceed,            ["linux"]),
    ("Dec:ct new",              test_ct_new,                ["linux"]),
    ("Native:basic ICMP",       test_native_basic,          ["linux", "ovs"]),
    ("Native:SSH macro",        test_native_ssh,            ["linux"]),
    ("Native:ipset nomatch",    test_native_ipset_nomatch,  ["linux", "ovs"]),
    ("Native:cluster alias",    test_native_cluster_alias,  ["linux"]),
    ("Native:cluster ipset",    test_native_cluster_ipset,  ["linux"]),
    ("Ext:macspoof+ipspoof",    test_spoof_combo,           ["linux", "ovs"]),
    ("Cross:macspoof-only+IP",  test_cross_macspoof_only_ip, ["linux"]),
]

# (name, func, backend)  — run one at a time, after the parallel phase.
SERIAL_TESTS = [
    ("Cross:ipspoof-only+MAC",   test_cross_ipspoof_only_mac, "linux"),
    ("Quarantine:OVS icmp fam",  test_quarantine_ovs_icmp,    "ovs"),
    ("Quarantine:nft set fam",   test_quarantine_nft_set,     "linux"),
    ("Quarantine:self-heal",     test_quarantine_self_heal,   "ovs"),
]


# ─────────────────────────── Runner ───────────────────────────
class Tally:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def absorb(self, results):
        for passed, label, detail in results:
            if passed:
                ok(label)
                self.passed += 1
            else:
                fail(f"{label} — {detail}" if detail else label)
                self.failed += 1


def lane_reset(backend, slot):
    """Bring a lane to a clean slate before a test claims it: drop the lane's
    rules and any leftover lane-scoped tst_ sets, re-apply, flush conntrack."""
    slot_clear("vm", backend, slot)
    slot_clear("ct", backend, slot)
    suffix = f"_{backend}_{slot}"
    for s in pvesh_json(f"{fw_base('vm')}/ipset"):
        if s.get("name", "").endswith(suffix):
            guest_ipset_del("vm", s["name"])
    for s in pvesh_json("/cluster/firewall/ipset"):
        if s.get("name", "").endswith(suffix):
            cluster_ipset_del(s["name"])
    for a in pvesh_json("/cluster/firewall/aliases"):
        if a.get("name", "").endswith(suffix):
            cluster_alias_del(a["name"])
    fw_apply()
    slot_ct_flush(backend, slot)


def run_parallel(tests, tally):
    """Slot job-pool. Each backend gets its own executor sized to N_SLOTS and
    its own queue of N_SLOTS lanes, so every running worker can claim a free
    lane immediately (workers == lanes) — linux and ovs lanes stay busy
    independently. PARALLEL=0 falls back to a single-threaded run."""
    jobs = {"linux": [], "ovs": []}
    for name, func, backends in tests:
        for backend in backends:
            jobs[backend].append((name, func))

    lanes = {"linux": queue.Queue(), "ovs": queue.Queue()}
    for slot in range(1, CFG.n_slots + 1):
        lanes["linux"].put(slot)
        lanes["ovs"].put(slot)

    def worker(name, func, backend):
        slot = lanes[backend].get()
        ctx = TestCtx(name, backend, slot)
        try:
            lane_reset(backend, slot)
            log(f"▶ [{backend} slot{slot}] {name}")
            func(ctx)
        except Exception as exc:  # noqa: BLE001 — one bad test must not kill the run
            ctx.results.append((False, f"{name} [{backend}]", f"EXCEPTION: {exc!r}"))
        finally:
            lanes[backend].put(slot)
        return ctx

    if not CFG.parallel:
        for backend in ("linux", "ovs"):
            for name, func in jobs[backend]:
                tally.absorb(worker(name, func, backend).results)
        return

    workers = CFG.n_slots
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="linux") as lex, \
         ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ovs") as oex:
        futs = [lex.submit(worker, n, f, "linux") for n, f in jobs["linux"]]
        futs += [oex.submit(worker, n, f, "ovs") for n, f in jobs["ovs"]]
        for fut in as_completed(futs):
            tally.absorb(fut.result().results)


def run_serial(tests, tally):
    for name, func, backend in tests:
        fw_global_reset()
        ctx = TestCtx(name, backend, 1)
        log(f"▶ [serial {backend}] {name}")
        try:
            func(ctx)
        except Exception as exc:  # noqa: BLE001
            ctx.results.append((False, f"{name} [{backend}]", f"EXCEPTION: {exc!r}"))
        tally.absorb(ctx.results)


def baseline(tally):
    """No firewall at all — confirm raw VM↔CT connectivity + tooling on each
    backend's slot 1, so a later red isn't just a broken environment."""
    fw_disable("vm")
    fw_disable("ct")
    fw_apply()
    results = []
    for backend in ("linux", "ovs"):
        got = probe_ping(backend, 1)
        results.append((got == "PASS",
                        f"Baseline: {backend} slot1 VM↔CT reachable",
                        "" if got == "PASS" else f"expected [PASS] got [{got}]"))
    tally.absorb(results)


def main():
    import os
    if os.geteuid() != 0:
        sys.exit("test.py must run as root")

    log("═══ pvefw-neo test suite ═══")
    log(CFG.summary())
    print(flush=True)

    tally = Tally()

    log("── Baseline (firewall disabled) ──")
    fw_global_reset()
    baseline(tally)

    log("── Enabling firewall for the suite ──")
    fw_enable("vm")
    fw_enable("ct")
    fw_apply()

    mode = "parallel job-pool" if CFG.parallel else "serial (PARALLEL=0)"
    log(f"── Parallel phase ({mode}, {len(PARALLEL_TESTS)} tests) ──")
    run_parallel(PARALLEL_TESTS, tally)

    log(f"── Serial phase ({len(SERIAL_TESTS)} tests) ──")
    run_serial(SERIAL_TESTS, tally)

    log("── Final reset (leave the environment clean) ──")
    fw_global_reset()
    fw_disable("vm")
    fw_disable("ct")
    fw_apply()

    print(flush=True)
    total = tally.passed + tally.failed
    log(f"═══ Results: {tally.passed}/{total} passed, {tally.failed} failed ═══")
    sys.exit(1 if tally.failed else 0)


if __name__ == "__main__":
    main()
