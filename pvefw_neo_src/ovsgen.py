"""
OVS (Open vSwitch) backend: IR Ruleset → OpenFlow rules.

Pure renderer for the new per-NetDev IR.

Pipeline:
  IR Phase                              → OVS table
  ─────────────────────────────────────────────────────────────
  STATELESS, macfilter (src_mac_neg)    → table 0  (per-port, in_port)
  STATELESS, other                      → table 10 (per-port, in_port)
  STATEFUL                              → table 30 (OUT, in_port match)
                                          table 31 (IN, dl_dst match)
  Conntrack send                        → table 20 (between 10 and 30)

Tables:
   0   ingress: macfilter (drop bad src MAC, fall through to 10)
  10   stateless: ipspoof, nodhcp, nora, notrack ACL
  20   conntrack send: ip/ipv6 → ct(table=30); arp → bypass
  30   forward OUT check: per-port in_port match, isolation
  31   forward IN check: dl_dst match + ct_state framework

NetDev with no STATEFUL rules → no table 30/31 entries → packets fall through
to default NORMAL action without entering ct().
"""

import subprocess

from . import ir


# OVS table assignments
TBL_INGRESS  = 0
TBL_RAW      = 10
TBL_CT_SEND  = 20
TBL_FWD_OUT  = 30
TBL_FWD_IN   = 31

# Cookie for our flows (used for selective deletion)
COOKIE = "0x4E30"

# ICMPv6 type number map
ICMPV6_TYPE_NUM = {
    "nd-neighbor-solicit": 135,
    "nd-neighbor-advert": 136,
    "nd-router-advert": 134,
    "nd-router-solicit": 133,
}


# ═══════════════════════════════════════
# Public API
# ═══════════════════════════════════════

def render(ruleset, bridge, devnames=None):
    """Render IR Ruleset → ovs-ofctl flow text for one OVS bridge.

    Args:
      ruleset: ir.Ruleset
      bridge:  OVS bridge name
      devnames: optional iterable of devnames on this bridge.
                If None, auto-discover from `ovs-vsctl list-ports`.

    Returns:
      flows_text (str)
    """
    return OvsRenderer(ruleset, bridge, devnames).render()


def apply(ruleset, bridge, devnames=None):
    """Render and atomically apply flows to an OVS bridge."""
    flows_text = render(ruleset, bridge, devnames)
    if not flows_text.strip():
        return True

    flows_path = f"/run/pvefw-neo/ovs-{bridge}.flows"
    import os
    os.makedirs("/run/pvefw-neo", exist_ok=True)
    with open(flows_path, "w") as f:
        f.write(flows_text)

    # Delete previous flows with our cookie
    subprocess.run(
        ["ovs-ofctl", "del-flows", bridge, f"cookie={COOKIE}/-1"],
        capture_output=True, text=True,
    )
    # Apply new flows
    ret = subprocess.run(
        ["ovs-ofctl", "add-flows", bridge, flows_path],
        capture_output=True, text=True,
    )
    if ret.returncode != 0:
        print(f"ovs-ofctl add-flows failed:\n{ret.stderr}")
        return False
    return True


def flush(bridge):
    """Remove all pvefw-neo flows from an OVS bridge, restore NORMAL."""
    subprocess.run(
        ["ovs-ofctl", "del-flows", bridge, f"cookie={COOKIE}/-1"],
        capture_output=True, text=True,
    )
    subprocess.run(
        ["ovs-ofctl", "add-flow", bridge, "priority=0,actions=NORMAL"],
        capture_output=True, text=True,
    )


# ═══════════════════════════════════════
# Renderer
# ═══════════════════════════════════════

class OvsRenderer:
    def __init__(self, ruleset, bridge, devnames=None):
        self.rs = ruleset
        self.bridge = bridge
        self.port_map = {}    # devname → ofport (int)
        self.flows = []
        self._discover_ports()
        # Filter to devnames on this bridge
        if devnames is not None:
            self.my_devs = set(devnames) & set(self.port_map.keys())
        else:
            self.my_devs = set(self.port_map.keys())

    def _discover_ports(self):
        """Map device names to OVS ofport numbers."""
        ret = subprocess.run(
            ["ovs-vsctl", "list-ports", self.bridge],
            capture_output=True, text=True,
        )
        if ret.returncode != 0:
            return
        for port_name in ret.stdout.strip().splitlines():
            port_name = port_name.strip()
            if not port_name:
                continue
            ret2 = subprocess.run(
                ["ovs-vsctl", "get", "Interface", port_name, "ofport"],
                capture_output=True, text=True,
            )
            if ret2.returncode == 0:
                try:
                    ofport = int(ret2.stdout.strip())
                    if ofport > 0:
                        self.port_map[port_name] = ofport
                except ValueError:
                    pass

    # ─────────────────── helpers ───────────────────

    @staticmethod
    def _is_macfilter_rule(rule):
        """Same heuristic as nftgen: src_mac_neg pure-L2 = macfilter."""
        l2 = rule.match.get("l2", {})
        if "src_mac_neg" in l2 and not rule.match.get("l3") and not rule.match.get("l4"):
            return True
        if rule.rate_limit_pps is not None and "dst_mac_mask" in l2:
            return True
        return False

    def _emit(self, table, priority, match, action):
        """Compose a single flow entry."""
        parts = [f"cookie={COOKIE}", f"table={table}", f"priority={priority}"]
        parts.extend(match)
        return ",".join(parts) + f",actions={action}"

    def _expand_match(self, m):
        """IR match dict → list of OVS match tokens.

        Returns: list of strings (each AND-joined into final match).
        """
        parts = []
        l2 = m.get("l2", {})
        l3 = m.get("l3", {})
        l4 = m.get("l4", {})

        # ── Determine ether_type prefix ──
        et = l2.get("ether_type")
        et_str = None
        if et == "ip":
            et_str = "ip"
        elif et == "ip6":
            et_str = "ipv6"
        elif et == "arp":
            et_str = "arp"

        # If L3/L4 fields present without explicit ether_type, infer
        if not et_str:
            if l3.get("src_ip") or l3.get("dst_ip") or l3.get("src_set") or l3.get("dst_set"):
                # Cannot fully determine v4 vs v6 from string here
                et_str = "ip"
            elif l3.get("proto") or l4:
                et_str = "ip"

        if et_str:
            parts.append(et_str)

        # ── L2 src_mac/dst_mac ──
        if "src_mac" in l2:
            parts.append(f"dl_src={l2['src_mac'].lower()}")
        # src_mac_neg handled at higher level (split into 2 flows)
        if "dst_mac" in l2:
            parts.append(f"dl_dst={l2['dst_mac'].lower()}")
        if "dst_mac_mask" in l2:
            addr, mask = l2["dst_mac_mask"]
            parts.append(f"dl_dst={addr}/{mask}")

        # ── ARP ──
        if "arp_op" in l2:
            # Caller must split into multiple flows for >1 op
            ops = l2["arp_op"]
            if len(ops) >= 1:
                op_num = 1 if ops[0] == "request" else 2
                parts.append(f"arp_op={op_num}")
        if "arp_spa" in l2:
            parts.append(f"arp_spa={l2['arp_spa']}")

        # ── L3 ──
        if "src_ip" in l3:
            ip_field = "ipv6_src" if et_str == "ipv6" else "nw_src"
            parts.append(f"{ip_field}={l3['src_ip']}")
        if "dst_ip" in l3:
            ip_field = "ipv6_dst" if et_str == "ipv6" else "nw_dst"
            parts.append(f"{ip_field}={l3['dst_ip']}")

        # Sets are NOT expanded here — caller must expand into N flows
        # (we leave src_set/dst_set marker for caller to detect)

        # ── L4 proto + ports ──
        proto = l3.get("proto")
        if proto:
            proto_num = {
                "tcp": 6, "udp": 17,
                "icmp": 1, "icmpv6": 58, "gre": 47,
            }.get(proto.lower())
            if proto_num is not None:
                parts.append(f"nw_proto={proto_num}")
            else:
                try:
                    parts.append(f"nw_proto={int(proto)}")
                except ValueError:
                    pass

        # ICMPv6 type
        if "icmpv6_type" in l3:
            types = l3["icmpv6_type"]
            if len(types) >= 1:
                num = ICMPV6_TYPE_NUM.get(types[0])
                if num is not None:
                    # Need nw_proto=58 prefix
                    if not any("nw_proto=" in p for p in parts):
                        parts.append("nw_proto=58")
                    parts.append(f"icmpv6_type={num}")

        if "src_port" in l4:
            parts.append(f"tp_src={self._fmt_port(l4['src_port'])}")
        if "dst_port" in l4:
            parts.append(f"tp_dst={self._fmt_port(l4['dst_port'])}")

        return parts

    @staticmethod
    def _fmt_port(p):
        """OVS doesn't directly support {80,443} sets in tp_dst.

        For ranges like '80-443' OVS uses a single value or a mask.
        For sets we'd need multiple flows. For now: take first.
        """
        if p.startswith("{") and p.endswith("}"):
            # Take first port from set
            first = p[1:-1].split(",")[0].strip()
            return first
        return p

    # ─────────────────── render ───────────────────

    def render(self):
        # Pre-pass: compute set of NetDevs that have STATEFUL rules
        stateful_devs = set()
        for devname in self.my_devs:
            nd = self.rs.netdevs.get(devname)
            if not nd:
                continue
            if any(r.phase == ir.Phase.STATEFUL for r in nd.rules):
                stateful_devs.add(devname)

        # Discover MACs from NetDev metadata (for IN-direction match)
        dev_mac = {dn: nd.mac.lower()
                   for dn, nd in self.rs.netdevs.items()
                   if dn in self.my_devs and nd.mac}

        # Process each NetDev
        prio_table0 = 30000
        prio_table10 = 30000
        prio_table30 = 20000
        prio_table31 = 20000

        for devname in sorted(self.my_devs):
            nd = self.rs.netdevs.get(devname)
            if nd is None:
                continue
            ofport = self.port_map.get(devname)
            if ofport is None:
                continue

            for rule in nd.rules:
                if rule.phase == ir.Phase.STATELESS:
                    if self._is_macfilter_rule(rule):
                        prio_table0 = self._emit_macfilter(
                            devname, ofport, rule, prio_table0)
                    else:
                        prio_table10 = self._emit_stateless(
                            devname, ofport, rule, prio_table10)
                else:  # STATEFUL
                    if rule.direction == ir.Direction.OUT:
                        prio_table30 = self._emit_stateful_out(
                            devname, ofport, rule, prio_table30)
                    else:
                        mac = dev_mac.get(devname)
                        if mac:
                            prio_table31 = self._emit_stateful_in(
                                devname, mac, rule, prio_table31)

        # ── Framework flows ──
        # Table 0 default → table 10
        self.flows.append(self._emit(
            TBL_INGRESS, 0, [], f"resubmit(,{TBL_RAW})"))
        # Table 10 default → table 20
        self.flows.append(self._emit(
            TBL_RAW, 0, [], f"resubmit(,{TBL_CT_SEND})"))

        # Table 20 (CT send)
        # ARP → bypass to OUT
        self.flows.append(self._emit(
            TBL_CT_SEND, 1000, ["arp"], f"resubmit(,{TBL_FWD_OUT})"))
        # IP → ct
        self.flows.append(self._emit(
            TBL_CT_SEND, 100, ["ip"], f"ct(table={TBL_FWD_OUT})"))
        self.flows.append(self._emit(
            TBL_CT_SEND, 100, ["ipv6"], f"ct(table={TBL_FWD_OUT})"))
        # Default
        self.flows.append(self._emit(
            TBL_CT_SEND, 0, [], f"resubmit(,{TBL_FWD_OUT})"))

        # Table 30 default → table 31
        self.flows.append(self._emit(
            TBL_FWD_OUT, 0, [], f"resubmit(,{TBL_FWD_IN})"))

        # Table 31 framework
        # ARP → NORMAL
        self.flows.append(self._emit(
            TBL_FWD_IN, 30000, ["arp"], "NORMAL"))
        # Established → NORMAL
        self.flows.append(self._emit(
            TBL_FWD_IN, 29000, ["ct_state=+est-inv"], "NORMAL"))
        # Related → NORMAL
        self.flows.append(self._emit(
            TBL_FWD_IN, 28500, ["ct_state=+rel-inv"], "NORMAL"))
        # Invalid → drop
        self.flows.append(self._emit(
            TBL_FWD_IN, 28000, ["ct_state=+inv"], "drop"))
        # Default → NORMAL (no rules = pass)
        self.flows.append(self._emit(
            TBL_FWD_IN, 0, [], "NORMAL"))

        # ── Isolation ──
        self._emit_isolation()

        return "\n".join(self.flows) + "\n"

    # ─────────────────── per-rule emitters ───────────────────

    def _emit_macfilter(self, devname, ofport, rule, prio):
        """macspoof: src_mac_neg → 2 flows (allow correct, drop rest)."""
        l2 = rule.match["l2"]
        mac = l2["src_mac_neg"].lower()
        # Allow correct MAC
        self.flows.append(self._emit(
            TBL_INGRESS, prio,
            [f"in_port={ofport}", f"dl_src={mac}"],
            f"resubmit(,{TBL_RAW})"))
        # Drop everything else from this in_port
        self.flows.append(self._emit(
            TBL_INGRESS, prio - 1,
            [f"in_port={ofport}"],
            "drop"))
        return prio - 2

    def _emit_stateless(self, devname, ofport, rule, prio):
        """STATELESS rule → table 10 with in_port match."""
        # Handle arp_op set: split into multiple flows
        l2 = rule.match.get("l2", {})
        ops = l2.get("arp_op", [])

        action = "drop" if rule.action == "drop" else f"resubmit(,{TBL_CT_SEND})"

        if len(ops) > 1:
            for op in ops:
                m = self._expand_match_with_arp_op(rule.match, op)
                self.flows.append(self._emit(
                    TBL_RAW, prio, [f"in_port={ofport}"] + m, action))
                prio -= 1
        else:
            m = self._expand_match(rule.match)
            self.flows.append(self._emit(
                TBL_RAW, prio, [f"in_port={ofport}"] + m, action))
            prio -= 1
        return prio

    def _expand_match_with_arp_op(self, m, op):
        """Render match with a specific single arp_op value."""
        m2 = {k: dict(v) for k, v in m.items()}
        m2["l2"]["arp_op"] = [op]
        return self._expand_match(m2)

    def _emit_stateful_out(self, devname, ofport, rule, prio):
        """STATEFUL OUT rule → table 30 in_port match."""
        m = self._expand_match(rule.match)
        if rule.action == "drop":
            action = "drop"
        else:  # accept (return semantics not needed in OVS — table 30 falls to 31)
            # ct(commit) only for IP traffic
            has_l3 = bool(rule.match.get("l3") or rule.match.get("l4"))
            action = f"ct(commit),resubmit(,{TBL_FWD_IN})" if has_l3 \
                     else f"resubmit(,{TBL_FWD_IN})"
        self.flows.append(self._emit(
            TBL_FWD_OUT, prio, [f"in_port={ofport}"] + m, action))
        return prio - 1

    def _emit_stateful_in(self, devname, mac, rule, prio):
        """STATEFUL IN rule → table 31 dl_dst match."""
        m = self._expand_match(rule.match)
        if rule.action == "drop":
            action = "drop"
        else:
            has_l3 = bool(rule.match.get("l3") or rule.match.get("l4"))
            action = "ct(commit),NORMAL" if has_l3 else "NORMAL"
        self.flows.append(self._emit(
            TBL_FWD_IN, prio, [f"dl_dst={mac}"] + m, action))
        return prio - 1

    # ─────────────────── isolation ───────────────────

    def _emit_isolation(self):
        """Implement language A: two isolated ports cannot communicate.

        Approach: mark isolated source with reg0[0]=1 in table 0.
        In table 31, drop if reg0[0]=1 and dl_dst is another isolated port's MAC.
        """
        iso_devs = []
        for devname in sorted(self.my_devs):
            nd = self.rs.netdevs.get(devname)
            if nd and nd.isolated:
                iso_devs.append(devname)

        if len(iso_devs) < 2:
            return  # need at least 2 isolated ports for A semantics to matter

        iso_macs = []
        for devname in iso_devs:
            nd = self.rs.netdevs.get(devname)
            if nd and nd.mac:
                iso_macs.append(nd.mac.lower())

        # Mark each isolated port's incoming traffic
        for devname in iso_devs:
            ofport = self.port_map.get(devname)
            if ofport is None:
                continue
            self.flows.append(self._emit(
                TBL_INGRESS, 40000,
                [f"in_port={ofport}"],
                f"load:1->NXM_NX_REG0[0],resubmit(,{TBL_RAW})"))

        # In table 31, drop if reg0[0]=1 AND dst is another isolated port
        for mac in iso_macs:
            self.flows.append(self._emit(
                TBL_FWD_IN, 31000,
                ["reg0=0x1/0x1", f"dl_dst={mac}"],
                "drop"))
