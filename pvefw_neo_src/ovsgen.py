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

import copy
import hashlib
import ipaddress
import subprocess
import sys

from . import ir


from . import icmp_types

# OVS table assignments
TBL_INGRESS  = 0
TBL_RAW      = 10
TBL_CT_SEND  = 20
TBL_FWD_OUT  = 30
TBL_FWD_IN   = 31

# Cookie layout (64-bit):
#   bits 63..48 : 0x4E30    (magic, identifies pvefw-neo flows)
#   bits 47..0  : hash of source_id, or 0 for framework flows (no source)
# Selective deletion uses the magic prefix mask only, so every pvefw-neo
# flow is cleaned regardless of per-rule cookie.
COOKIE_PREFIX = 0x4E30_0000_0000_0000
COOKIE_MASK   = 0xFFFF_0000_0000_0000
COOKIE_LEGACY = "0x4E30"   # for backwards-compat del-flows that still match

# Meter IDs are 32-bit in OpenFlow 1.3. We partition the space: high 16
# bits = 0x4E30 (magic, identifies pvefw-neo meters), low 16 bits = hash
# of source_id. Gives 65536 independent meters per bridge, enough for any
# realistic pvefw-neo deployment. Selective cleanup uses the prefix.
METER_ID_PREFIX = 0x4E30_0000
METER_ID_MASK   = 0xFFFF_0000


def _cookie_for(source_id):
    """Compute 64-bit cookie for a source_id (or framework flow if None)."""
    if not source_id:
        return COOKIE_PREFIX
    h = hashlib.sha256(source_id.encode("utf-8")).digest()
    low = int.from_bytes(h[:6], "big")   # 48 bits
    return COOKIE_PREFIX | low


def _cookie_str(source_id):
    """ovs-ofctl cookie literal: `0xXXXXXXXXXXXXXXXX`."""
    return f"0x{_cookie_for(source_id):016X}"


def _meter_id_for(source_id):
    """32-bit meter ID derived from source_id. High 16 bits fixed to
    identify pvefw-neo ownership; low 16 bits = sha256 low-nibble of
    source_id. Deterministic across runs so repeat applies replace cleanly.
    """
    h = hashlib.sha256(source_id.encode("utf-8")).digest()
    low = int.from_bytes(h[:2], "big")
    return METER_ID_PREFIX | low


# ═══════════════════════════════════════
# Public API
# ═══════════════════════════════════════

def render(ruleset, bridge, devnames=None):
    """Render IR Ruleset → (flows_text, cookie_map, meters) for one bridge.

    Args:
      ruleset: ir.Ruleset
      bridge:  OVS bridge name
      devnames: optional iterable of devnames on this bridge.
                If None, auto-discover from `ovs-vsctl list-ports`.

    Returns:
      (flows_text, cookie_map, meters)
        cookie_map : int → source_id
        meters     : {meter_id: (rate_pps, burst_pkts)}
    """
    r = OvsRenderer(ruleset, bridge, devnames)
    text = r.render()
    return text, dict(r._cookie_to_source), dict(r._meters)


def _ensure_bridge_of13(bridge):
    """Make sure `bridge` lists OpenFlow13 in its `protocols` column so
    add-flows with OF1.3 actions (e.g. meter references) can be negotiated.

    PVE leaves `protocols=[]` on OVS bridges by default, which implies
    OF1.0-only. Appending OpenFlow13 is additive: OF1.0 clients still
    work, and no existing flow gets touched.

    Returns True if OF1.3 is (now) in the protocol list, False on failure.
    """
    get = subprocess.run(
        ["ovs-vsctl", "get", "bridge", bridge, "protocols"],
        capture_output=True, text=True,
    )
    if get.returncode != 0:
        return False
    current = get.stdout.strip()
    if "OpenFlow13" in current:
        return True
    if current == "[]":
        protos = "OpenFlow10,OpenFlow13"
    else:
        inner = current.strip("[] ")
        items = [s.strip() for s in inner.split(",") if s.strip()]
        items.append("OpenFlow13")
        protos = ",".join(items)
    ret = subprocess.run(
        ["ovs-vsctl", "set", "bridge", bridge, f"protocols={protos}"],
        capture_output=True, text=True,
    )
    return ret.returncode == 0


def _delete_our_meters(bridge):
    """Remove every pvefw-neo-owned meter (by magic prefix) from a bridge.

    Uses OF1.3 since meters don't exist in OF1.0. Never raises — bridges
    without OF1.3 negotiation or meter support are silently ignored.
    """
    ret = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-meters", bridge],
        capture_output=True, text=True,
    )
    if ret.returncode != 0:
        return
    import re
    for line in ret.stdout.splitlines():
        m = re.search(r"meter=(\d+)", line)
        if not m:
            continue
        mid = int(m.group(1))
        if (mid & METER_ID_MASK) == METER_ID_PREFIX:
            subprocess.run(
                ["ovs-ofctl", "-O", "OpenFlow13", "del-meter",
                 bridge, f"meter={mid}"],
                capture_output=True, text=True,
            )


def _install_meters(bridge, meters):
    """Install a dict of {meter_id: (rate_pps, burst)} on a bridge.

    Returns (ok, err_text). On failure, a single meter's add-meter error
    is propagated; the caller can quarantine the owning source_id or fall
    back to a warning.
    """
    for mid, (rate, burst) in sorted(meters.items()):
        spec = (f"meter={mid},pktps,burst,"
                f"bands=type=drop rate={rate} burst_size={burst}")
        ret = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "add-meter", bridge, spec],
            capture_output=True, text=True,
        )
        if ret.returncode != 0:
            return False, ret.stderr
    return True, ""


def apply(ruleset, bridge, devnames=None):
    """Render and atomically apply flows + meters to an OVS bridge.

    Order: delete-old-meters → delete-old-flows → install-new-meters →
    install-new-flows. Meters first so flows that reference them don't
    race with a half-installed meter set.

    Returns (ok, err_text, flows_text, cookie_map). err_text is the raw
    `ovs-ofctl` stderr on failure (empty on success). Callers use it to
    pinpoint which source_id caused a rejection (via cookie_map).
    """
    flows_text, cookie_map, meters = render(ruleset, bridge, devnames)

    # Any rule that needs a meter forces the whole bridge onto OF1.3
    # (bridge-level protocol list) and we'll pass `-O OpenFlow13` to
    # ovs-ofctl. No-meter bridges stay on the default (OF1.0) path for
    # compatibility.
    of_args = []
    if meters:
        _ensure_bridge_of13(bridge)
        of_args = ["-O", "OpenFlow13"]

    # Always delete previous meters + flows with our magic prefix first.
    _delete_our_meters(bridge)
    mask_str = f"0x{COOKIE_PREFIX:016X}/0x{COOKIE_MASK:016X}"
    subprocess.run(
        ["ovs-ofctl", *of_args, "del-flows", bridge, f"cookie={mask_str}"],
        capture_output=True, text=True,
    )

    if not flows_text.strip():
        return True, "", flows_text, cookie_map

    # Install meters BEFORE flows. If a meter install fails (bridge doesn't
    # negotiate OF1.3, or meter subsystem unsupported) return the error so
    # the quarantine layer can disable the owning rule.
    if meters:
        ok, err = _install_meters(bridge, meters)
        if not ok:
            return False, err, flows_text, cookie_map

    flows_path = f"/run/pvefw-neo/ovs-{bridge}.flows"
    import os
    os.makedirs("/run/pvefw-neo", exist_ok=True)
    with open(flows_path, "w") as f:
        f.write(flows_text)

    ret = subprocess.run(
        ["ovs-ofctl", *of_args, "add-flows", bridge, flows_path],
        capture_output=True, text=True,
    )
    if ret.returncode != 0:
        return False, ret.stderr, flows_text, cookie_map
    return True, "", flows_text, cookie_map


def flush(bridge):
    """Remove all pvefw-neo flows + meters from an OVS bridge, restore NORMAL."""
    _delete_our_meters(bridge)
    mask_str = f"0x{COOKIE_PREFIX:016X}/0x{COOKIE_MASK:016X}"
    subprocess.run(
        ["ovs-ofctl", "del-flows", bridge, f"cookie={mask_str}"],
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
        self._cookie_to_source = {}   # cookie_int → source_id (for error reverse lookup)
        self._meters = {}             # meter_id → (rate_pps, burst_pkts)
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

    def _emit(self, table, priority, match, action, source_id=None):
        """Compose a single flow entry.

        source_id (str or None): when given, the flow's cookie encodes a hash
        of the source_id in its low 48 bits; the high 16 bits remain 0x4E30.
        Framework flows (default resubmit / ct dispatch / isolation) pass
        None and get cookie=0x4E30000000000000 (prefix only, no rule id).
        """
        cookie = _cookie_str(source_id)
        if source_id:
            self._cookie_to_source[_cookie_for(source_id)] = source_id
        parts = [f"cookie={cookie}", f"table={table}", f"priority={priority}"]
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
        if "src_mac_mask" in l2:
            addr, mask = l2["src_mac_mask"]
            parts.append(f"dl_src={addr.lower()}/{mask.lower()}")
        # src_mac_neg handled at higher level (split into 2 flows)
        if "dst_mac" in l2:
            parts.append(f"dl_dst={l2['dst_mac'].lower()}")
        if "dst_mac_mask" in l2:
            addr, mask = l2["dst_mac_mask"]
            parts.append(f"dl_dst={addr.lower()}/{mask.lower()}")

        # ── VLAN ──
        # `vlan_id` matches frames on a specific 802.1Q VLAN; `ether_type_neg
        # == vlan` means "untagged" (no VLAN tag present). Multi-vid OR is
        # handled by the caller emitting N flows at the same priority, the
        # same way arp_op sets are expanded.
        if "vlan_id" in l2:
            vids = l2["vlan_id"]
            # Caller splits list into separate flows; here render whichever
            # we were given (first element if a list sneaks through).
            vid = vids[0] if isinstance(vids, list) else vids
            parts.append(f"dl_vlan={vid}")
        if l2.get("ether_type_neg") == "vlan":
            # vlan_tci bit 0x1000 is the VID-present flag (CFI). Matching
            # vlan_tci=0x0000/0x1000 selects frames with no VLAN tag.
            parts.append("vlan_tci=0x0000/0x1000")

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

        # ── ct_state ──
        ct_state_map = {"new": "+new", "invalid": "+inv"}
        if "ct_state" in l3:
            flag = ct_state_map.get(l3["ct_state"])
            if flag:
                parts.append(f"ct_state={flag}")

        # ── L4 proto + ports ──
        proto = l3.get("proto")
        if proto:
            # All protocols from PVE WebUI dropdown (pvemanagerlib.js)
            # plus `icmpv6` alias used internally by PVE macros.
            proto_num = {
                "tcp": 6, "udp": 17, "icmp": 1, "igmp": 2,
                "ggp": 3, "ipencap": 4, "st": 5, "egp": 8,
                "igp": 9, "pup": 12, "hmp": 20, "xns-idp": 22,
                "rdp": 27, "iso-tp4": 29, "dccp": 33, "xtp": 36,
                "ddp": 37, "idpr-cmtp": 38, "ipv6": 41,
                "ipv6-route": 43, "ipv6-frag": 44, "idrp": 45,
                "rsvp": 46, "gre": 47, "esp": 50, "ah": 51,
                "skip": 57, "ipv6-icmp": 58, "icmpv6": 58,
                "ipv6-nonxt": 59, "ipv6-opts": 60, "vmtp": 81,
                "eigrp": 88, "ospf": 89, "ax.25": 93, "ipip": 94,
                "etherip": 97, "encap": 98, "pim": 103,
                "ipcomp": 108, "vrrp": 112, "l2tp": 115,
                "isis": 124, "sctp": 132, "fc": 133,
                "mobility-header": 135, "udplite": 136,
                "mpls-in-ip": 137, "hip": 139, "shim6": 140,
                "wesp": 141, "rohc": 142,
            }.get(proto.lower())
            if proto_num is not None:
                parts.append(f"nw_proto={proto_num}")
            else:
                try:
                    parts.append(f"nw_proto={int(proto)}")
                except ValueError:
                    print(f"WARNING: OVS unknown protocol '{proto}' — "
                          f"rule may be too broad", file=sys.stderr)

        # ICMP type (v4 and v6) — resolve PVE names to (type, code) via
        # shared mapping. OVS uses icmp_type=N[,icmp_code=N] for v4,
        # icmpv6_type=N[,icmpv6_code=N] for v6.
        if "icmp_type" in l3:
            for name in l3["icmp_type"][:1]:
                entry = icmp_types.ICMPV4.get(name)
                if entry:
                    typ, code = entry
                    if typ is not None:
                        parts.append(f"icmp_type={typ}")
                        if code is not None:
                            parts.append(f"icmp_code={code}")
                else:
                    try:
                        parts.append(f"icmp_type={int(name)}")
                    except ValueError:
                        pass
        if "icmpv6_type" in l3:
            for name in l3["icmpv6_type"][:1]:
                entry = (icmp_types.ICMPV6.get(name)
                         or icmp_types.NFT_ICMPV6_NUM.get(name))
                if entry:
                    typ, code = entry
                else:
                    try:
                        typ, code = int(name), None
                    except ValueError:
                        continue
                if not any("nw_proto=" in p for p in parts):
                    parts.append("nw_proto=58")
                parts.append(f"icmpv6_type={typ}")
                if code is not None:
                    parts.append(f"icmpv6_code={code}")

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
            if not nd or nd.disabled:
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
            # @neo:disable: skip port entirely — no flows emitted, packet
            # falls through to table default (NORMAL) = pass-through.
            if nd.disabled:
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

        # Per-stateful-port ct dispatch. Only ports that have STATEFUL rules
        # need to invoke ct(); other traffic skips conntrack entirely and
        # hits the table-31 priority-0 NORMAL catchall with ct_state=-trk
        # (which doesn't match `+inv` so the invalid drop rule is harmless).
        #
        # We match forward (in_port=port) AND reply (dl_dst=port_mac) so ct
        # tracking covers both directions of any flow touching a stateful
        # port. Commit happens inside the per-port stateful rule flows
        # (_emit_stateful_out / _emit_stateful_in) — here we only do ct
        # lookups so existing entries classify returning packets as +est.
        for devname in sorted(stateful_devs):
            ofport = self.port_map.get(devname)
            mac = dev_mac.get(devname)
            if ofport is None or mac is None:
                continue
            self.flows.append(self._emit(
                TBL_CT_SEND, 200,
                [f"in_port={ofport}", "ip"],
                f"ct(table={TBL_FWD_OUT})"))
            self.flows.append(self._emit(
                TBL_CT_SEND, 200,
                [f"in_port={ofport}", "ipv6"],
                f"ct(table={TBL_FWD_OUT})"))
            self.flows.append(self._emit(
                TBL_CT_SEND, 200,
                [f"dl_dst={mac}", "ip"],
                f"ct(table={TBL_FWD_OUT})"))
            self.flows.append(self._emit(
                TBL_CT_SEND, 200,
                [f"dl_dst={mac}", "ipv6"],
                f"ct(table={TBL_FWD_OUT})"))

        # Default: skip ct entirely for non-stateful traffic.
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
        # Default → NORMAL (no rules = pass)
        self.flows.append(self._emit(
            TBL_FWD_IN, 0, [], "NORMAL"))

        # ── Isolation ──
        self._emit_isolation()

        return "\n".join(self.flows) + "\n"

    # ─────────────────── per-rule emitters ───────────────────

    def _emit_macfilter(self, devname, ofport, rule, prio):
        """Per-port L2-only rule → table 0 flows.

        Two shapes route here (see _is_macfilter_rule):
          1. macspoof: src_mac_neg pure-L2 → N allow + 1 catchall drop
          2. mcast_limit: dst_mac_mask + rate_limit_pps → not supported
             on OVS (no clean meter mapping for per-flow pps). We warn
             and drop the rule silently rather than crash; user sees the
             warning and falls back to a Linux bridge for rate limits.
        """
        l2 = rule.match["l2"]

        if "src_mac_neg" in l2:
            neg = l2["src_mac_neg"]
            macs = neg if isinstance(neg, list) else [neg]
            for mac in macs:
                self.flows.append(self._emit(
                    TBL_INGRESS, prio,
                    [f"in_port={ofport}", f"dl_src={mac.lower()}"],
                    f"resubmit(,{TBL_RAW})",
                    source_id=rule.source_id))
            self.flows.append(self._emit(
                TBL_INGRESS, prio - 1,
                [f"in_port={ofport}"],
                "drop",
                source_id=rule.source_id))
            return prio - 2

        if rule.rate_limit_pps is not None and "dst_mac_mask" in l2:
            # mcast_limit → OpenFlow meter (OF1.3). The meter's drop band
            # fires when pps exceeds rate; within rate, the meter passes
            # through and we resubmit to the next table like any other
            # well-formed stateless rule. Burst 5 matches the nft backend's
            # `limit rate over N/second burst 5 packets` default.
            if not rule.source_id:
                # Defensive: meter ID needs a source_id to hash. Sugar
                # always provides one; fail loudly if something slipped.
                print("WARNING: ovsgen: mcast_limit rule lacks source_id, "
                      "skipping meter", file=sys.stderr)
                return prio
            meter_id = _meter_id_for(rule.source_id)
            burst = 5
            self._meters[meter_id] = (rule.rate_limit_pps, burst)
            addr, mask = l2["dst_mac_mask"]
            self.flows.append(self._emit(
                TBL_INGRESS, prio,
                [f"in_port={ofport}",
                 f"dl_dst={addr.lower()}/{mask.lower()}"],
                f"meter:{meter_id},resubmit(,{TBL_RAW})",
                source_id=rule.source_id))
            return prio - 1

        # Shouldn't reach here given _is_macfilter_rule's checks, but fail
        # loudly rather than silently mis-render.
        print(f"WARNING: ovsgen: unexpected macfilter shape, skipping: "
              f"match={rule.match}", file=sys.stderr)
        return prio

    def _emit_stateless(self, devname, ofport, rule, prio):
        """STATELESS rule → table 10 with in_port match.

        Pipeline: L2 list-valued fields (arp_op, vlan_id) → ipset variants
        (src_set/dst_set). All resulting flows share the same priority so
        set / OR-list elements are semantically peers of a single .fw rule.

        Pure-nomatch sets (elements=[], excludes=[allowed]) get special
        handling: per-allowed-IP "pass" flows at high prio + family
        catchall drop at low prio. Same pattern as macfilter but for L3.
        """
        action = "drop" if rule.action == "drop" else f"resubmit(,{TBL_CT_SEND})"
        pass_action = f"resubmit(,{TBL_CT_SEND})"

        for l2m in self._expand_l2_variants(rule.match):
            neg_result = self._try_emit_pure_neg(
                l2m, ofport, prio, pass_action, rule.source_id)
            if neg_result is not None:
                prio = neg_result
                continue
            # Normal path: expand sets via CIDR subtraction
            for v in self._expand_set_variants(l2m):
                parts = self._expand_match(v)
                self.flows.append(self._emit(
                    TBL_RAW, prio, [f"in_port={ofport}"] + parts, action,
                    source_id=rule.source_id))
            prio -= 1
        return prio

    def _try_emit_pure_neg(self, match, ofport, prio, pass_action, source_id=None):
        """If match references a pure-nomatch set (src or dst), emit inverted
        flows: per-allowed-IP pass + family catchall drop. Returns new prio
        if handled, None otherwise.

        Because ipspoof's ARP/v4/v6 rules use different ether_types, their
        catchall drops are mutually exclusive (arp vs ip vs ipv6), so
        multiple pure-neg rules on the same port compose correctly within
        a single table via priority bands.
        """
        l3 = match.get("l3", {})
        for set_key, field_fn in (
            ("src_set", self._neg_ip_field_src),
            ("dst_set", self._neg_ip_field_dst),
        ):
            sname = l3.get(set_key)
            if not sname:
                continue
            ns = self.rs.sets.get(sname)
            if not ns or ns.elements or not ns.excludes:
                continue
            # Pure-nomatch detected. Build base match without the set ref.
            base = copy.deepcopy(match)
            base["l3"].pop(set_key, None)
            base_parts = self._expand_match(base)
            ip_field = field_fn(base.get("l2", {}), ns.family)
            # Allow flow per excluded (= allowed) IP
            for ip in ns.excludes:
                self.flows.append(self._emit(
                    TBL_RAW, prio,
                    [f"in_port={ofport}"] + base_parts + [f"{ip_field}={ip}"],
                    pass_action,
                    source_id=source_id))
            # Catchall drop for this family
            self.flows.append(self._emit(
                TBL_RAW, prio - 1,
                [f"in_port={ofport}"] + base_parts,
                "drop",
                source_id=source_id))
            return prio - 2
        return None

    @staticmethod
    def _neg_ip_field_src(l2, family):
        et = l2.get("ether_type")
        if et == "arp":
            return "arp_spa"
        return "ipv6_src" if family == "ipv6" else "nw_src"

    @staticmethod
    def _neg_ip_field_dst(l2, family):
        et = l2.get("ether_type")
        if et == "arp":
            return "arp_tpa"
        return "ipv6_dst" if family == "ipv6" else "nw_dst"

    def _expand_variants(self, match):
        """Full L2+ipset expansion pipeline. Returns list of matches."""
        variants = []
        for l2m in self._expand_l2_variants(match):
            variants.extend(self._expand_set_variants(l2m))
        return variants

    def _expand_match_with_arp_op(self, m, op):
        """Render match with a specific single arp_op value."""
        m2 = {k: dict(v) for k, v in m.items()}
        m2["l2"]["arp_op"] = [op]
        return self._expand_match(m2)

    def _expand_l2_variants(self, match):
        """Split a match containing list-valued L2 fields into N singleton
        matches. Handles `arp_op` and `vlan_id` (both OR-lists in the IR).

        OVS has no "field IN {a, b}" match for these fields; we emit one
        flow per element at the same priority, matching nft `{a, b}` set
        semantic via OR-at-the-priority-band level.
        """
        variants = [match]
        out = []
        for v in variants:
            l2 = v.get("l2", {})
            arp_ops = l2.get("arp_op", [])
            if isinstance(arp_ops, list) and len(arp_ops) > 1:
                for op in arp_ops:
                    clone = copy.deepcopy(v)
                    clone["l2"]["arp_op"] = [op]
                    out.append(clone)
            else:
                out.append(v)

        variants = out
        out = []
        for v in variants:
            l2 = v.get("l2", {})
            vids = l2.get("vlan_id", [])
            if isinstance(vids, list) and len(vids) > 1:
                for vid in vids:
                    clone = copy.deepcopy(v)
                    clone["l2"]["vlan_id"] = [vid]
                    out.append(clone)
            else:
                out.append(v)
        return out

    # ─────────────────── ipset expansion (Strategy A) ───────────────────
    #
    # OVS has no set-membership match, so a rule referencing an ipset is
    # expanded into N flows — one per effective CIDR. "Effective CIDR list"
    # = elements − excludes, computed via IPv{4,6}Network.address_exclude()
    # which splits a network into disjoint pieces when a nested block is
    # carved out. For PVE's nomatch-in-ipset feature, this gives us
    # semantically exact results without per-rule OVS tables.
    #
    # Fragment count bound: excluding one /32 from a /24 produces 24
    # networks; each additional exclusion can double. For typical PVE
    # ipsets (a few excludes in broader ranges) fragmentation stays small;
    # worst case is bounded by the set size × prefix-length budget.

    def _effective_cidrs(self, set_name):
        """Return (family, list[str]) — effective CIDR list for an ipset.

        Positives minus excludes, using ipaddress CIDR arithmetic. Family
        is "ipv4" or "ipv6" taken from the NamedSet. Returns an empty list
        if the set reduces to nothing (every positive is masked out).
        """
        ns = self.rs.sets.get(set_name)
        if not ns:
            return None, []

        Net = ipaddress.IPv4Network if ns.family == "ipv4" else ipaddress.IPv6Network

        def _parse(s):
            try:
                return Net(s, strict=False)
            except ValueError:
                return None

        pos_nets = [n for n in (_parse(e) for e in ns.elements) if n is not None]
        exc_nets = [n for n in (_parse(e) for e in ns.excludes) if n is not None]

        for ex in exc_nets:
            survivors = []
            for pn in pos_nets:
                if not pn.overlaps(ex):
                    survivors.append(pn)
                    continue
                # Any two CIDRs are identical, one contains the other, or
                # disjoint — never partially overlapping. If pn is inside
                # ex (or equal) it's fully removed; otherwise carve ex out.
                if pn.subnet_of(ex):
                    continue
                survivors.extend(pn.address_exclude(ex))
            pos_nets = survivors

        return ns.family, [str(n) for n in pos_nets]

    def _expand_set_variants(self, match):
        """Return list[match_dict] with src_set/dst_set flattened to literals.

        Cross-product when both sides reference sets: |src| × |dst| variants.
        Empty list if any referenced side resolves to zero effective CIDRs
        (rule can never match, same as PVE behavior).
        """
        l3 = match.get("l3", {})
        src_set = l3.get("src_set")
        dst_set = l3.get("dst_set")
        if not src_set and not dst_set:
            return [match]

        if src_set:
            _, src_cidrs = self._effective_cidrs(src_set)
            if not src_cidrs:
                return []
        else:
            src_cidrs = [None]

        if dst_set:
            _, dst_cidrs = self._effective_cidrs(dst_set)
            if not dst_cidrs:
                return []
        else:
            dst_cidrs = [None]

        variants = []
        for s in src_cidrs:
            for d in dst_cidrs:
                m = copy.deepcopy(match)
                m.setdefault("l3", {}).pop("src_set", None)
                m["l3"].pop("dst_set", None)
                if s is not None:
                    m["l3"]["src_ip"] = s
                if d is not None:
                    m["l3"]["dst_ip"] = d
                variants.append(m)
        return variants

    def _warn_log_unsupported(self, rule):
        """Print a one-shot warning for rules with log_level on OVS.

        OVS has no nflog equivalent. The flow is still emitted — we just
        skip the log side-effect. Warning is rate-limited per render.
        """
        if not getattr(rule, "log_level", None):
            return
        if not hasattr(self, "_warned_log"):
            self._warned_log = True
            print(
                "WARNING: pvefw-neo OVS backend does not support -log; "
                "rule logging is silently dropped on OVS bridges. Switch "
                "the bridge to Linux+nftables if you need per-rule logs.",
                file=sys.stderr, flush=True,
            )

    def _emit_stateful_out(self, devname, ofport, rule, prio):
        """STATEFUL OUT rule → table 30 in_port match."""
        self._warn_log_unsupported(rule)
        variants = self._expand_variants(rule.match)
        if not variants:
            return prio
        if rule.action == "drop":
            action = "drop"
        else:  # accept (return semantics not needed in OVS — table 30 falls to 31)
            # ct(commit) only for IP traffic
            has_l3 = bool(rule.match.get("l3") or rule.match.get("l4"))
            action = f"ct(commit),resubmit(,{TBL_FWD_IN})" if has_l3 \
                     else f"resubmit(,{TBL_FWD_IN})"
        for v in variants:
            parts = self._expand_match(v)
            self.flows.append(self._emit(
                TBL_FWD_OUT, prio, [f"in_port={ofport}"] + parts, action,
                source_id=rule.source_id))
        return prio - 1

    def _emit_stateful_in(self, devname, mac, rule, prio):
        """STATEFUL IN rule → table 31 dl_dst match."""
        self._warn_log_unsupported(rule)
        variants = self._expand_variants(rule.match)
        if not variants:
            return prio
        if rule.action == "drop":
            action = "drop"
        else:
            has_l3 = bool(rule.match.get("l3") or rule.match.get("l4"))
            action = "ct(commit),NORMAL" if has_l3 else "NORMAL"
        for v in variants:
            parts = self._expand_match(v)
            self.flows.append(self._emit(
                TBL_FWD_IN, prio, [f"dl_dst={mac}"] + parts, action,
                source_id=rule.source_id))
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
            if nd and nd.isolated and not nd.disabled:
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
