"""
nftables backend: IR Ruleset → nftables text.

Pure renderer. Consumes new per-NetDev IR.

Pipeline mapping:
  IR Phase                              → nftables hook
  ───────────────────────────────────────────────────────────
  STATELESS, pure-L2 (only L2 fields)   → table netdev pvefw-neo-<dev>
                                          chain ingress, hook ingress, prio -300
  STATELESS, has L3+                    → table bridge pvefw-neo
                                          chain raw_prerouting, prio -300
  STATEFUL                              → table bridge pvefw-neo
                                          chain forward, prio filter
                                          + per-(dev,direction) sub-chains

NetDev with no STATEFUL rules: skipped from forward dispatch entirely
(packets pass through without entering conntrack).
"""

from . import ir


# ═══════════════════════════════════════
# Public API
# ═══════════════════════════════════════

def render(ruleset, devnames=None):
    """Render IR Ruleset → nftables text + isolated devices list.

    Args:
      ruleset: ir.Ruleset
      devnames: optional iterable of devnames to include.
                If None, include all NetDevs in ruleset.

    Returns:
      (nft_text, isolated_devs) where isolated_devs is a list of devnames
      that should have kernel bridge port isolation enabled.
    """
    if devnames is None:
        devnames = list(ruleset.netdevs.keys())
    return NftRenderer(ruleset, set(devnames)).render()


# ═══════════════════════════════════════
# Renderer
# ═══════════════════════════════════════

class NftRenderer:
    def __init__(self, ruleset, devnames):
        self.rs = ruleset
        self.devnames = devnames  # set
        # Per-device netdev rules (pure-L2 stateless)
        self._netdev_rules = {}    # devname → [str]
        # Bridge raw chain rules
        self._raw_rules = []       # [str]
        # Per (devname, direction) stateful sub-chain rules
        self._fwd_chains = {}      # (devname, direction) → [str]
        # NetDevs that have STATEFUL rules (need forward dispatch)
        self._stateful_devs = set()
        # NamedSets used by rules in this render
        self._used_sets = set()

    # ─────────────────── helpers ───────────────────

    @staticmethod
    def _is_macfilter_rule(rule):
        """Detect rules that should go to per-device netdev table.

        Only standalone L2-filter rules belong here (macspoof, mcast_limit).
        Rules that are part of a sequence (ipspoof allow + drop) must NOT
        be split — they all stay in shared bridge raw chain.

        Heuristic: src_mac_neg (macspoof) or dst_mac_mask + rate_limit (mcast_limit).
        """
        l2 = rule.match.get("l2", {})
        # macspoof: src MAC negation, no other fields
        if "src_mac_neg" in l2 and not rule.match.get("l3") and not rule.match.get("l4"):
            return True
        # mcast_limit: rate limit on multicast bit
        if rule.rate_limit_pps is not None and "dst_mac_mask" in l2:
            return True
        return False

    @staticmethod
    def _action_str(action):
        if action in ("accept", "drop"):
            return action
        return "drop"  # safe default

    @staticmethod
    def _ether_type_to_nft(et):
        return {"ip": "ip", "ip6": "ip6", "arp": "arp", "vlan": "8021q"}.get(et, et)

    @staticmethod
    def _proto_to_nft(proto):
        if not proto:
            return None
        proto = proto.lower()
        if proto in ("tcp", "udp", "icmp", "icmpv6"):
            return proto
        # Numeric or other protocols
        return proto

    def _render_match(self, match):
        """Render an IR match dict to nftables match tokens."""
        parts = []
        l2 = match.get("l2", {})
        l3 = match.get("l3", {})
        l4 = match.get("l4", {})

        # ── L2 ──
        if "src_mac" in l2:
            parts.append(f"ether saddr {l2['src_mac']}")
        if "src_mac_neg" in l2:
            neg = l2["src_mac_neg"]
            if isinstance(neg, list):
                if len(neg) == 1:
                    parts.append(f"ether saddr != {neg[0]}")
                else:
                    parts.append("ether saddr != { " + ", ".join(neg) + " }")
            else:
                parts.append(f"ether saddr != {neg}")
        if "src_mac_mask" in l2:
            addr, mask = l2["src_mac_mask"]
            parts.append(f"ether saddr & {mask} == {addr}")
        if "dst_mac" in l2:
            parts.append(f"ether daddr {l2['dst_mac']}")
        if "dst_mac_mask" in l2:
            addr, mask = l2["dst_mac_mask"]
            parts.append(f"ether daddr & {mask} == {addr}")

        if "ether_type" in l2:
            et = self._ether_type_to_nft(l2["ether_type"])
            parts.append(f"ether type {et}")
        if "ether_type_neg" in l2:
            et = self._ether_type_to_nft(l2["ether_type_neg"])
            parts.append(f"ether type != {et}")

        if "vlan_id" in l2:
            vids = l2["vlan_id"]
            if len(vids) == 1:
                parts.append(f"vlan id {vids[0]}")
            else:
                parts.append("vlan id { " + ", ".join(str(v) for v in vids) + " }")

        if "arp_op" in l2:
            ops = l2["arp_op"]
            if len(ops) == 1:
                parts.append(f"arp operation {ops[0]}")
            else:
                parts.append("arp operation { " + ", ".join(ops) + " }")
        if "arp_spa" in l2:
            parts.append(f"arp saddr ip {l2['arp_spa']}")

        # ── L3 ──
        # ip prefix depends on ether_type
        et = l2.get("ether_type", "ip")
        ip_pfx = "ip" if et == "ip" else ("ip6" if et == "ip6" else "ip")

        if "src_ip" in l3:
            parts.append(f"{ip_pfx} saddr {l3['src_ip']}")
        if "dst_ip" in l3:
            parts.append(f"{ip_pfx} daddr {l3['dst_ip']}")
        # ipset refs: pure-nomatch (empty positive + non-empty excludes) is
        # treated as pure negation — emit only `saddr != @<set>_nomatch`.
        # Mixed sets emit both the positive membership AND the nomatch
        # negation (mirrors official PVE Rust impl).
        #
        # When the rule is on ether_type=arp, the set reference targets the
        # ARP sender protocol address (`arp saddr ip`) rather than the
        # regular L3 src IP. This lets @neo:ipspoof reuse one IPv4 NamedSet
        # for both IPv4 and ARP enforcement.
        is_arp = (l2.get("ether_type") == "arp")
        saddr_field = "arp saddr ip" if is_arp else f"{ip_pfx} saddr"
        daddr_field = "arp daddr ip" if is_arp else f"{ip_pfx} daddr"
        if "src_set" in l3:
            sname = l3["src_set"]
            self._used_sets.add(sname)
            ns = self.rs.sets.get(sname)
            if ns and not ns.elements and ns.excludes:
                parts.append(f"{saddr_field} != @{sname}_nomatch")
            else:
                parts.append(f"{saddr_field} @{sname}")
                if ns and ns.excludes:
                    parts.append(f"{saddr_field} != @{sname}_nomatch")
        if "dst_set" in l3:
            sname = l3["dst_set"]
            self._used_sets.add(sname)
            ns = self.rs.sets.get(sname)
            if ns and not ns.elements and ns.excludes:
                parts.append(f"{daddr_field} != @{sname}_nomatch")
            else:
                parts.append(f"{daddr_field} @{sname}")
                if ns and ns.excludes:
                    parts.append(f"{daddr_field} != @{sname}_nomatch")

        if "proto" in l3:
            proto = self._proto_to_nft(l3["proto"])
            parts.append(f"meta l4proto {proto}")

        if "icmp_type" in l3:
            types = l3["icmp_type"]
            if len(types) == 1:
                parts.append(f"icmp type {types[0]}")
            else:
                parts.append("icmp type { " + ", ".join(types) + " }")
        if "icmpv6_type" in l3:
            types = l3["icmpv6_type"]
            if len(types) == 1:
                parts.append(f"icmpv6 type {types[0]}")
            else:
                parts.append("icmpv6 type { " + ", ".join(types) + " }")

        # ── L4 ──
        proto_name = l3.get("proto", "tcp").lower()
        if "src_port" in l4:
            parts.append(f"{proto_name} sport {self._fmt_port(l4['src_port'])}")
        if "dst_port" in l4:
            parts.append(f"{proto_name} dport {self._fmt_port(l4['dst_port'])}")

        return parts

    @staticmethod
    def _fmt_port(p):
        """Compiler uses {80,443} but nft wants { 80, 443 }."""
        if p.startswith("{") and p.endswith("}"):
            inner = p[1:-1]
            return "{ " + ", ".join(s.strip() for s in inner.split(",")) + " }"
        return p

    # ─────────────────── classify rules ───────────────────

    def _classify(self):
        """Distribute rules into target buckets."""
        for devname in sorted(self.rs.netdevs):
            if devname not in self.devnames:
                continue
            nd = self.rs.netdevs[devname]

            # @neo:disable: skip the port entirely. No netdev table, no
            # bridge raw rules, no forward dispatch → packets pass through
            # without any filtering or conntrack (equivalent to the port
            # having no rules at all).
            if nd.disabled:
                continue

            for r in nd.rules:
                if r.phase == ir.Phase.STATELESS:
                    self._handle_stateless(devname, r)
                else:  # STATEFUL
                    self._handle_stateful(devname, nd, r)

    def _handle_stateless(self, devname, rule):
        """STATELESS rule → netdev table (macfilter) or bridge raw."""
        match_parts = self._render_match(rule.match)
        action = self._action_str(rule.action)

        if rule.rate_limit_pps is not None:
            limit_clause = f"limit rate over {rule.rate_limit_pps}/second"
            line = " ".join(match_parts + [limit_clause, action])
        else:
            line = " ".join(match_parts + [action])

        if self._is_macfilter_rule(rule):
            # netdev ingress (per-device, no iif prefix needed)
            self._netdev_rules.setdefault(devname, []).append(line)
        else:
            # bridge raw_prerouting (needs iif/oif prefix)
            iface_prefix = self._iface_prefix(devname, rule.direction)
            self._raw_rules.append(f"{iface_prefix} {line}")

    def _handle_stateful(self, devname, netdev, rule):
        """STATEFUL rule → per-(devname, direction) sub-chain.

        When `rule.log_level` is set we emit a *separate* log rule with the
        same match conditions before the verdict rule. Mirrors official
        Rust impl `RuleMatch::to_nft_rules` which pushes a log NftRule first
        and then the verdict NftRule, both carrying identical match clauses.
        """
        self._stateful_devs.add(devname)
        key = (devname, rule.direction)
        match_parts = self._render_match(rule.match)
        action = self._action_str(rule.action)

        # OUT chain uses jump from forward, accept must become return
        # so the IN check has a chance to run for VM-to-VM traffic.
        if rule.direction == ir.Direction.OUT and action == "accept":
            action = "return"

        chain = self._fwd_chains.setdefault(key, [])

        if rule.log_level:
            log_clause = self._log_clause(
                netdev.vmid, rule.log_level, key, action,
            )
            chain.append(" ".join(match_parts + [log_clause]).strip())

        chain.append(" ".join(match_parts + [action]).strip())

    # nflog_level mapping mirrors official LogLevel::nflog_level()
    # (proxmox-nftables/src/statement.rs:232).
    _NFLOG_LEVEL = {
        "emerg": 0, "alert": 1, "crit": 2, "err": 3,
        "warning": 4, "notice": 5, "info": 6, "debug": 7,
    }

    @classmethod
    def _log_clause(cls, vmid, level, chain_key, verdict):
        """Build a rate-limited `nflog` clause.

        Prefix format is bit-for-bit `Log::generate_prefix`:
          ":<vmid>:<nflog_level>:<chain_name>: <verdict>: "
        Group 0, matching official.
        """
        devname, direction = chain_key
        dir_tag = "in" if direction == ir.Direction.IN else "out"
        chain_name = f"guest-{vmid or 0}-{dir_tag}"
        nflog_lvl = cls._NFLOG_LEVEL.get(level, 6)
        prefix = f":{vmid or 0}:{nflog_lvl}:{chain_name}: {verdict}: "
        return f'limit rate 10/second log prefix "{prefix}" group 0'

    @staticmethod
    def _iface_prefix(devname, direction):
        """nftables iif/oif prefix for a (devname, direction) pair."""
        if direction == ir.Direction.OUT:
            return f'iifname "{devname}"'
        return f'oifname "{devname}"'

    # ─────────────────── render ───────────────────

    def render(self):
        self._classify()

        lines = []
        lines.append("# Generated by pvefw-neo (new IR backend)")
        lines.append("")

        # Flush bridge table (netdev tables are cleaned up in main.apply_ruleset
        # before this script runs, to handle disabled / removed ports).
        lines.append("# Flush existing pvefw-neo bridge table")
        lines.append("table bridge pvefw-neo")
        lines.append("delete table bridge pvefw-neo")
        lines.append("")

        # ── Netdev tables (per-device pure-L2 stateless) ──
        if self._netdev_rules:
            lines.append("# ═══ netdev ingress (pure-L2 stateless) ═══")
            for devname in sorted(self._netdev_rules):
                lines.append(f"table netdev pvefw-neo-{devname} {{")
                lines.append(f"    chain ingress {{")
                lines.append(
                    f'        type filter hook ingress device "{devname}" '
                    f"priority -300; policy accept;"
                )
                for rule_line in self._netdev_rules[devname]:
                    lines.append(f"        {rule_line}")
                lines.append("    }")
                lines.append("}")
                lines.append("")

        # ── Bridge table ──
        lines.append("# ═══ bridge family ═══")
        lines.append("table bridge pvefw-neo {")

        # Named sets (only those actually used).
        # Per PVE official: each IPSet that has negative members emits a
        # paired `<name>_nomatch` set. Pure-nomatch sets (no positive
        # members) are rendered in nftgen as set-negation only (see
        # _render_match) and do NOT need the empty `<name>` set emitted.
        for set_name in sorted(self._used_sets):
            ns = self.rs.sets.get(set_name)
            if not ns:
                continue
            nft_type = "ipv4_addr" if ns.family == "ipv4" else "ipv6_addr"
            if ns.elements:
                lines.append(f"    set {ns.name} {{")
                lines.append(f"        type {nft_type}; flags interval;")
                elems = ", ".join(ns.elements)
                lines.append(f"        elements = {{ {elems} }}")
                lines.append("    }")
            if ns.excludes:
                lines.append(f"    set {ns.name}_nomatch {{")
                lines.append(f"        type {nft_type}; flags interval;")
                elems = ", ".join(ns.excludes)
                lines.append(f"        elements = {{ {elems} }}")
                lines.append("    }")

        # raw_prerouting (stateless with L3+)
        lines.append("")
        lines.append("    chain raw_prerouting {")
        lines.append(
            "        type filter hook prerouting priority -300; policy accept;"
        )
        for rl in self._raw_rules:
            lines.append(f"        {rl}")
        lines.append("    }")

        # forward (stateful)
        lines.append("")
        lines.append("    chain forward {")
        lines.append(
            "        type filter hook forward priority filter; policy accept;"
        )
        # Skip rules entirely if no NetDev has STATEFUL rules
        if self._stateful_devs:
            # ARP pass-through (so MAC learning works)
            lines.append("        ether type arp accept")
            # Conntrack framework
            lines.append("        ct state established,related accept")

            # Per-NetDev dispatch
            for devname in sorted(self._stateful_devs):
                key_out = (devname, ir.Direction.OUT)
                key_in = (devname, ir.Direction.IN)
                has_out = key_out in self._fwd_chains
                has_in = key_in in self._fwd_chains
                if has_out:
                    lines.append(
                        f'        iifname "{devname}" jump '
                        f"vm_{devname}_out"
                    )
                if has_in:
                    lines.append(
                        f'        oifname "{devname}" goto '
                        f"vm_{devname}_in"
                    )
        lines.append("    }")

        # Per-(dev, direction) sub-chains
        for (devname, direction) in sorted(self._fwd_chains.keys(),
                                            key=lambda k: (k[0], k[1].value)):
            chain_name = (f"vm_{devname}_out" if direction == ir.Direction.OUT
                         else f"vm_{devname}_in")
            lines.append("")
            lines.append(f"    chain {chain_name} {{")
            nd = self.rs.netdevs.get(devname)
            if nd and nd.ctinvalid:
                lines.append("        ct state invalid drop")
            for rl in self._fwd_chains[(devname, direction)]:
                lines.append(f"        {rl}")
            lines.append("    }")

        lines.append("}")
        lines.append("")

        # Isolation: list of devs with isolated=True and NOT disabled
        # (disabled port should pass everything, including peer-to-peer)
        isolated_devs = [
            nd.devname for nd in self.rs.netdevs.values()
            if nd.devname in self.devnames and nd.isolated and not nd.disabled
        ]

        return "\n".join(lines), isolated_devs
