"""
Compiler: parser output → IR Ruleset (new per-NetDev structure)

Expands sugar tags, resolves aliases/ipsets/macros/security groups,
produces a backend-agnostic IR Ruleset organized per NetDev.
"""

import copy
import ipaddress
import re

from . import ir
from . import parser
from . import macros as macros_mod
from . import vmdevs


# ═══════════════════════════════════════
# Helpers
# ═══════════════════════════════════════

def is_ipv4(addr):
    try:
        ipaddress.IPv4Address(addr.split("/")[0])
        return True
    except (ValueError, IndexError):
        return False


def is_ipv6(addr):
    try:
        ipaddress.IPv6Address(addr.split("/")[0])
        return True
    except (ValueError, IndexError):
        return False


def normalize_port(port_str):
    """Normalize PVE port spec: '80:443' → '80-443', '80,443' → '{80,443}'."""
    if not port_str:
        return None
    if "," in port_str:
        ports = [p.replace(":", "-") for p in port_str.split(",")]
        return "{" + ",".join(ports) + "}"
    return port_str.replace(":", "-")


# ═══════════════════════════════════════
# Compiler
# ═══════════════════════════════════════

class Compiler:
    """Compile parsed PVE firewall configs into IR Ruleset."""

    def __init__(self):
        self.macros = macros_mod.get_macros()
        self.netdevs = {}     # devname → ir.NetDev (in progress)
        self.sets = {}        # set_name → ir.NamedSet
        self._set_families = {}  # set_name → "ipv4" / "ipv6"

    def compile(self):
        """Compile all VMs with .fw files into an IR Ruleset."""
        vm_ids = vmdevs.discover_vms()

        for vmid in vm_ids:
            config = parser.parse_vm_fw(vmid)
            if not config.options.enable:
                continue

            nets, is_ct = vmdevs.get_vm_nets(vmid)
            if not nets:
                continue

            # Pre-create NetDev for each interface.
            #
            # Hard requirement: NIC must NOT have `firewall=1` in VM config.
            #
            # Rationale: PVE automatically creates a fwbr (firewall bridge)
            # between tap/veth and vmbr whenever NIC has `firewall=1` (on
            # OVS always, and on Linux bridge when `is_nftables()=false`).
            # The fwbr breaks pvefw-neo's direct-attach model. Users must
            # set `firewall=0` (or leave unset) on every NIC; install.sh
            # offers to bulk-flip existing firewall=1 NICs.
            #
            # Ports with firewall=1 are warned and skipped. Everything
            # else (firewall=0 or unset) becomes a candidate NetDev.
            #
            # For per-port debug, use `@neo:disable` in the .fw file to
            # temporarily bypass a port's rules without touching the
            # VM config (see _sugar_disable).
            for iface_name, net_info in nets.items():
                if net_info.get("firewall") == 1:
                    print(
                        f"WARNING: vm{vmid} {iface_name} has 'firewall=1' "
                        f"— PVE will build a fwbr and pvefw-neo cannot "
                        f"manage this port. Set firewall=0 (or unset) to "
                        f"fix, or run install.sh to bulk-flip.",
                        flush=True,
                    )
                    continue
                devname = vmdevs.get_device_name(vmid, net_info["id"], is_ct)
                self.netdevs[devname] = ir.NetDev(
                    devname=devname,
                    mac=(net_info.get("mac") or "").upper(),
                    vmid=vmid,
                    iface=iface_name,
                )

            # Process rules. @neo:disable sugar handler may mark NetDevs as
            # disabled; NetDev lookup silently skips missing NetDevs so
            # warn-skipped firewall=1 ports are inert.
            self._compile_vm(vmid, config, nets, is_ct)

            # Translate policy_in / policy_out to explicit catch-all rules
            self._add_policy_catchalls(vmid, config, nets, is_ct)

        return ir.Ruleset(netdevs=self.netdevs, sets=self.sets)

    # ═══════════════════════════════════════
    # Per-VM compilation
    # ═══════════════════════════════════════

    def _compile_vm(self, vmid, config, nets, is_ct):
        for rule in config.rules:
            if rule.is_group:
                self._expand_group(vmid, config, nets, is_ct, rule)
            elif rule.is_sugar():
                self._expand_sugar(vmid, config, nets, is_ct, rule)
            elif rule.is_notrack():
                self._expand_notrack(vmid, config, nets, is_ct, rule)
            else:
                self._expand_stateful(vmid, config, nets, is_ct, rule)

    def _add_policy_catchalls(self, vmid, config, nets, is_ct):
        """Translate [OPTIONS] policy_in/out to explicit catch-all rules."""
        pol_in = config.options.policy_in.upper()
        pol_out = config.options.policy_out.upper()

        for iface_name, net_info in nets.items():
            devname = vmdevs.get_device_name(vmid, net_info["id"], is_ct)
            nd = self.netdevs.get(devname)
            if nd is None:
                continue

            # IN catch-all if not ACCEPT
            if pol_in != "ACCEPT":
                nd.rules.append(ir.Rule(
                    direction=ir.Direction.IN,
                    phase=ir.Phase.STATEFUL,
                    match={},
                    action="drop",
                    comment=f"policy_in {pol_in}",
                ))

            # OUT catch-all if not ACCEPT
            if pol_out != "ACCEPT":
                nd.rules.append(ir.Rule(
                    direction=ir.Direction.OUT,
                    phase=ir.Phase.STATEFUL,
                    match={},
                    action="drop",
                    comment=f"policy_out {pol_out}",
                ))

    # ═══════════════════════════════════════
    # iface → devname helpers
    # ═══════════════════════════════════════

    def _get_devname(self, vmid, iface, nets, is_ct):
        if iface and iface in nets:
            return vmdevs.get_device_name(vmid, nets[iface]["id"], is_ct)
        if iface:
            m = re.match(r"net(\d+)", iface)
            if m:
                return vmdevs.get_device_name(vmid, int(m.group(1)), is_ct)
        return None

    def _get_iface_devnames(self, vmid, rule, nets, is_ct):
        """Return list of (iface, devname) for a rule."""
        if rule.iface:
            devname = self._get_devname(vmid, rule.iface, nets, is_ct)
            if devname:
                return [(rule.iface, devname)]
            return []
        # No iface = applies to all ports
        result = []
        for net_name, net_info in sorted(nets.items()):
            devname = vmdevs.get_device_name(vmid, net_info["id"], is_ct)
            result.append((net_name, devname))
        return result

    def _add_rule(self, devname, rule):
        """Append a Rule to a NetDev's rules list."""
        nd = self.netdevs.get(devname)
        if nd:
            nd.rules.append(rule)

    # ═══════════════════════════════════════
    # PVE direction → IR Direction
    # ═══════════════════════════════════════

    @staticmethod
    def _pve_dir(direction):
        if direction == "OUT":
            return ir.Direction.OUT
        if direction == "IN":
            return ir.Direction.IN
        return ir.Direction.OUT  # FORWARD treated as OUT for now

    # ═══════════════════════════════════════
    # Sugar tag expansion
    # ═══════════════════════════════════════

    def _expand_sugar(self, vmid, config, nets, is_ct, rule):
        for tag in rule.neo_tags:
            handler = {
                "macspoof":    self._sugar_macspoof,
                "ipspoof":     self._sugar_ipspoof,
                "nodhcp":      self._sugar_nodhcp,
                "nora":        self._sugar_nora,
                "nondp":       self._sugar_nondp,
                "mcast_limit": self._sugar_mcast_limit,
                "isolated":    self._sugar_isolated,
                "disable":     self._sugar_disable,
            }.get(tag.name)
            if handler:
                handler(vmid, config, nets, is_ct, rule, tag)

    def _sugar_macspoof(self, vmid, config, nets, is_ct, rule, tag):
        """@neo:macspoof → STATELESS rule with src_mac_neg (purely L2)."""
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            mac = tag.args[0].upper() if tag.args else nets.get(iface, {}).get("mac")
            if not mac:
                continue
            self._add_rule(devname, ir.Rule(
                direction=ir.Direction.OUT,
                phase=ir.Phase.STATELESS,
                match={"l2": {"src_mac_neg": mac.upper()}},
                action="drop",
                comment=f"@neo:macspoof {mac.upper()}",
            ))

    def _sugar_ipspoof(self, vmid, config, nets, is_ct, rule, tag):
        """@neo:ipspoof → STATELESS rules: ARP whitelist + IPv4/IPv6 src whitelist."""
        if not tag.args:
            return
        ips = tag.args[0].split(",")
        v4_ips = [ip for ip in ips if is_ipv4(ip.split("/")[0])]
        v6_ips = [ip for ip in ips if is_ipv6(ip.split("/")[0])]

        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            # ── ARP protection ──
            if v4_ips:
                for ip in v4_ips:
                    ip_bare = ip.split("/")[0]
                    self._add_rule(devname, ir.Rule(
                        direction=ir.Direction.OUT,
                        phase=ir.Phase.STATELESS,
                        match={"l2": {"ether_type": "arp",
                                      "arp_op": ["request", "reply"],
                                      "arp_spa": ip_bare}},
                        action="accept",
                        comment=f"@neo:ipspoof ARP allow {ip_bare}",
                    ))
                self._add_rule(devname, ir.Rule(
                    direction=ir.Direction.OUT,
                    phase=ir.Phase.STATELESS,
                    match={"l2": {"ether_type": "arp"}},
                    action="drop",
                    comment="@neo:ipspoof ARP drop rest",
                ))

            # ── IPv4 protection ──
            if v4_ips:
                for ip in v4_ips:
                    self._add_rule(devname, ir.Rule(
                        direction=ir.Direction.OUT,
                        phase=ir.Phase.STATELESS,
                        match={"l2": {"ether_type": "ip"},
                               "l3": {"src_ip": ip}},
                        action="accept",
                        comment=f"@neo:ipspoof IPv4 allow {ip}",
                    ))
                self._add_rule(devname, ir.Rule(
                    direction=ir.Direction.OUT,
                    phase=ir.Phase.STATELESS,
                    match={"l2": {"ether_type": "ip"}},
                    action="drop",
                    comment="@neo:ipspoof IPv4 drop rest",
                ))

            # ── IPv6 protection (always added when any ipspoof is set) ──
            if v6_ips or v4_ips:
                # DAD: ::0 source NS
                self._add_rule(devname, ir.Rule(
                    direction=ir.Direction.OUT,
                    phase=ir.Phase.STATELESS,
                    match={"l2": {"ether_type": "ip6"},
                           "l3": {"src_ip": "::0",
                                  "icmpv6_type": ["nd-neighbor-solicit"]}},
                    action="accept",
                    comment="@neo:ipspoof IPv6 DAD",
                ))
                # Link-local
                self._add_rule(devname, ir.Rule(
                    direction=ir.Direction.OUT,
                    phase=ir.Phase.STATELESS,
                    match={"l2": {"ether_type": "ip6"},
                           "l3": {"src_ip": "fe80::/10"}},
                    action="accept",
                    comment="@neo:ipspoof IPv6 link-local",
                ))
                for ip in v6_ips:
                    self._add_rule(devname, ir.Rule(
                        direction=ir.Direction.OUT,
                        phase=ir.Phase.STATELESS,
                        match={"l2": {"ether_type": "ip6"},
                               "l3": {"src_ip": ip}},
                        action="accept",
                        comment=f"@neo:ipspoof IPv6 allow {ip}",
                    ))
                self._add_rule(devname, ir.Rule(
                    direction=ir.Direction.OUT,
                    phase=ir.Phase.STATELESS,
                    match={"l2": {"ether_type": "ip6"}},
                    action="drop",
                    comment="@neo:ipspoof IPv6 drop rest",
                ))

    def _sugar_nodhcp(self, vmid, config, nets, is_ct, rule, tag):
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            self._add_rule(devname, ir.Rule(
                direction=ir.Direction.OUT,
                phase=ir.Phase.STATELESS,
                match={"l2": {"ether_type": "ip"},
                       "l3": {"proto": "udp"},
                       "l4": {"src_port": "67", "dst_port": "68"}},
                action="drop",
                comment="@neo:nodhcp v4",
            ))
            self._add_rule(devname, ir.Rule(
                direction=ir.Direction.OUT,
                phase=ir.Phase.STATELESS,
                match={"l2": {"ether_type": "ip6"},
                       "l3": {"proto": "udp"},
                       "l4": {"src_port": "547", "dst_port": "546"}},
                action="drop",
                comment="@neo:nodhcp v6",
            ))

    def _sugar_nora(self, vmid, config, nets, is_ct, rule, tag):
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            self._add_rule(devname, ir.Rule(
                direction=ir.Direction.OUT,
                phase=ir.Phase.STATELESS,
                match={"l2": {"ether_type": "ip6"},
                       "l3": {"icmpv6_type": ["nd-router-advert"]}},
                action="drop",
                comment="@neo:nora",
            ))

    def _sugar_nondp(self, vmid, config, nets, is_ct, rule, tag):
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            self._add_rule(devname, ir.Rule(
                direction=ir.Direction.OUT,
                phase=ir.Phase.STATELESS,
                match={"l2": {"ether_type": "ip6"},
                       "l3": {"icmpv6_type": ["nd-neighbor-solicit",
                                              "nd-neighbor-advert"]}},
                action="drop",
                comment="@neo:nondp",
            ))

    def _sugar_mcast_limit(self, vmid, config, nets, is_ct, rule, tag):
        if not tag.args:
            return
        pps = int(tag.args[0])
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            self._add_rule(devname, ir.Rule(
                direction=ir.Direction.OUT,
                phase=ir.Phase.STATELESS,
                match={"l2": {"dst_mac_mask": ("01:00:00:00:00:00",
                                               "01:00:00:00:00:00")}},
                action="drop",
                rate_limit_pps=pps,
                comment=f"@neo:mcast_limit {pps}",
            ))

    def _sugar_isolated(self, vmid, config, nets, is_ct, rule, tag):
        """@neo:isolated → set NetDev.isolated, no rule generated."""
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            nd = self.netdevs.get(devname)
            if nd:
                nd.isolated = True

    def _sugar_disable(self, vmid, config, nets, is_ct, rule, tag):
        """@neo:disable → set NetDev.disabled (debug: bypass this port).

        Equivalent to removing all rules for this port so packets pass
        through without any filtering or conntrack. Useful for quickly
        turning off a port's firewall to diagnose connectivity issues
        without touching VM config or deleting rules.

        Without `-i netN` the disable applies to all ports of the VM.
        """
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            nd = self.netdevs.get(devname)
            if nd:
                nd.disabled = True

    # ═══════════════════════════════════════
    # @neo:notrack rule expansion
    # ═══════════════════════════════════════

    def _expand_notrack(self, vmid, config, nets, is_ct, rule):
        mac_tag = rule.get_neo_tag("mac")
        vlan_tag = rule.get_neo_tag("vlan")

        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            ir_rules = self._build_notrack_rules(
                vmid, config, devname, rule, mac_tag, vlan_tag
            )
            for r in ir_rules:
                self._add_rule(devname, r)

    def _build_notrack_rules(self, vmid, config, devname, rule, mac_tag, vlan_tag):
        """Build IR rules for a @neo:notrack rule."""
        base_match = {"l2": {}, "l3": {}, "l4": {}}

        # MAC tag
        if mac_tag and mac_tag.args:
            src_mac = mac_tag.args[0]
            if src_mac != "*":
                base_match["l2"]["src_mac"] = src_mac
            if len(mac_tag.args) > 1:
                dst_mac = mac_tag.args[1]
                if dst_mac != "*":
                    base_match["l2"]["dst_mac"] = dst_mac

        # VLAN tag
        if vlan_tag and vlan_tag.args:
            vlan_str = vlan_tag.args[0]
            if vlan_str == "untagged":
                base_match["l2"]["ether_type_neg"] = "vlan"
            else:
                base_match["l2"]["vlan_id"] = [int(v) for v in vlan_str.split(",")]

        # Source/dest (sets ether_type)
        self._apply_src_dst(base_match, rule, config)

        # Protocol + ports
        if rule.proto:
            base_match["l3"]["proto"] = rule.proto.lower()
        if rule.sport:
            base_match["l4"]["src_port"] = normalize_port(rule.sport)
        if rule.dport:
            base_match["l4"]["dst_port"] = normalize_port(rule.dport)

        action = "drop" if rule.action in ("DROP", "REJECT") else "accept"
        direction = self._pve_dir(rule.direction)

        # Macro expansion
        if rule.macro and rule.macro != "Finger":
            return self._expand_macro_rules(base_match, rule, action,
                                           direction, ir.Phase.STATELESS)

        return [ir.Rule(
            direction=direction,
            phase=ir.Phase.STATELESS,
            match=_clean_match(base_match),
            action=action,
            comment=rule.comment or "",
        )]

    # ═══════════════════════════════════════
    # Stateful rule expansion
    # ═══════════════════════════════════════

    def _expand_stateful(self, vmid, config, nets, is_ct, rule):
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            ir_rules = self._build_stateful_rules(vmid, config, rule)
            for r in ir_rules:
                self._add_rule(devname, r)

    def _build_stateful_rules(self, vmid, config, rule):
        action = "drop" if rule.action in ("DROP", "REJECT") else "accept"
        direction = self._pve_dir(rule.direction)

        if rule.macro:
            macro_entries = self.macros.get(rule.macro, [])
            if not macro_entries:
                return []
            base_match = {"l2": {}, "l3": {}, "l4": {}}
            self._apply_src_dst(base_match, rule, config)
            return self._expand_macro_rules(base_match, rule, action,
                                           direction, ir.Phase.STATEFUL)

        # No macro: build single rule
        match = {"l2": {}, "l3": {}, "l4": {}}
        self._apply_src_dst(match, rule, config)
        if rule.proto:
            match["l3"]["proto"] = rule.proto.lower()
        if rule.sport:
            match["l4"]["src_port"] = normalize_port(rule.sport)
        if rule.dport:
            match["l4"]["dst_port"] = normalize_port(rule.dport)

        return [ir.Rule(
            direction=direction,
            phase=ir.Phase.STATEFUL,
            match=_clean_match(match),
            action=action,
            comment=rule.comment or "",
        )]

    def _expand_macro_rules(self, base_match, rule, action, direction, phase):
        """Expand a PVE macro into multiple IR rules, merging with base match."""
        macro_entries = self.macros.get(rule.macro, [])
        results = []
        for entry in macro_entries:
            m = copy.deepcopy(base_match)
            proto = entry.get("proto")
            if proto:
                m["l3"]["proto"] = proto.lower()
            if entry.get("dport"):
                m["l4"]["dst_port"] = normalize_port(entry["dport"])
            if entry.get("sport"):
                m["l4"]["src_port"] = normalize_port(entry["sport"])
            results.append(ir.Rule(
                direction=direction,
                phase=phase,
                match=_clean_match(m),
                action=action,
                comment=rule.comment or "",
            ))
        return results

    # ═══════════════════════════════════════
    # Group expansion
    # ═══════════════════════════════════════

    def _expand_group(self, vmid, config, nets, is_ct, rule):
        group_name = rule.group_name
        if not group_name or group_name not in config.security_groups:
            return
        for grule in config.security_groups[group_name]:
            if rule.iface and not grule.iface:
                grule.iface = rule.iface
            if grule.is_sugar():
                self._expand_sugar(vmid, config, nets, is_ct, grule)
            elif grule.is_notrack():
                self._expand_notrack(vmid, config, nets, is_ct, grule)
            else:
                self._expand_stateful(vmid, config, nets, is_ct, grule)

    # ═══════════════════════════════════════
    # Source/dest resolution
    # ═══════════════════════════════════════

    def _apply_src_dst(self, match, rule, config):
        """Resolve source/dest into match dict, set ether_type."""
        src = self._resolve_value(rule.source, config)
        dst = self._resolve_value(rule.dest, config)

        ether_type = None

        if src:
            if src.startswith("@"):
                set_name = src[1:]
                fam = self._set_families.get(set_name, "ipv4")
                match["l3"]["src_set"] = set_name
                ether_type = "ip" if fam == "ipv4" else "ip6"
            elif is_ipv4(src.split("/")[0]):
                match["l3"]["src_ip"] = src
                ether_type = "ip"
            elif is_ipv6(src.split("/")[0]):
                match["l3"]["src_ip"] = src
                ether_type = "ip6"

        if dst:
            if dst.startswith("@"):
                set_name = dst[1:]
                fam = self._set_families.get(set_name, "ipv4")
                match["l3"]["dst_set"] = set_name
                if not ether_type:
                    ether_type = "ip" if fam == "ipv4" else "ip6"
            elif is_ipv4(dst.split("/")[0]):
                match["l3"]["dst_ip"] = dst
                if not ether_type:
                    ether_type = "ip"
            elif is_ipv6(dst.split("/")[0]):
                match["l3"]["dst_ip"] = dst
                if not ether_type:
                    ether_type = "ip6"

        if ether_type:
            match["l2"]["ether_type"] = ether_type

    def _resolve_value(self, value, config):
        """Resolve alias/ipset reference to IP or @setname."""
        if not value:
            return None

        typ, resolved = parser.resolve_source_dest(
            value, config.aliases, config.ipsets, config.vmid
        )

        if typ in ("ip", "alias"):
            return resolved
        elif typ == "ipset":
            set_name = f"vm{config.vmid}_{resolved}"
            if resolved in config.ipsets:
                members = config.ipsets[resolved]
                resolved_members = []
                for member in members:
                    if member.startswith("guest/") or member.startswith("+"):
                        ref = member.lstrip("+").replace("guest/", "").replace("dc/", "")
                        if ref in config.aliases:
                            resolved_members.append(config.aliases[ref])
                        elif ref in config.ipsets:
                            resolved_members.extend(config.ipsets[ref])
                    else:
                        resolved_members.append(member)
                if resolved_members:
                    has_v4 = any(is_ipv4(m.split("/")[0]) for m in resolved_members)
                    fam = "ipv4" if has_v4 else "ipv6"
                    self.sets[set_name] = ir.NamedSet(
                        name=set_name, family=fam, elements=resolved_members,
                    )
                    self._set_families[set_name] = fam
                    return f"@{set_name}"
            return None

        return value


# ═══════════════════════════════════════
# Match cleanup
# ═══════════════════════════════════════

def _clean_match(m):
    """Remove empty layer dicts from match."""
    return {k: v for k, v in m.items() if v}


# ═══════════════════════════════════════
# Module-level entry
# ═══════════════════════════════════════

def compile_ruleset():
    """Convenience function."""
    return Compiler().compile()
