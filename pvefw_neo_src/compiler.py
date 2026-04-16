"""
Compiler: parser output → IR Ruleset (new per-NetDev structure)

Expands sugar tags, resolves aliases/ipsets/macros/security groups,
produces a backend-agnostic IR Ruleset organized per NetDev.
"""

import copy
import ipaddress
import re
import sys

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


# PVE/Firewall.pm valid log levels (excluding "nolog" which means "no log rule").
# Mirrors official `LogLevel::try_from` in proxmox-firewall.
_PVE_LOG_LEVELS = {"emerg", "alert", "crit", "err", "warning", "notice",
                    "info", "debug"}


def _normalize_log_level(value):
    """Return a valid log level string or None.

    PVE accepts "nolog" (= disabled) and the 8 syslog levels above.
    Anything else is silently treated as no logging (matches official
    behavior — invalid level → LogLevel::try_from fails → no log rule).
    """
    if not value:
        return None
    v = value.strip().lower()
    if v in _PVE_LOG_LEVELS:
        return v
    return None


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
                        file=sys.stderr,
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
                if not rule.enable:
                    continue
                self._expand_group(vmid, config, nets, is_ct, rule)
            elif rule.is_sugar():
                # Sugar carriers are *intentionally* disabled in PVE (no leading `|`)
                # so PVE itself ignores them; we expand them here.
                self._expand_sugar(vmid, config, nets, is_ct, rule)
            elif not rule.enable:
                # Disabled rule with no @neo: meaning — honor PVE's intent and skip.
                continue
            elif rule.is_stateless():
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
                "ctinvalid":   self._sugar_ctinvalid,
                "disable":     self._sugar_disable,
            }.get(tag.name)
            if handler:
                handler(vmid, config, nets, is_ct, rule, tag)

    def _sugar_macspoof(self, vmid, config, nets, is_ct, rule, tag):
        """@neo:macspoof [mac1,mac2,...] → STATELESS rule: drop if src MAC
        not in the whitelist. Empty args = auto-read from VM config."""
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            if tag.args:
                macs = [m.strip().upper() for m in tag.args[0].split(",")
                        if m.strip()]
            else:
                auto = nets.get(iface, {}).get("mac")
                macs = [auto.upper()] if auto else []
            if not macs:
                continue
            neg = macs[0] if len(macs) == 1 else macs
            self._add_rule(devname, ir.Rule(
                direction=ir.Direction.OUT,
                phase=ir.Phase.STATELESS,
                match={"l2": {"src_mac_neg": neg}},
                action="drop",
                comment=f"@neo:macspoof {','.join(macs)}",
            ))

    def _sugar_ipspoof(self, vmid, config, nets, is_ct, rule, tag):
        """@neo:ipspoof → 3 conditional-drop rules per port (ARP / v4 / v6)
        each referencing a pure-nomatch NamedSet carrying the allow-list.

        The emitted IR shape is identical to what a user would get by
        hand-writing:

            [IPSET ipspoof_vm<id>_<iface>_v4]
              !10.0.0.10
            [IPSET ipspoof_vm<id>_<iface>_v6]
              !fe80::/10
              !::0
              !2001:db8::1
            [RULES]
              |OUT DROP -p arp -source +ipspoof_..._v4  # @neo:notrack (ARP)
              |OUT DROP -p ip  -source +ipspoof_..._v4  # @neo:notrack (IPv4)
              |OUT DROP -p ip6 -source +ipspoof_..._v6  # @neo:notrack (IPv6)

        IP list comes from either `rule.source` (preferred; put IPs in the
        WebUI Source field) or legacy tag args (`# @neo:ipspoof a,b,c`).
        Sugar disappears in IR — only sets + rules referencing them remain.
        """
        if tag.args:
            raw = tag.args[0]
        elif rule.source:
            raw = rule.source
        else:
            return
        ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
        v4 = [ip for ip in ips if is_ipv4(ip.split("/")[0])]
        v6 = [ip for ip in ips if is_ipv6(ip.split("/")[0])]

        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            if not v4 and not v6:
                continue

            base = f"ipspoof_vm{vmid}_{iface}"
            set_v4 = f"{base}_v4"
            set_v6 = f"{base}_v6"

            # ── v4 pure-nomatch set (ARP + IPv4 share it) ──
            if v4:
                self.sets[set_v4] = ir.NamedSet(
                    name=set_v4, family="ipv4",
                    elements=[], excludes=list(v4),
                )
                self._set_families[set_v4] = "ipv4"

                # ARP rule: drop when ARP sender IP not in allow list.
                # nftgen picks `arp saddr ip` as the match field because
                # ether_type=arp (see _render_match set-ref handling).
                self._add_rule(devname, ir.Rule(
                    direction=ir.Direction.OUT,
                    phase=ir.Phase.STATELESS,
                    match={"l2": {"ether_type": "arp",
                                  "arp_op": ["request", "reply"]},
                           "l3": {"src_set": set_v4}},
                    action="drop",
                    comment=f"@neo:ipspoof ARP (allow {','.join(v4)})",
                ))
                # IPv4 rule: drop when src_ip not in allow list.
                self._add_rule(devname, ir.Rule(
                    direction=ir.Direction.OUT,
                    phase=ir.Phase.STATELESS,
                    match={"l2": {"ether_type": "ip"},
                           "l3": {"src_set": set_v4}},
                    action="drop",
                    comment=f"@neo:ipspoof IPv4 (allow {','.join(v4)})",
                ))

            # ── v6 pure-nomatch set ──
            # Always include link-local (fe80::/10) and DAD (::) so the
            # VM can do Neighbor Discovery even if the user only listed
            # v4 addresses.
            v6_allow = list(v6) + ["fe80::/10", "::"]
            self.sets[set_v6] = ir.NamedSet(
                name=set_v6, family="ipv6",
                elements=[], excludes=v6_allow,
            )
            self._set_families[set_v6] = "ipv6"
            self._add_rule(devname, ir.Rule(
                direction=ir.Direction.OUT,
                phase=ir.Phase.STATELESS,
                match={"l2": {"ether_type": "ip6"},
                       "l3": {"src_set": set_v6}},
                action="drop",
                comment=f"@neo:ipspoof IPv6 (allow {','.join(v6_allow)})",
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

    def _sugar_ctinvalid(self, vmid, config, nets, is_ct, rule, tag):
        """@neo:ctinvalid → expands to IN DROP + OUT DROP with ct_state=invalid."""
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            for direction in (ir.Direction.IN, ir.Direction.OUT):
                self._add_rule(devname, ir.Rule(
                    direction=direction,
                    phase=ir.Phase.STATEFUL,
                    match={"l3": {"ct_state": "invalid"}},
                    action="drop",
                    comment="@neo:ctinvalid",
                ))

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
        for iface, devname in self._get_iface_devnames(vmid, rule, nets, is_ct):
            ir_rules = self._build_notrack_rules(vmid, config, devname, rule)
            for r in ir_rules:
                self._add_rule(devname, r)

    def _apply_l2_primitives(self, match, rule):
        """Apply @neo:srcmac / @neo:dstmac / @neo:vlan decorators onto an L2
        match dict.

        Shared by notrack and stateful paths so a rule like
        `|IN ACCEPT -p tcp -dport 22 # @neo:srcmac exact 02:00:00:AA:03:00`
        works uniformly — decorator conditions are AND'd with the rule's
        natural L3/L4 match.

        Syntax:
          @neo:srcmac exact <mac>        ether saddr == mac
          @neo:srcmac bitmask <mac>      ether saddr & mac == mac
          @neo:dstmac exact <mac>        ether daddr == mac
          @neo:dstmac bitmask <mac>      ether daddr & mac == mac
        A bare `@neo:srcmac <mac>` (no mode) defaults to `exact`.
        """
        for tag_name, exact_key, mask_key in (
            ("srcmac", "src_mac", "src_mac_mask"),
            ("dstmac", "dst_mac", "dst_mac_mask"),
        ):
            tag = rule.get_neo_tag(tag_name)
            if not tag or not tag.args:
                continue
            if len(tag.args) >= 2 and tag.args[0].lower() in ("exact", "bitmask"):
                mode = tag.args[0].lower()
                mac = tag.args[1]
            else:
                mode = "exact"
                mac = tag.args[0]
            mac = mac.upper()
            if mode == "bitmask":
                match["l2"][mask_key] = (mac, mac)
            else:
                match["l2"][exact_key] = mac

        vlan_tag = rule.get_neo_tag("vlan")
        if vlan_tag and vlan_tag.args:
            vlan_str = vlan_tag.args[0]
            if vlan_str == "untagged":
                match["l2"]["ether_type_neg"] = "vlan"
            else:
                match["l2"]["vlan_id"] = [int(v) for v in vlan_str.split(",")]

    @staticmethod
    def _rate_pps_from_rule(rule):
        """Return int pps from @neo:rateexceed tag, or None."""
        tag = rule.get_neo_tag("rateexceed")
        if tag and tag.args:
            try:
                return int(tag.args[0])
            except ValueError:
                return None
        return None

    @staticmethod
    def _apply_ct_decorator(match, rule, *, default_state=None):
        """Apply @neo:ct <state> decorator to match dict.

        Supported states: `new`, `invalid`. `established`/`related` are
        always globally accepted by the framework before per-port rules
        evaluate — a per-port rule would never fire for those states.

        Bare `@neo:ct` (no args) = match all reachable states (new+invalid).
        No ct_state key is set in the match — equivalent to no filter.

        Stateful rules without explicit `@neo:ct` are semantically equivalent
        to bare `@neo:ct` (match all). The compiler does NOT inject a default
        ct_state to keep IR honest about what the rule actually matches.
        """
        ct_tag = rule.get_neo_tag("ct")
        if ct_tag and ct_tag.args:
            state = ct_tag.args[0].lower()
            if state in ("new", "invalid"):
                match.setdefault("l3", {})["ct_state"] = state
        elif default_state:
            match.setdefault("l3", {})["ct_state"] = default_state

    def _build_notrack_rules(self, vmid, config, devname, rule):
        """Build IR rules for a @neo:notrack rule."""
        base_match = {"l2": {}, "l3": {}, "l4": {}}

        self._apply_l2_primitives(base_match, rule)
        self._apply_ct_decorator(base_match, rule, default_state=None)

        # Source/dest (sets ether_type)
        self._apply_src_dst(base_match, rule, config)

        # Protocol + ports
        if rule.proto:
            base_match["l3"]["proto"] = rule.proto.lower()
        if rule.sport:
            base_match["l4"]["src_port"] = normalize_port(rule.sport)
        if rule.dport:
            base_match["l4"]["dst_port"] = normalize_port(rule.dport)
        if rule.icmp_type:
            self._apply_icmp_type(base_match, rule.icmp_type)

        action = "drop" if rule.action in ("DROP", "REJECT") else "accept"
        direction = self._pve_dir(rule.direction)
        log_level = _normalize_log_level(rule.log)
        rate_pps = self._rate_pps_from_rule(rule)

        # Macro expansion
        if rule.macro and rule.macro != "Finger":
            results = self._expand_macro_rules(base_match, rule, action,
                                               direction, ir.Phase.STATELESS,
                                               log_level=log_level)
        else:
            results = self._materialize_family_variants(
                base_match, direction, ir.Phase.STATELESS, action,
                log_level, rule.comment or "",
            )

        if rate_pps is not None:
            for r in results:
                r.rate_limit_pps = rate_pps
        return results

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
        log_level = _normalize_log_level(rule.log)

        if rule.get_neo_tag("rateexceed"):
            print(
                f"WARNING: vm{vmid} line {rule.line_num}: @neo:rateexceed "
                f"is only supported on @neo:notrack rules; decorator ignored.",
                file=sys.stderr,
                flush=True,
            )

        if rule.macro:
            macro_entries = self.macros.get(rule.macro, [])
            if not macro_entries:
                return []
            base_match = {"l2": {}, "l3": {}, "l4": {}}
            self._apply_l2_primitives(base_match, rule)
            self._apply_ct_decorator(base_match, rule)
            self._apply_src_dst(base_match, rule, config)
            return self._expand_macro_rules(base_match, rule, action,
                                           direction, ir.Phase.STATEFUL,
                                           log_level=log_level)

        # No macro: build single rule
        match = {"l2": {}, "l3": {}, "l4": {}}
        self._apply_l2_primitives(match, rule)
        self._apply_ct_decorator(match, rule)
        self._apply_src_dst(match, rule, config)
        if rule.proto:
            match["l3"]["proto"] = rule.proto.lower()
        if rule.sport:
            match["l4"]["src_port"] = normalize_port(rule.sport)
        if rule.dport:
            match["l4"]["dst_port"] = normalize_port(rule.dport)
        if rule.icmp_type:
            self._apply_icmp_type(match, rule.icmp_type)

        return self._materialize_family_variants(match, direction,
                                                 ir.Phase.STATEFUL, action,
                                                 log_level, rule.comment or "")

    def _expand_macro_rules(self, base_match, rule, action, direction, phase,
                             log_level=None):
        """Expand a PVE macro into multiple IR rules, merging with base match.

        For each macro entry we run the same per-family materialization as
        plain rules, so a macro applied to a mixed-family ipset is correctly
        cloned per family.
        """
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
            if rule.icmp_type:
                self._apply_icmp_type(m, rule.icmp_type)
            results.extend(self._materialize_family_variants(
                m, direction, phase, action, log_level, rule.comment or "",
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
                continue
            if not grule.enable:
                continue
            if grule.is_stateless():
                self._expand_notrack(vmid, config, nets, is_ct, grule)
            else:
                self._expand_stateful(vmid, config, nets, is_ct, grule)

    # ═══════════════════════════════════════
    # Source/dest resolution
    # ═══════════════════════════════════════

    def _apply_src_dst(self, match, rule, config):
        """Resolve source/dest into match dict.

        For literal IPs / aliases (always single-family) writes ether_type
        immediately. For ipset refs that contain both v4 and v6 members,
        leaves a `__src_set_pf__` / `__dst_set_pf__` magic key holding a
        {family: set_name} dict; `_materialize_family_variants` splits the
        rule into per-family copies later (mirrors official Rust impl
        which clones rules per family in handle_set/handle_match).
        """
        src = self._resolve_value(rule.source, config)
        dst = self._resolve_value(rule.dest, config)

        ether_type = None

        for value, set_key, ip_key, alt_key in (
            (src, "src_set", "src_ip", "__src_set_pf__"),
            (dst, "dst_set", "dst_ip", "__dst_set_pf__"),
        ):
            if not value:
                continue
            if isinstance(value, dict):
                # Per-family ipset (mixed v4/v6) — defer to family split.
                match["l3"][alt_key] = value
                continue
            if value.startswith("@"):
                set_name = value[1:]
                fam = self._set_families.get(set_name, "ipv4")
                match["l3"][set_key] = set_name
                et = "ip" if fam == "ipv4" else "ip6"
            elif is_ipv4(value.split("/")[0]):
                match["l3"][ip_key] = value
                et = "ip"
            elif is_ipv6(value.split("/")[0]):
                match["l3"][ip_key] = value
                et = "ip6"
            else:
                continue
            if ether_type is None:
                ether_type = et
            elif ether_type != et:
                # Mixed src(v4) + dst(v6) — official drops such rules.
                # We mark the match as poisoned via a sentinel.
                match["__poison__"] = True

        if ether_type and "ether_type" not in match["l2"]:
            match["l2"]["ether_type"] = ether_type

    def _resolve_value(self, value, config):
        """Resolve alias/ipset reference.

        Returns:
          None              — unresolvable
          str (IP/CIDR)     — literal address
          str ("@<name>")   — single-family ipset (already materialized)
          dict {fam: name}  — multi-family ipset (per-family materialized)
        """
        if not value:
            return None

        typ, resolved = parser.resolve_source_dest(
            value, config.aliases, config.ipsets, config.vmid
        )

        if typ in ("ip", "alias"):
            return resolved

        if typ == "ipset":
            if resolved not in config.ipsets:
                return None
            per_fam = self._materialize_ipset_by_family(
                config.ipsets[resolved], config
            )
            # Drop empty families
            per_fam = {f: pn for f, pn in per_fam.items() if pn[0] or pn[1]}
            if not per_fam:
                return None

            base = f"vm{config.vmid}_{resolved}"
            family_set_names = {}
            for fam, (positives, excludes) in per_fam.items():
                # v4 keeps the bare name (back-compat with existing tests);
                # v6 gets a `_v6` suffix. Mirrors official `v4-`/`v6-` split
                # in spirit but stays within our existing naming scheme.
                sname = base if fam == "ipv4" else f"{base}_v6"
                self.sets[sname] = ir.NamedSet(
                    name=sname,
                    family=fam,
                    elements=positives,
                    excludes=excludes,
                )
                self._set_families[sname] = fam
                family_set_names[fam] = f"@{sname}"

            if len(family_set_names) == 1:
                return next(iter(family_set_names.values()))
            return family_set_names  # mixed-family

        return value

    def _materialize_ipset(self, members, config, _seen=None):
        """Family-blind variant — kept for callers that don't care.

        Returns (positives, excludes) flattened across both families.
        """
        per_fam = self._materialize_ipset_by_family(members, config, _seen)
        positives, excludes = [], []
        for pos, neg in per_fam.values():
            positives.extend(pos)
            excludes.extend(neg)
        return positives, excludes

    def _materialize_ipset_by_family(self, members, config, _seen=None):
        """Resolve PVE ipset members and partition by IP family.

        Member syntax (mirror of `proxmox-ve-config` ipset parser):
          IP / CIDR                       literal positive
          !IP / !CIDR                     literal negative
          dc/<alias> / guest/<alias>      scoped alias  → resolve
          !dc/<alias> / !guest/<alias>    scoped alias, negated
          +dc/<set> / +guest/<set>        nested ipset (rare; flatten)
          !+dc/<set>                      negated nested set (polarity flip)

        Returns dict {family: (positives, excludes)} for any non-empty
        family. Unresolved refs are silently dropped (PVE does the same).
        """
        _seen = _seen or set()
        buckets = {"ipv4": ([], []), "ipv6": ([], [])}

        def _bucket_for(addr):
            ip = addr.split("/")[0]
            if is_ipv4(ip):
                return buckets["ipv4"]
            if is_ipv6(ip):
                return buckets["ipv6"]
            return None

        for raw in members:
            negated = raw.startswith("!")
            bare = raw.lstrip("!").strip()

            # ── Nested ipset reference ──
            if bare.startswith("+"):
                ref = bare.lstrip("+").split("/", 1)[-1]
                if ref in _seen or ref not in config.ipsets:
                    continue
                sub = self._materialize_ipset_by_family(
                    config.ipsets[ref], config, _seen | {ref}
                )
                for fam, (sub_pos, sub_neg) in sub.items():
                    pos, neg = buckets[fam]
                    if negated:
                        neg.extend(sub_pos)
                        pos.extend(sub_neg)
                    else:
                        pos.extend(sub_pos)
                        neg.extend(sub_neg)
                continue

            # ── Scoped alias ──
            if bare.startswith(("dc/", "guest/")):
                ref = bare.split("/", 1)[1]
                addr = config.aliases.get(ref)
                if not addr:
                    continue  # silently drop
                bucket = _bucket_for(addr)
                if bucket is None:
                    continue
                (bucket[1] if negated else bucket[0]).append(addr)
                continue

            # ── Literal IP / CIDR ──
            bucket = _bucket_for(bare)
            if bucket is None:
                continue
            (bucket[1] if negated else bucket[0]).append(bare)

        return buckets

    def _materialize_family_variants(self, match, direction, phase, action,
                                      log_level, comment):
        """Turn a match dict (possibly carrying multi-family ipset refs) into
        one or more IR rules. Mirrors official Rust per-family rule cloning."""
        if match.pop("__poison__", False):
            # Source / dest in incompatible families — official drops these.
            return []

        src_pf = match["l3"].pop("__src_set_pf__", None)
        dst_pf = match["l3"].pop("__dst_set_pf__", None)

        if not src_pf and not dst_pf:
            cleaned = _clean_match(match)
            return [ir.Rule(
                direction=direction, phase=phase, match=cleaned,
                action=action, log_level=log_level, comment=comment,
            )]

        # Determine which families to emit. If both sides are per-family,
        # emit only families they share. Otherwise emit each family present
        # on the side that has it, picking the literal/single-family side for
        # the other.
        src_fams = set(src_pf.keys()) if src_pf else None
        dst_fams = set(dst_pf.keys()) if dst_pf else None
        if src_fams and dst_fams:
            fams = src_fams & dst_fams
        else:
            fams = src_fams or dst_fams

        rules = []
        for fam in sorted(fams):
            m = copy.deepcopy(match)
            m["l2"]["ether_type"] = "ip" if fam == "ipv4" else "ip6"
            if src_pf:
                m["l3"]["src_set"] = src_pf[fam].lstrip("@")
            if dst_pf:
                m["l3"]["dst_set"] = dst_pf[fam].lstrip("@")
            rules.append(ir.Rule(
                direction=direction, phase=phase, match=_clean_match(m),
                action=action, log_level=log_level, comment=comment,
            ))
        return rules

    def _apply_icmp_type(self, match, type_str):
        """Wire `-icmp-type X` / `-icmpv6-type X` into the IR match.

        Accepts comma-separated list. Family is inferred from current
        ether_type if already set, else from proto. Default v4.
        """
        types = [t.strip() for t in type_str.split(",") if t.strip()]
        if not types:
            return
        et = match["l2"].get("ether_type")
        proto = match["l3"].get("proto", "").lower()
        if et == "ip6" or proto == "icmpv6":
            match["l3"]["icmpv6_type"] = types
        else:
            match["l3"]["icmp_type"] = types


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
