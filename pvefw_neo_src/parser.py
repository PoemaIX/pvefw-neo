"""Parse PVE .fw firewall config files and @neo: tags."""

import re
import os
from . import macros as macros_mod


class NeoTag:
    """Represents a parsed @neo: tag."""
    def __init__(self, name, args=None):
        self.name = name      # e.g. "ipspoof", "notrack", "mac", "vlan"
        self.args = args or []  # positional arguments

    def __repr__(self):
        if self.args:
            return f"@neo:{self.name} {' '.join(self.args)}"
        return f"@neo:{self.name}"


class FwRule:
    """Represents a parsed PVE firewall rule."""
    def __init__(self):
        self.direction = None   # "IN", "OUT", "FORWARD"
        self.action = None      # "ACCEPT", "DROP", "REJECT"
        self.macro = None       # e.g. "SSH", "HTTP"
        self.enable = True
        self.iface = None       # e.g. "net0"
        self.source = None      # IP/CIDR or alias ref
        self.dest = None
        self.proto = None
        self.sport = None
        self.dport = None
        self.icmp_type = None   # PVE -icmp-type / -icmpv6-type
        self.log = None
        self.comment = None
        self.neo_tags = []      # list of NeoTag
        self.is_group = False
        self.group_name = None
        self.line_num = 0

    def is_sugar(self):
        """Check if this is a sugar carrier rule (Finger macro + @neo: tag).

        Enable state is orthogonal: caller decides whether to expand or skip.
        An unchecked sugar rule (enable=False) means either the user manually
        disabled the extension, or pvefw-neo auto-disabled it via quarantine.
        """
        if not self.neo_tags:
            return False
        return self.macro == "Finger"

    @property
    def enabled_in_pve(self):
        """Mirror of self.enable, kept for clarity at call sites."""
        return self.enable

    def is_stateless(self):
        """Check if this rule is stateless (@neo:noct or @neo:stateless)."""
        return any(t.name in ("noct", "stateless") for t in self.neo_tags)

    def get_neo_tag(self, name):
        """Get a specific @neo: tag by name, or None."""
        for t in self.neo_tags:
            if t.name == name:
                return t
        return None


class FwOptions:
    """Parsed [OPTIONS] section."""
    def __init__(self):
        self.enable = False
        self.policy_in = "DROP"
        self.policy_out = "ACCEPT"
        self.dhcp = None
        self.macfilter = None
        self.ipfilter = None
        self.ndp = None
        self.radv = None
        self.log_level_in = None
        self.log_level_out = None


class FwConfig:
    """Complete parsed firewall config for a VM/CT."""
    def __init__(self, vmid):
        self.vmid = vmid
        self.options = FwOptions()
        self.aliases = {}       # name -> ip
        self.ipsets = {}        # name -> list of members
        self.rules = []         # list of FwRule
        self.security_groups = {}  # name -> list of FwRule (from cluster.fw)


class ClusterConfig:
    """Parsed cluster.fw config."""
    def __init__(self):
        self.options = FwOptions()
        self.aliases = {}
        self.ipsets = {}
        self.security_groups = {}  # group_name -> list of FwRule
        self.rules = []


def parse_neo_tags(comment):
    """Parse @neo: tags from a rule's comment string."""
    if not comment:
        return []

    tags = []
    for m in re.finditer(r'@neo:(\w+)(?:\s+([^@]*))?', comment):
        name = m.group(1)
        args_str = m.group(2)
        args = []
        if args_str:
            args = args_str.strip().split()
        tags.append(NeoTag(name, args))
    return tags


def parse_rule_line(line):
    """Parse a single PVE firewall rule line.

    Format:  DIRECTION ACTION [-options...] [# comment]   (enabled)
    or:     |DIRECTION ACTION [-options...] [# comment]   (disabled — PVE WebUI)
    or:      DIRECTION MACRO(ACTION) [-options...] [# comment]
    or:      GROUP group_name [-options...]

    PVE marks a rule as disabled by a **leading `|`** (see PVE Firewall.pm
    line 3171: `$rule->{enable} = $line =~ s/^\\|// ? 0 : 1`). We parse both
    states; downstream (compiler) decides what to do with disabled rules.
    Sugar carriers (Finger + @neo:) are normally enable=1 so the user sees
    the rule as active; when pvefw-neo quarantines a broken rule it writes
    back enable=0, which compiler treats as "skip this sugar".
    """
    line = line.strip()
    if not line:
        return None

    enabled = not line.startswith("|")

    # First token must look like a direction/GROUP or this isn't a rule line.
    probe = line.lstrip("|").split(None, 1)[0].upper() if line.lstrip("|") else ""
    if probe not in ("IN", "OUT", "FORWARD", "GROUP"):
        return None

    rule = FwRule()
    rule.enable = enabled

    # Split comment
    comment_part = None
    if " # " in line:
        line_part, _, comment_part = line.partition(" # ")
    elif line.endswith("#"):
        line_part = line[:-1]
    else:
        line_part = line
        # Also check for # without space before it at end
        m = re.search(r'\s#\s*(.*)', line_part)
        if m:
            comment_part = m.group(1)
            line_part = line_part[:m.start()]

    rule.comment = comment_part
    if comment_part:
        rule.neo_tags = parse_neo_tags(comment_part)

    # Tokenize
    parts = line_part.split()
    if len(parts) < 2:
        return None

    # Remove leading |
    parts[0] = parts[0].lstrip("|")
    direction = parts[0].upper()

    # GROUP reference
    if direction == "GROUP":
        rule.is_group = True
        rule.group_name = parts[1] if len(parts) > 1 else None
        rule.direction = "GROUP"
        _parse_options(rule, parts[2:])
        return rule

    if direction not in ("IN", "OUT", "FORWARD"):
        return None
    rule.direction = direction

    # Action or Macro(Action)
    action_str = parts[1]
    m = re.match(r'^(\w+)\((\w+)\)$', action_str)
    if m:
        rule.macro = m.group(1)
        rule.action = m.group(2).upper()
    else:
        rule.action = action_str.upper()

    # Parse -options
    _parse_options(rule, parts[2:])

    return rule


def _parse_options(rule, parts):
    """Parse -flag value pairs from rule parts."""
    i = 0
    while i < len(parts):
        p = parts[i]
        if p.startswith("#"):
            break
        if p in ("-i", "-iface") and i + 1 < len(parts):
            rule.iface = parts[i + 1]
            i += 2
        elif p in ("-source", "-src", "-s") and i + 1 < len(parts):
            rule.source = parts[i + 1]
            i += 2
        elif p in ("-dest", "-dst", "-d") and i + 1 < len(parts):
            rule.dest = parts[i + 1]
            i += 2
        elif p in ("-p", "-proto") and i + 1 < len(parts):
            rule.proto = parts[i + 1]
            i += 2
        elif p in ("-sport",) and i + 1 < len(parts):
            rule.sport = parts[i + 1]
            i += 2
        elif p in ("-dport",) and i + 1 < len(parts):
            rule.dport = parts[i + 1]
            i += 2
        elif p in ("-enable",) and i + 1 < len(parts):
            rule.enable = parts[i + 1] != "0"
            i += 2
        elif p in ("-icmp-type", "-icmpv6-type") and i + 1 < len(parts):
            rule.icmp_type = parts[i + 1]
            i += 2
        elif p in ("-log",) and i + 1 < len(parts):
            rule.log = parts[i + 1]
            i += 2
        else:
            i += 1


def parse_fw_file(path):
    """Parse a .fw file, return (options, aliases, ipsets, rules, security_groups)."""
    if not os.path.isfile(path):
        return FwOptions(), {}, {}, [], {}

    with open(path) as f:
        lines = f.readlines()

    options = FwOptions()
    aliases = {}
    ipsets = {}
    rules = []
    security_groups = {}

    current_section = None
    current_ipset_name = None
    current_group_name = None
    current_group_rules = []

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()

        # Skip empty lines and comments
        if not line or (line.startswith("#") and not line.startswith("#")):
            if not line:
                continue
            # Comments are allowed
            if line.startswith("#"):
                continue

        # Section headers
        m = re.match(r'^\[(\w+)(?:\s+(.*))?\]\s*(?:#.*)?$', line)
        if m:
            section_name = m.group(1).upper()
            section_arg = m.group(2)

            # Save previous group
            if current_group_name and current_group_rules:
                security_groups[current_group_name] = current_group_rules
                current_group_rules = []
                current_group_name = None

            if section_name == "OPTIONS":
                current_section = "OPTIONS"
            elif section_name == "ALIASES":
                current_section = "ALIASES"
            elif section_name == "IPSET":
                current_section = "IPSET"
                if section_arg:
                    current_ipset_name = section_arg.split("#")[0].strip()
                    ipsets[current_ipset_name] = []
            elif section_name == "RULES":
                current_section = "RULES"
            elif section_name == "GROUP":
                current_section = "GROUP"
                if section_arg:
                    current_group_name = section_arg.split("#")[0].strip()
                    current_group_rules = []
            continue

        if line.startswith("#"):
            continue

        if current_section == "OPTIONS":
            _parse_option_line(options, line)
        elif current_section == "ALIASES":
            _parse_alias_line(aliases, line)
        elif current_section == "IPSET" and current_ipset_name:
            member = line.split("#")[0].strip()
            if member:
                ipsets[current_ipset_name].append(member)
        elif current_section == "RULES":
            r = parse_rule_line(line)
            if r:
                r.line_num = line_num
                rules.append(r)
        elif current_section == "GROUP" and current_group_name is not None:
            r = parse_rule_line(line)
            if r:
                r.line_num = line_num
                current_group_rules.append(r)

    # Save last group
    if current_group_name and current_group_rules:
        security_groups[current_group_name] = current_group_rules

    return options, aliases, ipsets, rules, security_groups


def _parse_option_line(options, line):
    """Parse an OPTIONS section line."""
    m = re.match(r'^(\w+)\s*[:=]\s*(.+)$', line)
    if not m:
        return

    key = m.group(1).lower()
    val = m.group(2).strip()

    if key == "enable":
        options.enable = val == "1"
    elif key == "policy_in":
        options.policy_in = val.upper()
    elif key == "policy_out":
        options.policy_out = val.upper()
    elif key == "dhcp":
        options.dhcp = val == "1"
    elif key == "macfilter":
        options.macfilter = val == "1"
    elif key == "ipfilter":
        options.ipfilter = val == "1"
    elif key == "ndp":
        options.ndp = val == "1"
    elif key == "radv":
        options.radv = val == "1"
    elif key == "log_level_in":
        options.log_level_in = val
    elif key == "log_level_out":
        options.log_level_out = val


def _parse_alias_line(aliases, line):
    """Parse an ALIASES section line: name IP [# comment]"""
    line = line.split("#")[0].strip()
    parts = line.split(None, 1)
    if len(parts) >= 2:
        # Handle both "name IP" and "name = IP"
        name = parts[0]
        value = parts[1].lstrip("= ").strip()
        aliases[name] = value


def parse_cluster_fw():
    """Parse /etc/pve/firewall/cluster.fw."""
    config = ClusterConfig()
    path = "/etc/pve/firewall/cluster.fw"
    opts, aliases, ipsets, rules, groups = parse_fw_file(path)
    config.options = opts
    config.aliases = aliases
    config.ipsets = ipsets
    config.rules = rules
    config.security_groups = groups
    return config


def parse_vm_fw(vmid):
    """Parse /etc/pve/firewall/<vmid>.fw and merge cluster config."""
    cluster = parse_cluster_fw()

    path = f"/etc/pve/firewall/{vmid}.fw"
    opts, aliases, ipsets, rules, groups = parse_fw_file(path)

    config = FwConfig(vmid)
    config.options = opts
    config.rules = rules

    # Merge: VM aliases override cluster aliases
    config.aliases = dict(cluster.aliases)
    config.aliases.update(aliases)

    # Merge ipsets: VM ipsets override cluster ipsets
    config.ipsets = dict(cluster.ipsets)
    config.ipsets.update(ipsets)

    # Security groups come from cluster.fw
    config.security_groups = dict(cluster.security_groups)
    config.security_groups.update(groups)

    return config


def resolve_alias(name, aliases):
    """Resolve an alias name to an IP address."""
    if name in aliases:
        return aliases[name]
    return None


def resolve_source_dest(value, aliases, ipsets, vmid=None):
    """Resolve a -source or -dest value.

    PVE namespace conventions (mirrors official Rust impl
    `proxmox-firewall/src/config.rs::alias`/`ipset`):

      +<scope>/<name>   ipset ref  (scope: guest, dc, sdn)
      +<name>           legacy ipset ref (vm-local, then cluster)
      <scope>/<name>    alias ref  (scope: guest, dc)
      <name>            legacy alias ref (vm-local, then cluster)
      <ip>[/<cidr>]     literal address

    Returns (type, resolved_value) where type is:
      "ip"    - literal IP/CIDR
      "ipset" - set name (caller materializes)
      "alias" - alias resolved to IP/CIDR
      None    - could not resolve
    """
    if not value:
        return None, None

    # ── ipset reference: must start with `+` ──
    if value.startswith("+"):
        m = re.match(r'^\+(?:(?:guest|dc|sdn)/)?(\w+)$', value)
        if m:
            set_name = m.group(1)
            if set_name in ipsets:
                return "ipset", set_name
        return None, None

    # ── scoped alias: dc/<name> or guest/<name> ──
    m = re.match(r'^(?:guest|dc)/(\w+)$', value)
    if m:
        ref = m.group(1)
        resolved = resolve_alias(ref, aliases)
        if resolved:
            return "alias", resolved
        return None, None

    # ── legacy bare alias (identifier-shaped, not an IP) ──
    if re.match(r'^[a-zA-Z]', value) and "/" not in value and "." not in value and ":" not in value:
        resolved = resolve_alias(value, aliases)
        if resolved:
            return "alias", resolved
        return None, None

    # ── literal IP/CIDR ──
    return "ip", value
