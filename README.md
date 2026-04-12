# pvefw-neo

A drop-in nftables/OVS firewall manager for Proxmox VE that fixes the
limitations of the built-in PVE firewall: per-port rules, NOTRACK
(stateless) bypass for asymmetric routing, MAC/IP spoofing protection
per vNIC, port isolation, and OVS bridge support.

> 🌐 [繁體中文版](README.zh_TW.md)
> 🏗️ Architecture & internals: [DESIGN.md](DESIGN.md)

---

## Why?

PVE's built-in firewall has three fundamental issues:

1. **Forces conntrack on everything** — asymmetric routing (BGP, multipath)
   gets dropped as `invalid`. Even disabling firewall at port level doesn't
   fix it because the global `drop invalid` rule still applies.
2. **Five security rules are per-VM only** (DHCP / RA / IP spoofing /
   MAC spoofing / NDP). You can't say "net0 may not run a DHCP server but
   net1 may".
3. **No NOTRACK fast path** — even pure stateless ACLs (`src-ip`,
   `src-mac`) walk the conntrack table, wasting CPU and hash space.

pvefw-neo solves all three by reading the same `.fw` config files and
generating an independent nftables/OVS ruleset, giving you per-port
control, NOTRACK bypass, and a cleaner extension mechanism via
`@neo:` tags in rule comments.

It does **not** modify any PVE source code — it only reads
`/etc/pve/firewall/*.fw` and `/etc/pve/{qemu-server,lxc}/*.conf`.

---

## Status

| | |
|---|---|
| **Backends** | nftables (Linux bridge), OVS bridge |
| **Auto-reload** | inotify on .fw/.conf + 10s OVS port polling |
| **Tests** | 52/52 passing (36 nft, 4 OVS, 12 isolation) |
| **Dependencies** | `python3-nftables`, `python3-inotify`, optionally `openvswitch-switch` |

---

## Install

```bash
git clone https://github.com/PoemaIX/pvefw-neo.git /tmp/pvefw-neo
cd /tmp/pvefw-neo
bash install.sh
```

`install.sh` will:

1. `apt install python3-nftables python3-inotify`
2. `git clone https://github.com/PoemaIX/pvefw-neo.git /usr/local/lib/pvefw_neo`
3. Symlink launcher → `/usr/local/bin/pvefw-neo`
4. Symlink systemd unit → `/etc/systemd/system/pvefw-neo.service`
5. Run a quick verification

### Development install (symlink instead of clone)

```bash
DEV_LINK=/path/to/your/pvefw-neo bash install.sh
```

This symlinks `/usr/local/lib/pvefw_neo` to your working dir so edits
take effect immediately. Used for development.

### Stop conflicting services

`pvefw-neo` requires the built-in PVE firewall to be **disabled**:

```bash
systemctl disable --now pve-firewall.service proxmox-firewall.service
```

The daemon refuses to start if either is still running.

### Enable the daemon

```bash
systemctl enable --now pvefw-neo
journalctl -u pvefw-neo -f          # follow logs
```

The daemon will:
- Watch `/etc/pve/firewall/`, `/etc/pve/qemu-server/`, `/etc/pve/lxc/`
  for write events (2-second debounce)
- Poll OVS port topology every 10 seconds
- Auto-apply on changes

---

## Upgrade

```bash
bash /usr/local/lib/pvefw_neo/upgrade.sh
```

This runs `git pull` in the install dir and restarts the daemon.

---

## Uninstall

```bash
bash /usr/local/lib/pvefw_neo/uninstall.sh
```

This will:
1. Stop and disable the daemon
2. Flush all pvefw-neo nftables tables and OVS flows
3. Remove the symlinks
4. Remove `/usr/local/lib/pvefw_neo/`

`.fw` files in `/etc/pve/firewall/` are **not** touched. Re-enable
PVE's own firewall manually if you want it back.

---

## Usage

### CLI commands

```bash
pvefw-neo --apply             # Apply rules (auto-dispatch nft + OVS)
pvefw-neo --dry-run           # Print generated nftables ruleset
pvefw-neo --dump-ir           # Print intermediate representation (debug)
pvefw-neo --dump-ovs vmbr2    # Print OVS flows for a specific bridge
pvefw-neo --flush             # Remove all pvefw-neo state (nft + OVS)
pvefw-neo --preflight-check   # Check that PVE firewall is stopped
pvefw-neo --daemon            # Run daemon (used by systemd)
```

In normal operation you only need to enable the systemd service —
everything else is automatic.

### Edit firewall rules

Edit rules via the **PVE WebUI** (Datacenter → Firewall, or VM/CT →
Firewall) or directly via `/etc/pve/firewall/*.fw`. The daemon will
detect the change and re-apply within 2-3 seconds.

---

## Rule types

pvefw-neo supports both **regular PVE firewall rules** and **`@neo:`
extension tags**.

### 1. Regular PVE rules

Standard PVE syntax works as-is — pvefw-neo reads the same config format:

```ini
# /etc/pve/firewall/100.fw
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT

[ALIASES]
trusted_net 10.0.0.0/24

[IPSET allowed_clients]
10.0.1.5
10.0.1.6
10.0.1.0/24

[RULES]
|IN  SSH(ACCEPT)   -source trusted_net
|IN  HTTP(ACCEPT)
|IN  HTTPS(ACCEPT)
|IN  ACCEPT -source +allowed_clients -p tcp -dport 9090
|OUT ACCEPT
```

Supported features:
- All standard macros (SSH, HTTP, HTTPS, DNS, BGP, BitTorrent, …) —
  parsed at runtime from `/usr/share/perl5/PVE/Firewall.pm`
- `[ALIASES]` — referenced by name in `-source` / `-dest`
- `[IPSET name]` — referenced as `+name` or `+guest/name`
- `[GROUP name]` security groups — inlined where referenced
- `policy_in` / `policy_out` — translated to explicit catch-all rules
- `-i net0` per-vNIC scoping
- Protocol + port matching (`-p tcp -dport 80`, `-sport 1024:65535`,
  port lists `-dport 80,443`)

### 2. `@neo:` extension tags

These extend PVE rules via the **comment field** of the rule. They come
in two flavors:

#### Sugar tags — common patterns, one line each

Sugar tags expand into multiple low-level rules. They use a Finger dummy
rule (`-enable 0` so PVE itself ignores it) as a carrier:

```ini
[RULES]
# Anti-spoofing on net0:
|OUT Finger(DROP) -enable 0 -i net0 # @neo:macspoof
|OUT Finger(DROP) -enable 0 -i net0 # @neo:ipspoof 10.0.0.10/32
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nodhcp
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nora

# Port isolation:
|OUT Finger(DROP) -enable 0 -i net2 # @neo:isolated
```

| Sugar tag | Effect |
|-----------|--------|
| `@neo:macspoof [mac]` | Drop frames whose source MAC ≠ given MAC. If no MAC given, reads from VM config. |
| `@neo:ipspoof <ip,...>` | Allow only the listed source IPs. Auto-handles ARP, IPv4, IPv6 (DAD, link-local, whitelisted). |
| `@neo:nodhcp` | Drop UDP src-port 67/547 dst-port 68/546 (block VM acting as DHCP server). |
| `@neo:nora` | Drop IPv6 Router Advertisement. |
| `@neo:nondp` | Drop IPv6 Neighbor Solicit/Advert (block fake NDP). |
| `@neo:mcast_limit <pps>` | Rate-limit multicast frames at netdev ingress. |
| `@neo:isolated` | Set kernel bridge `isolated on` (Linux) or equivalent OF rule (OVS). Two isolated ports cannot communicate; isolated ↔ non-isolated still works. |

#### Primitive tags — append to a real rule for fine control

```ini
[RULES]
# NOTRACK ACL for asymmetric routing (no conntrack)
|OUT ACCEPT -i net1 -source 10.0.0.0/24 # @neo:notrack
|OUT ACCEPT -i net1 -source 169.254.0.0/16 # @neo:notrack
|OUT DROP   -i net1                       # @neo:notrack

# MAC + IP combined match (notrack)
|OUT ACCEPT -i net0 -source 10.0.0.10/32 # @neo:notrack @neo:mac aa:bb:cc:dd:ee:ff

# VLAN scoping
|OUT ACCEPT -i net0 -source 10.0.0.0/24 # @neo:notrack @neo:vlan 20
```

| Primitive | Effect |
|-----------|--------|
| `@neo:notrack` | Mark this rule as stateless. Goes into `bridge raw_prerouting` (nft) or table 10 (OVS). Bypasses conntrack entirely. Order matters — write more specific rules first, catch-all last. |
| `@neo:mac <src> [dst]` | Add MAC source/dest match to the rule. `*` means "any". Pair with `@neo:notrack`. |
| `@neo:vlan <vid|untagged|vid1,vid2>` | Add VLAN tag match. `untagged` = no 802.1Q header. |

### When to use STATELESS vs STATEFUL

| Use STATELESS (`@neo:notrack` / sugar tags) when... | Use STATEFUL (regular rules) when... |
|-----------|-----------|
| Anti-spoofing (`@neo:ipspoof`, `macspoof`) | Allowing inbound services where reply traffic should auto-pass |
| Asymmetric routing (BGP multipath) | Standard server firewall (allow SSH from X, deny rest) |
| ACLs that say "only these source IPs may send" | NAT-like patterns (PVE itself doesn't NAT, but stateful firewall allows return traffic) |
| Pure L2 / L3 filtering, no return-traffic concept | Anything that benefits from O(1) conntrack short-circuit |

**Don't mix incorrectly**: a `@neo:notrack DROP` catch-all on a port will
block inbound replies even for stateful services on that port. NOTRACK
runs before conntrack, so the stateful framework never gets to evaluate
return traffic that the stateless layer dropped.

---

## Backend dispatch

pvefw-neo automatically detects whether each VM port lives on a Linux
bridge or an OVS bridge, and applies rules with the right backend:

```
NetDev → detect_bridge() → bridge_type
                              ↓
                    ┌─────────┴─────────┐
                  linux               ovs
                    ↓                   ↓
                nftgen.render       ovsgen.apply
                    ↓                   ↓
                 nft -f            ovs-ofctl add-flows
```

A VM with `net0` on `vmbr1` (Linux) and `net1` on `vmbr2` (OVS) is fully
supported — each port goes to the appropriate backend.

---

## Limitations

| Limitation | Reason |
|------------|--------|
| `REJECT` becomes `DROP` | nftables bridge family doesn't support REJECT; OVS doesn't either. The peer just times out. |
| `bridge` family conntrack requires kernel ≥ 5.3 | nftables requirement. PVE 7+ is fine. |
| `Finger` macro is reserved as a sugar carrier | TCP/79 is unused in practice. |
| OVS isolation needs ≥2 isolated ports to take effect | Semantic A: "two isolated ports cannot communicate" — a single isolated port is meaningless. |
| `@neo:` tags depend on rule comments | PVE WebUI's comment field has a length limit. Split complex rules. |

---

## Troubleshooting

```bash
# Daemon status & logs
systemctl status pvefw-neo
journalctl -u pvefw-neo -f

# Inspect generated rules
pvefw-neo --dump-ir              # IR (backend-agnostic)
pvefw-neo --dry-run              # nftables text
pvefw-neo --dump-ovs vmbr2       # OVS flows for one bridge

# Inspect kernel state
nft list table bridge pvefw-neo
ovs-ofctl dump-flows vmbr2
ip -d link show veth100i0 | grep isolated

# Check what's actually running
nft list ruleset | grep pvefw-neo
ovs-ofctl dump-flows vmbr2 | grep "cookie=0x4e30"

# Reset everything (won't touch .fw files)
pvefw-neo --flush
systemctl restart pvefw-neo
```

---

## Project structure

```
pvefw-neo/
├── pvefw-neo                # launcher
├── pvefw-neo.service        # systemd unit
├── pvefw_neo_src/           # Python package
│   ├── ir.py                # Intermediate representation
│   ├── parser.py            # .fw / @neo: parser
│   ├── compiler.py          # parser → IR
│   ├── nftgen.py            # IR → nftables
│   ├── ovsgen.py            # IR → OVS flows
│   ├── bridge.py            # bridge isolation
│   ├── macros.py            # PVE macro parsing
│   ├── vmdevs.py            # VM device discovery
│   └── main.py              # CLI + daemon
├── tests/                   # Test suite (run from any PVE host)
├── install.sh / upgrade.sh / uninstall.sh
└── DESIGN.md                # Architecture & rationale
```

For internals, rule semantics, and design rationale see [DESIGN.md](DESIGN.md).

---

## License

(See repository for license details.)
