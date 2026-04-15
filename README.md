# pvefw-neo

A drop-in nftables/OVS firewall manager for Proxmox VE. Per-port
macspoof/ipspoof, NOTRACK bypass for asymmetric routing, OVS bridge
support, multi-backend (native nftables for Linux bridge, OpenFlow for
OVS), reuses the existing PVE `.fw` config files.

> 🌐 [繁體中文版](README.zh_TW.md)
> 🏗️ Architecture & internals: [DESIGN.md](DESIGN.md)

---

## Requirements

Regardless of whether PVE's native firewall is enabled, **nftables mode
(tech preview) must be turned on** on the host:

PVE WebUI → **Host → Firewall → Options → nftables (tech preview) → yes**

pvefw-neo runs alongside the native firewall without modifying PVE
source. See [DESIGN.md](DESIGN.md) for the coexistence model
(node-off + nftables mode) and why the port-level `firewall=` flag
must be unset or `0`.

---

## Installation

```bash
curl -sSL https://raw.githubusercontent.com/PoemaIX/pvefw-neo/refs/heads/main/install.sh | bash
```

`install.sh` is interactive: it installs dependencies, symlinks the
package, offers to set `host.fw` to `enable=0, nftables=1`, and offers
to bulk-flip any existing `firewall=1` vNICs to `firewall=0`. Then
enable the daemon:

```bash
systemctl enable --now pvefw-neo
```

Upgrade / uninstall:

```bash
bash /usr/local/lib/pvefw_neo/upgrade.sh
bash /usr/local/lib/pvefw_neo/uninstall.sh
```

---

## Usage

Edit firewall rules via **PVE WebUI** (VM → Firewall) or directly in
`/etc/pve/firewall/*.fw`. The daemon detects changes and re-applies
within a few seconds.

Standard PVE rules work as-is — all macros, `[ALIASES]`, `[IPSET]`,
`[GROUP]`, `policy_in/out`, per-vNIC `-i netN`, protocol/port matching,
`-icmp-type`, `-log <level>`.

On top of that, pvefw-neo adds two classes of rule extensions, both
expressed via the **comment field** of a PVE rule and all prefixed
`@neo:`.

### Class 1 — Extension rules (`@neo:` sugar)

These add capabilities PVE's WebUI can't express. Because they don't
match any real protocol, we borrow the long-obsolete **Finger** macro
(TCP/79, which nothing uses anymore) as the carrier, mark the carrier
as **disabled** in PVE (so PVE itself ignores it), and put the real
meaning in the comment.

**WebUI recipe** (`VM → Firewall → Add`):

| Field | Value |
|---|---|
| Direction | `out` |
| Enable | **unchecked** ← important |
| Action | `DROP` |
| Macro | `Finger` |
| Source | (IP-type args, if applicable) |
| Comment | `@neo:<name> [args]` |

> PVE marks a rule disabled by prepending `|` to the line. That's
> exactly what we want: PVE skips it, pvefw-neo picks it up.

| Tag | Effect |
|---|---|
| `@neo:disable` | **Debug switch.** Turn off pvefw-neo management for this port entirely — all other rules on this port are ignored and traffic passes through. Equivalent to "port-level firewall disable" in PVE's model (and the reason we can't use the PVE GUI flag: that flag would also turn off the checkbox that gates fwbr creation). |
| `@neo:isolated` | Linux bridge `isolated on` / the equivalent OF rule on OVS. Two isolated ports on the same bridge can't talk to each other; isolated ↔ non-isolated still works. |
| `@neo:macspoof [mac,...]` | Drop frames whose source MAC isn't in the list. Empty list = auto-read from VM config. |
| `@neo:ipspoof <ip,...>` | Allow only the listed source IPs. Auto-handles ARP, IPv4, IPv6 (DAD, link-local, whitelist). |
| `@neo:nodhcp` | Block the VM from acting as a DHCP server (drop UDP sport 67/547 → dport 68/546). |
| `@neo:nora` | Drop outbound IPv6 Router Advertisement. |
| `@neo:nondp` | Drop outbound IPv6 NS/NA (block spoofed NDP). |
| `@neo:mcast_limit <pps>` | Rate-limit multicast frames at netdev ingress. |

**Examples:**

```ini
[RULES]
# ipspoof — allow only specific source IPs through
|OUT Finger(DROP) # @neo:ipspoof 192.168.5.6,192.168.5.7,192.168.20.0/24

# macspoof — allow only specific source MACs through
|OUT Finger(DROP) # @neo:macspoof 22:44:66:88:aa:bb,22:44:66:88:aa:cc

# macspoof — no arg: read MAC from VM config
|OUT Finger(DROP) # @neo:macspoof

# nodhcp — block this VM from running a DHCP server
|OUT Finger(DROP) # @neo:nodhcp
```

### Class 2 — Decorator tags

Decorators extend **real** (non-Finger) PVE rules. They either change
rule behavior or add extra match conditions.

#### Behavior-changing

| Tag | Effect |
|---|---|
| `@neo:notrack` | Evaluate this rule stateless. Lives in `bridge raw_prerouting` (nft) or table 10 (OVS), bypasses conntrack entirely. Order matters — more specific first, catch-all last. |

#### Extra-match (narrows the rule's scope)

| Tag | Effect |
|---|---|
| `@neo:srcmac exact <mac>` | Only match packets whose source MAC equals `<mac>`. Useful when one VM has multiple MACs and you want per-MAC rules. |
| `@neo:srcmac bitmask <mac>` | Match source MAC by bitmask (`field & mac == mac`). |
| `@neo:dstmac exact <mac>` | Only match packets whose destination MAC equals `<mac>`. |
| `@neo:dstmac bitmask <mac>` | Match destination MAC by bitmask. |
| `@neo:vlan <vid\|untagged\|vid1,vid2>` | Only match traffic on the given VLAN(s). Used when a trunk port is handed to the VM and you want a rule scoped to one inner VLAN. |
| `@neo:rateexceed <pps>` | Only match the portion of traffic that **exceeds** `<pps>`. Packets within the rate budget fall through to the next rule. **`@neo:notrack` only** — not supported on stateful rules. |

**Examples:**

```ini
[RULES]
# Stateless per-MAC allow + catch-all drop
|OUT ACCEPT -i net0 -source 10.0.0.10/32 # @neo:notrack @neo:srcmac exact aa:bb:cc:dd:ee:ff
|OUT DROP                                # @neo:notrack

# VLAN-scoped stateless rule (trunk port, inner VLAN 20 only)
|OUT ACCEPT -i net0 -source 10.0.0.0/24 # @neo:notrack @neo:vlan 20

# Rate-limit multicast at 100 pps (drop the excess)
|OUT Finger(DROP) -i net0 # @neo:mcast_limit 100
```

### Why sugar = decorators

`macspoof`, `ipspoof`, `nodhcp`, `nora`, `nondp`, `mcast_limit` are all
**sugar** over decorator rules. Conceptually each sugar tag expands
into one or more decorator-based rules at compile time:

```
# @neo:macspoof mac1,mac2   expands to:
OUT @neo:notrack @neo:srcmac exact mac1 allow
OUT @neo:notrack @neo:srcmac exact mac2 allow
OUT @neo:notrack                        drop

# @neo:ipspoof ip1,cidr2    expands to:
OUT ACCEPT -source ip1/32  # @neo:notrack
OUT ACCEPT -source cidr2   # @neo:notrack
OUT DROP                   # @neo:notrack

# @neo:mcast_limit 100      expands to (roughly):
OUT DROP # @neo:notrack @neo:rateexceed 100 @neo:dstmac bitmask 01:00:00:00:00:00
```

So the compile pipeline is:

1. Sugar expansion (after this, only `@neo:disable` / `@neo:isolated`
   remain as extension rules; everything else is a normal rule +
   decorators).
2. Parser+decorators → IR.
3. IR → backend (nftables or OVS flows).
4. Apply.

See [DESIGN.md](DESIGN.md) for the full pipeline, IR contract, and
backend details.

---

## CLI

```bash
pvefw-neo --apply             # apply rules (auto-dispatch nft + OVS)
pvefw-neo --dry-run           # print generated nftables ruleset
pvefw-neo --dump-ir           # print IR (debug)
pvefw-neo --dump-ovs vmbr2    # print OVS flows for a bridge
pvefw-neo --flush             # remove all pvefw-neo state
pvefw-neo --preflight-check   # verify host.fw enable=0 + nftables=1
```

---

## Limitations

| Limitation | Reason |
|---|---|
| `REJECT` becomes `DROP` | neither `bridge` family nor OVS supports REJECT. Peer times out. |
| `Finger` macro is reserved as the sugar carrier | TCP/79 is unused in practice. |
| OVS isolation needs ≥2 isolated ports to take effect | "Two isolated ports cannot communicate" — a single isolated port is meaningless. |
| `@neo:rateexceed` only on `@neo:notrack` | Rate-after-conntrack has edge cases the OVS meter path can't express cleanly. |
| OVS backend expands ipsets by CIDR pre-subtraction | Flow count grows with ipset size. Small sets are fine, huge ones may be slow to compile. |
| `@neo:` tags live in rule comments | PVE WebUI's comment field has a length limit — split complex rules across multiple lines. |

---

## Troubleshooting

```bash
systemctl status pvefw-neo
journalctl -u pvefw-neo -f

pvefw-neo --dump-ir              # IR (backend-agnostic)
pvefw-neo --dry-run              # nftables text
pvefw-neo --dump-ovs vmbr2       # OVS flows for one bridge

nft list table bridge pvefw-neo
ovs-ofctl dump-flows vmbr2 | grep "cookie=0x4e30"

pvefw-neo --flush && systemctl restart pvefw-neo
```

---

## License

See [LICENSE](LICENSE).
