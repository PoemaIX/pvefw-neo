# pvefw-neo

A reimplemented firewall for Proxmox VE, designed to fix PVE's pain points.

Does not modify PVE source code or configuration files.  
Simply reads `.fw` files and generates corresponding rules.

> 🌐 [中文](README.zh.md)  
> 🏗️ Architecture & internals: [DESIGN.md](DESIGN.md)
---

Solves the following pain points:

1. Does not use the `tap → 🧱fwbr🧱→ fwpr ↔ fwln → vmbr0` architecture
    * Native iptables has limited capabilities, forcing the introduction of `fwbr` for firewalling
    * This causes packets to traverse 5 virtual NICs — a serious waste
2. For Linux bridges, uses nftables bridge table
    * Direct path: `tap🧱 → vmbr0`
3. For OVS bridges, uses native OpenFlow rules
    * Avoids `fwbr` and the overhead of routing back through the Linux kernel for nftables
4. All rules are per-port, unlike PVE's native firewall which can only enable/disable per-VM
    1. macspoof: only allow specific src MAC, prevent MAC spoofing
    2. ipspoof: only allow specific src IP, prevent IP spoofing
    3. nodhcp: block DHCP server
    4. nora: block sending RA
---

Current limitations:

1. REJECT rules are ineffective — replaced with DROP
    * nftables cannot do REJECT in the `bridge` family, only `inet` can
    * But using `inet` would require going back to the `fwbr` architecture, so we give up on REJECT
2. **PVE must enable nftables (tech preview)**
    * Even if node firewall / VM firewall are disabled, this must be enabled
    * Because iptables mode causes `pve-firewall` to generate rules (even when node/VM firewall is disabled)
    * Therefore `pvefw-neo` is incompatible with pve-firewall's iptables mode — must switch to nftables mode
3. VM NICs **must have firewall disabled**
    * `pvefw-neo`'s design: NICs with firewall checked are managed by `proxmox-firewall`
    * Regardless of cluster/node/VM firewall settings, if NIC firewall is checked, OVS will create `fwbr`, preventing OpenFlow rules from being applied
    * To avoid conflicts, only NICs without the checkbox are controlled by `pvefw-neo`
        * `pvefw-neo`'s own port-level enable control is in `@neo:disable`
---

How it works:

1. Read existing PVE `/etc/pve/firewall/*.fw` configuration files
2. Preprocessing
3. Compile to IR
4. Query whether port belongs to Linux bridge or OVS, call respective backend
5. Compile to nftables / OpenFlow rules

---

## Requirements

Regardless of whether PVE's native firewall is enabled, **nftables mode
(tech preview) must be turned on** on the host:

PVE WebUI → **Host → Firewall → Options → nftables (tech preview) → yes**

---

## Installation

```bash
curl -sSL https://raw.githubusercontent.com/PoemaIX/pvefw-neo/refs/heads/main/install.sh | bash
```
The script will ask whether to migrate configuration files.

Enable the firewall:
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

Use **PVE WebUI** (VM → Firewall) and edit firewall rules.  
The daemon detects changes and re-applies within a few seconds.

1. Existing PVE rules work as-is
2. pvefw-neo provides two classes of extensions, both placed in the **comment field**
of PVE rules, prefixed with `@neo:`

### Class 1 — Extension rules

These rules provide functionality not available in PVE's native firewall.  
Since PVE WebUI has no corresponding fields, we cannot edit them directly.  
We borrow the long-obsolete **Finger** protocol (TCP/79) as a carrier and write the real rules in the comment field. Because the per-NIC firewall checkbox is off, PVE never actually renders the Finger rule into iptables/nftables — so leaving the rule **Enabled** is safe and preferred: the WebUI shows it as active, and if pvefw-neo has to auto-disable it due to an apply failure, the checkbox flipping off is an immediate visual cue.

**WebUI steps** (`VM → Firewall → Add`)

First fill in the following fields (shared skeleton for all extension rules):

| Field | Value |
|---|---|
| Direction | `out` |
| **Enable** | **checked** |
| Action | `DROP` |
| Macro | `Finger` |
| Source / Comment | filled per tag (see below) |

> Unchecking a Finger+`@neo:` rule is how you **turn that extension off**. pvefw-neo also sets the checkbox to unchecked automatically when nftables/OVS rejects the compiled rule (see "Quarantine" behavior).


| Tag | Effect |
|---|---|
| `@neo:disable` | Turn off pvefw-neo management for this port. All other rules on this port are ignored, traffic passes through freely.<br>Equivalent to PVE's "port-level firewall disable" (we can't use PVE's GUI flag because checking it causes PVE to create fwbr, which is incompatible). |
| `@neo:isolated` | Set kernel bridge `isolated on` (Linux) or corresponding OF rules (OVS).<br>Two isolated ports on the same bridge cannot communicate; isolated ↔ non-isolated can. |

All other Extension rules are **syntactic sugar** (see "Syntactic Sugar" section below).

### Class 2 — Decorator tags

Decorators attach to **real** (non-Finger) PVE rules. Some change rule behavior, others narrow the match scope.  
Use real macros / actions, and **check Enable** in the WebUI.

#### Behavior modifiers

| Tag | Effect |
|---|---|
| `@neo:noct` | Evaluate **before conntrack**, per-packet matching.<br>Alias: `@neo:stateless` |
| `@neo:ct` | Stateful rule, matches all packets that reach the `ct_state` check.<br>Alias: not writing anything.<br>If neither `@neo:noct` nor `@neo:ct` is written, this is the default. |
| `@neo:ct new` | Stateful rule, matches only `ct_state=new` packets. |
| `@neo:ct invalid` | Stateful rule, matches only `ct_state=invalid` packets. |

#### Scope narrowing

| Tag | Effect |
|---|---|
| `@neo:srcmac in <mac1,mac2>` | This rule only applies to packets whose source MAC matches `<mac>`. |
| `@neo:srcmac notin <mac1,mac2>` | This rule only applies to packets whose source MAC does NOT match `<mac>`. |
| `@neo:srcmac bitmask <mask>` | Match source MAC by bitmask (`field & mac == mac`). |
| `@neo:dstmac in <mac1,mac2>` | This rule only applies to packets whose destination MAC matches `<mac>`. |
| `@neo:dstmac notin <mac1,mac2>` | This rule only applies to packets whose destination MAC does NOT match `<mac>`. |
| `@neo:dstmac bitmask <mask>` | Match destination MAC by bitmask (`field & mac == mac`). |
| `@neo:vlan <untagged\|vid1,vid2>` | Only apply to traffic on the specified VLAN(s).<br>Used when a trunk port is given to a VM and rules should only apply to a specific inner VLAN. |
| `@neo:rateexceed <pps>` | Only match the portion of traffic **exceeding** `<pps>`.<br>Packets within the rate budget don't match and fall through to the next rule.<br>**Constraints:** `@neo:stateless` only (not on `@neo:ct`), **and action must be `DROP`/`REJECT`**. `ACCEPT + rateexceed` has no sensible meaning and OVS meters can't express an "accept" band — compiler rejects with a warning and drops the rule. |

### L3 address-family validation

A rule's source, dest and `@neo:ether` tag must agree on IP family or the
compiler skips the rule with a stderr warning (no backend quarantine —
the rule simply doesn't make it to nft/OVS).

**Step 1 — src × dst alignment (strict).** When both `source` and `dest`
are non-null, their families must match exactly: `v4 == v4`, `v6 == v6`,
`mixed == mixed` (an ipset containing both families counts as `mixed`).
Any other combination is rejected (e.g. `source 10.0.0.5 / dest 2001:db8::1`).
The agreed family becomes `l3_afs`; if one side is null the other decides.

**Step 2 — `l3_afs × @neo:ether` intersection (partial).** `@neo:ether ip`
and `@neo:ether arp` both mean v4 (ARP's spa/tpa fields are v4); `@neo:ether ip6`
means v6. When the rule is `mixed` l3_afs and `@neo:ether` is explicit,
the compiler emits **only the matching-family variant** — the other family
is silently skipped for this rule, but the ipset definition stays intact so
other rules referencing the same set still get their full set.

| l3_afs ↓ / @neo:ether → | *(none)* | `ip` | `ip6` | `arp` |
|---|---|---|---|---|
| *(none)* | OK | OK | OK | OK |
| v4 | OK | OK | **REJECT** | OK |
| v6 | OK | **REJECT** | OK | **REJECT** |
| mixed | OK (emit v4 + v6) | OK (emit v4 only) | OK (emit v6 only) | OK (emit v4 only) |

**Examples:**

**Src MAC whitelist**:

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `DROP` | *(none)* | *(none)* | `@neo:stateless @neo:srcmac notin aa:bb:cc:dd:ee:ff` |

**Stateless Src IP whitelist**:

| IPSet | IPs |
|---|---|
`nonself`|`!192.168.66.1/32`

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `DROP` | *(none)* | `+guest/nonself` | `@neo:stateless` |

**VLAN-scoped** stateless rule (trunk port, only apply to inner VLAN 20):

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `ACCEPT` | *(none)* | `10.0.0.0/24` | `@neo:stateless @neo:vlan 20` |

**Drop ct invalid** (per-port, stateful):

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `in`  | `DROP` | *(none)* | *(none)* | `@neo:ct invalid` |
| `out` | `DROP` | *(none)* | *(none)* | `@neo:ct invalid` |

**Allow outbound only, block inbound** (reject inbound `ct_state=new`):

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `in`  | `DROP` |  *(none)* | *(none)* | `@neo:ct new` |

### Syntactic Sugar

The following Extension rules are **syntactic sugar** — they are expanded into decorator rule combinations at compile time, and the sugar itself disappears.  
Usage is the same as Extension rules (Finger skeleton + comment).

---

#### `@neo:macspoof [mac1,mac2,...]`

Only allow source MACs in the list; drop the rest. No args = auto-read from VM config.

`@neo:macspoof`

Expands to:

| Direction | Action | Comment |
|---|---|---|
| `out` | `DROP` | `@neo:noct @neo:srcmac notin <mac>` (MAC auto-read from NIC config) |

---

#### `@neo:ipspoof`

Only allow listed source IPs. Automatically handles ARP / IPv4 / IPv6.

Put the IP list in the Source field or the comment args (choose one).  
(Note: PVE Source field does not accept mixed v4/v6.  
For mixed v4 + v6, use the comment syntax: `@neo:ipspoof 10.0.0.5,2001:db8::1`  
or split into two rules.)

Using comment syntax as an example:

`@neo:ipspoof 192.168.16.3,192.168.30.0/24,2001:db8::1,2a0a:6040::/32`

Expands to **2 pure-nomatch ipsets** + **3 stateless rules** (ARP / v4 / v6):

```
[IPSET ipspoof_vm100_net0_v4]       ← v4 allow list (inverted)
!192.168.16.3
!192.168.30.0/24

[IPSET ipspoof_vm100_net0_v6]       ← v6 auto-includes link-local + DAD
!fe80::/64
!2001:db8::1
!2a0a:6040::/32
!::
```

| Direction | Action | Source | Comment |
|---|---|---|---|
| `out` | `DROP` | `+ipspoof_vm100_net0_v4` | `@neo:noct @ether arp op {request,reply}` (ARP protection) |
| `out` | `DROP` | `+ipspoof_vm100_net0_v4` | `@neo:noct` (IPv4 protection) |
| `out` | `DROP` | `+ipspoof_vm100_net0_v6` | `@neo:noct` (IPv6 protection) |

> The IPv6 ipset always auto-includes `fe80::/64` (link-local) and `::` (DAD),
> ensuring the VM can perform Neighbor Discovery. If the user specifies
> additional v6 addresses (e.g. `2001:db8::1`), they are also added to this ipset.

---

#### `@neo:nodhcp`

Block the VM from acting as a DHCP server (drop UDP sport 67/547 → dport 68/546).

`@neo:nodhcp`

Expands to (one v4 + one v6 rule):

| Direction | Proto | Src Port | Dst Port | Action | Comment |
|---|---|---|---|---|---|
| `out` | `udp` |`67`|`68`|`DROP` | `@neo:noct @ether ip` (v4) |
| `out` | `udp` |`547`|`546`|`DROP` | `@neo:noct @ether ipv6` (v6) |

---

#### `@neo:nora`

Block outbound IPv6 Router Advertisement.

`@neo:nora`

Expands to:

| Direction | Proto | ICMP Type | Action | Comment |
|---|---|---|---|---|
| `out` | `DROP` | `ipv6-icmp` | `router-advertisement` | `@neo:noct` |

---

#### `@neo:nondp`
`@neo:nondp`

Expands to:

| Direction | Proto | ICMP Type | Action | Comment |
|---|---|---|---|---|
| `out` | `DROP` | `ipv6-icmp` | `neighbour-solicitation` | `@neo:noct` |
| `out` | `DROP` | `ipv6-icmp` | `neighbour-advertisement` | `@neo:noct` |

---

#### `@neo:mcast_limit <pps>`

Rate-limit multicast frames sent by the VM.

`@neo:mcast_limit 100`

Expands to:

| Direction | Action | Comment |
|---|---|---|
| `out` | `DROP` | `@neo:noct @neo:rateexceed 100 @neo:dstmac bitmask 01:00:00:00:00:00` |

---

#### `@neo:ctinvdrop`

Drop `ct_state=invalid` packets on this port (both IN + OUT).  
Without this, invalid packets (e.g. asymmetric routing return traffic) are accepted by matching rules.

`@neo:ctinvdrop`

Expands to:

| Direction | Action | Comment |
|---|---|---|
| `in`  | `DROP` | `@neo:ct invalid` |
| `out` | `DROP` | `@neo:ct invalid` |

> Extension vs decorator are now **separate namespaces**: use `@neo:ctinvdrop` only on Finger carriers (sugar), use `@neo:ct invalid` only on real rules (decorator). They produce similar behavior but are written in different places — the decorator form lets you drop invalid packets only when a specific match triggers, rather than unconditionally.

The compilation pipeline is:

1. Sugar expansion (afterwards only `@neo:disable` / `@neo:isolated` remain as native extension rules).
2. Parser + decorator → IR.
3. IR → backend (nftables or OVS flows).
4. Apply.

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

## Quarantine

When a rule can't be compiled — either by the front-end validator
(family mismatch, `rateexceed + ACCEPT`, ...) or by `nft` / `ovs-ofctl`
rejecting it at load time — pvefw-neo **auto-disables** the rule:

1. The `.fw` line is rewritten to prepend `|` (PVE's disable marker),
   so the WebUI checkbox visibly flips to unchecked.
2. A single line is appended to `/var/log/pve-firewall.log` so the
   **VM → Firewall → Log** tab shows, for example:

   ```
   [pvefw-neo] invalid rule #8 disabled, reason: <nft/ovs error or
   validator explanation>
   ```

3. The remaining (valid) rules keep working — the bad rule is the only
   thing that doesn't make it into nft/OVS.

Reverse-routing the backend error to the right source rule uses:

- **nft**: each rule carries `comment "vm<vmid>-line<N>"`. nft's stderr
  echoes the failing rule verbatim, so parsing is a simple substring
  match.
- **OVS**: each flow's cookie is `0x4E30<48-bit hash(source_id)>`; each
  meter ID is `0x4E30<16-bit hash>`. `ovs-ofctl` prints
  `<flows-file>:<N>: <reason>`, we read that line, extract the cookie,
  look up the source_id.

To recover: edit or delete the rule in the WebUI and re-check the
checkbox. The next apply will retry; if the rule is still broken it
gets quarantined again and a new log line appears.

---

## Limitations

| Limitation | Reason |
|---|---|
| `REJECT` becomes `DROP` | `bridge` family and OVS don't support REJECT. Peer times out. |
| `Finger` macro reserved as sugar carrier | TCP/79 is unused in practice. |
| OVS isolation needs ≥2 isolated ports to take effect | "Two isolated ports cannot communicate" — a single isolated port is meaningless. |
| `@neo:rateexceed` only on `@neo:stateless` | Stateful + rate-limit semantics can't be cleanly expressed in the OVS meter model. (Stateless `mcast_limit` on OVS is implemented via OF1.3 meters; pvefw-neo auto-adds `OpenFlow13` to the bridge's `protocols` list when needed.) |
| OVS backend expands ipsets via CIDR pre-subtraction | Flow table size grows with ipset member count. Small sets are fine, large ones may be slow to compile. |
| `@neo:` tags live in the comment field | PVE WebUI's comment field has a length limit. Split complex rules across multiple lines. |

---

## Troubleshooting

```bash
systemctl status pvefw-neo
journalctl -u pvefw-neo -f

pvefw-neo --dump-ir              # backend-agnostic IR
pvefw-neo --dry-run              # nftables text
pvefw-neo --dump-ovs vmbr2       # OVS flows for a bridge

# Inspect what actually got installed
nft list table bridge pvefw-neo
ovs-ofctl dump-flows vmbr2 | grep 'cookie=0x4e30'
ovs-ofctl -O OpenFlow13 dump-meters vmbr2   # rate-limit meters

# Inspect the quarantine audit trail (per-VM in WebUI Log tab)
tail -50 /var/log/pve-firewall.log | grep pvefw-neo

pvefw-neo --flush && systemctl restart pvefw-neo
```

---

## License

See [LICENSE](LICENSE).
