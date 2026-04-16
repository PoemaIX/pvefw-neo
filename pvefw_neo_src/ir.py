"""
pvefw-neo Intermediate Representation (IR)

Pipeline:
    .fw → parser → compiler → IR (Ruleset) → backend (nftables / OVS / ...)

Design:
  - Ruleset 以 NetDev (devname) 為主軸，每個 NetDev 包含 properties + rules
  - Match 用 nested dict (l2/l3/l4)，compiler 必填 ether_type
  - Phase 二元：STATELESS / STATEFUL，backend 自動從 match 內容決定 hook
  - 沒有隱式 default policy：沒規則 = 雙向 accept (透通)
  - 「只允許連出」需用戶手動加 |IN DROP (stateful，回應靠 ct est/rel 自動放行)
  - Backend 在 NetDev 沒有 STATEFUL 規則時應跳過 forward dispatch (含 conntrack)
"""

from dataclasses import dataclass, field
from enum import Enum


# ═══════════════════════════════════════
# Enums
# ═══════════════════════════════════════

class Phase(Enum):
    """規則評估階段 — 看 conntrack 用不用。"""
    STATELESS = "stateless"   # 不用 conntrack
                              # 含: macspoof, ipspoof, nodhcp, nora, notrack ACL
                              # nft: netdev ingress (純 L2) / bridge raw (其他)
                              # ovs: table 0 (純 L2) / table 10 (其他)

    STATEFUL  = "stateful"    # 用 conntrack
                              # 含: 普通 PVE rules (SSH, HTTP, ...)
                              # nft: bridge forward
                              # ovs: table 30/31 (含 ct() action)


class Direction(Enum):
    """從 VM 視角看封包方向。"""
    OUT = "out"   # 封包離開 VM (iif=devname)
    IN  = "in"    # 封包進入 VM (oif=devname / dl_dst=mac)


# ═══════════════════════════════════════
# Match dict 契約 (compiler 填、backend 認)
# ═══════════════════════════════════════
#
# match = {"l2": {...}, "l3": {...}, "l4": {...}}
# 各層 AND，同層 keys 也 AND。空 match {} = catch-all。
#
# ── L2 keys ──
#   src_mac:        str           "AA:BB:CC:DD:EE:FF"
#   src_mac_neg:    str | list    源 MAC != (用於 macspoof，支援多 MAC)
#   src_mac_mask:   (addr, mask)  bitmask 比對 (用於 @neo:srcmac bitmask)
#   dst_mac:        str
#   dst_mac_mask:   (addr, mask)  bitmask 比對 (multicast: 01:00:00:00:00:00)
#   ether_type:     str           "ip" / "ip6" / "arp" / "vlan"
#                                 compiler 必填（除非純 MAC 過濾）
#   ether_type_neg: str           "vlan" (untagged 比對)
#   vlan_id:        list[int]     [20] / [100, 200]
#   arp_op:         list[str]     ["request", "reply"]
#   arp_spa:        str           ARP sender protocol address
#
# ── L3 keys ──
#   src_ip:         str           "10.0.0.0/24" (v4 或 v6)
#   dst_ip:         str           compiler 同步設 l2.ether_type
#   src_set:        str           NamedSet 名稱
#   dst_set:        str
#   proto:          str           "tcp" / "udp" / "icmp" / "icmpv6" / "47"
#   icmp_type:      list[str]     ["echo-request", "echo-reply"]   (v4)
#   icmpv6_type:    list[str]     ["nd-router-advert"]              (v6)
#
# ── L4 keys ──
#   src_port:       str           "80" / "1024-65535" / "{80,443}"
#   dst_port:       str
#
# ═══════════════════════════════════════


# ═══════════════════════════════════════
# Rule
# ═══════════════════════════════════════

@dataclass
class Rule:
    """單一規則。歸屬於哪個 netdev 由 NetDev.rules 的 dict context 決定。"""
    direction: Direction
    phase: Phase
    match: dict                # {"l2": {...}, "l3": {...}, "l4": {...}}
    action: str                # "accept" / "drop"
                               # 未來: "dnat:1.2.3.4:80" / "snat:..." / "masquerade"
    rate_limit_pps: int = None # 選用，搭配 action="drop"
    log_level: str = None      # 選用，PVE -log emerg/alert/crit/err/warning/notice/info/debug
                               # nftgen 為非空 log_level 額外發 nflog rule（mirror official）
    comment: str = ""          # .fw 註解 + @neo: tag 原文


# ═══════════════════════════════════════
# NetDev (properties + rules)
# ═══════════════════════════════════════

@dataclass
class NetDev:
    """一個網路裝置 (tap/veth) 的完整 firewall 配置。"""
    devname: str               # 主鍵 — tap100i0 / veth100i0
    mac: str                   # VM source MAC，IN direction match 用
    vmid: int                  # 來源 VM ID
    iface: str                 # "net0" — VM 內部 NIC 名 (PVE 用語)
    isolated: bool = False     # Linux bridge isolated flag (語意 A)
                               #   nft: bridge link set isolated on
                               #   ovs: reg0 mark + dl_dst drop
    ctinvalid: bool = False    # @neo:ctinvalid — drop ct_state invalid on this port
    disabled: bool = False     # @neo:disable — debug switch, 跳過整個 port
                               # backends 看到 disabled=True 就完全 skip,
                               # 封包透通（跟 port 沒出現在 IR 等價）
    rules: list = field(default_factory=list)  # list[Rule]，按 .fw 順序


# ═══════════════════════════════════════
# NamedSet
# ═══════════════════════════════════════

@dataclass
class NamedSet:
    """命名 IP 集合，對應 .fw 的 [IPSET name]。

    PVE ipset 成員允許前綴 `!` 表示「排除」(nomatch)。nftables set 本身
    不支援 per-element 否定，所以我們把它拆成兩個邏輯集合：

      elements: 正向成員  → backend 渲染成 set <name>
      excludes: 否定成員  → backend 渲染成 set <name>_nomatch（若非空）

    參考 official Rust impl: proxmox-firewall/src/object.rs 把每個 IPSet
    生成 `<name>` 和 `<name>-nomatch` 兩個 nft set，rule 引用時同時 match
    `field == @<name>` AND `field != @<name>_nomatch`。我們採用同樣作法。
    """
    name: str                  # 全域唯一，例 "vm100_whitelist"
    family: str                # "ipv4" / "ipv6"
    elements: list             # 正向 ["10.0.0.0/24", "10.0.1.5"]
    excludes: list = field(default_factory=list)  # 否定 ["10.0.0.5"]


# ═══════════════════════════════════════
# Ruleset (top-level)
# ═══════════════════════════════════════

@dataclass
class Ruleset:
    """整個 host 的 firewall state。compiler 輸出，backend 輸入。"""
    netdevs: dict = field(default_factory=dict)   # devname → NetDev
    sets: dict = field(default_factory=dict)      # set_name → NamedSet

    def dump(self):
        """除錯用：人類可讀表示。"""
        lines = []

        if self.sets:
            lines.append("# ── Named sets ──")
            for name in sorted(self.sets):
                s = self.sets[name]
                lines.append(f"  {name} ({s.family}): {s.elements}")
            lines.append("")

        for devname in sorted(self.netdevs):
            nd = self.netdevs[devname]
            flags = []
            if nd.isolated:
                flags.append("isolated")
            if nd.disabled:
                flags.append("disabled")
            flag_str = f" [{','.join(flags)}]" if flags else ""
            lines.append(
                f"# ── NetDev {devname}  vm{nd.vmid}/{nd.iface}  "
                f"mac={nd.mac}{flag_str} ──"
            )
            if nd.disabled:
                lines.append("  (rules omitted: port is disabled via @neo:disable)")
                lines.append("")
                continue

            by_phase = {Phase.STATELESS: [], Phase.STATEFUL: []}
            for r in nd.rules:
                by_phase[r.phase].append(r)

            for phase in (Phase.STATELESS, Phase.STATEFUL):
                rules = by_phase[phase]
                if not rules:
                    continue
                lines.append(f"  [{phase.value}]")
                for r in rules:
                    lines.append(f"    {_dump_rule(r)}")
            lines.append("")

        return "\n".join(lines)


def _dump_rule(r):
    parts = [r.direction.value, _dump_match(r.match), f"→ {r.action}"]
    if r.rate_limit_pps is not None:
        parts.append(f"(rate>{r.rate_limit_pps}pps)")
    s = " ".join(parts)
    if r.comment:
        s += f"  # {r.comment}"
    return s


def _dump_match(m):
    parts = []
    for layer in ("l2", "l3", "l4"):
        d = m.get(layer, {})
        if not d:
            continue
        kvs = []
        for k, v in d.items():
            if isinstance(v, list):
                kvs.append(f"{k}={'|'.join(str(x) for x in v)}")
            else:
                kvs.append(f"{k}={v}")
        parts.append(f"{layer}{{{','.join(kvs)}}}")
    return " ".join(parts) if parts else "*"
