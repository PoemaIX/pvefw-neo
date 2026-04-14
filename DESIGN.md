# pvefw-neo Design Document

> **Version**: 4.0 — 2026-04-12
> **Status**: Implemented + tested. Production-ready.

> 📖 安裝/使用說明請見 [README.md](README.md) (English) 或 [README.zh_TW.md](README.zh_TW.md) (繁體中文)

---

## 1. Problem Statement

PVE 的內建防火牆有三個根本問題：

### 1.1 強制 conntrack，三種模式都有問題

| 模式 | 問題 |
|------|------|
| `conntrack (drop invalid)` | 非對稱路由的封包全部被丟。這是全域規則，**就算 port 級別關閉防火牆還是丟**。BGP 場景非對稱路由很常見 |
| `conntrack (allow invalid)` | 不丟了，但所有封包仍然走 conntrack，有性能損耗 |
| Datacenter 級別關閉 firewall | 什麼保護都沒有了，連 MAC spoofing 都防不了 |

### 1.2 五個安全規則只能 per-VM，不能 per-port

DHCP / RA / IP spoofing / MAC spoofing / NDP 這五個規則只能整台 VM 一起設定。
無法做到「net0 禁止發 DHCP，net1 允許發 DHCP」。

### 1.3 沒有 NOTRACK 路徑

所有過濾都走 conntrack，即使 src-ip、src-mac 這類無狀態過濾也是如此。

---

## 2. Solution: pvefw-neo

一個獨立的 nftables 規則產生器：

- 讀取 PVE 既有的 `/etc/pve/firewall/*.fw` 設定檔
- 直接產生並套用 nftables 規則
- 要求 PVE 自己的防火牆**已關閉**
- **不修改任何 PVE 程式碼**——只讀取設定檔
- 支援 per-port（per-vNIC）精細控制
- 盡可能使用 `NOTRACK` 避免 conntrack 開銷
- 遵守 PEP 668，只使用 Python 標準函式庫 + 系統套件 (`python3-nftables`)

---

## 3. 關鍵技術分析

### 3.1 fwbr 問題：nftables 完全不需要

**PVE iptables 防火牆的拓撲：**

```
FW ON:   VM [tap100i0] → veth → [fwbr100i0] → veth → [vmbr0]
FW OFF:  VM [tap100i0] → [vmbr0]（直連）
```

PVE 引入 fwbr 是因為 iptables 無法在 bridge port 上正確做 L3 過濾。

**nftables 不需要 fwbr，直連即可：**

```
pvefw-neo:  VM [tap100i0] → [vmbr0]（直連，FW OFF 的拓撲）
```

原因：

1. **nftables bridge family 原生支援 L3/L4 match + conntrack（kernel ≥ 5.3）**

   PVE 7（kernel 5.13+）和 PVE 8（kernel 6.2+）都滿足。

2. **方向性用 `iifname` / `oifname` 解決**，不需要 `br_netfilter`

3. **netdev ingress hook** 提供最早攔截點（比 bridge 還早）

> PVE 官方的 `proxmox-firewall`（Rust 實作）也不建立 fwbr。

### 3.2 封包流向

**VM 之間的 bridged traffic 不走 inet forward hook。**

所有 VM 規則必須放在 `table bridge`，不能放 `table inet`。

```
VM tap device
     │
     ▼
[netdev ingress]        ← per-device, MAC filter, mcast ratelimit
     │
     ▼
bridge raw_prerouting   ← @neo:notrack 規則、語法糖展開的規則
     │                     priority raw (-300), 在 conntrack 之前
     ▼
bridge forward          ← 原生 stateful 規則
     │                     priority filter (0), conntrack 生效
     ▼
目標 port / IP stack
```

### 3.3 Macro 定義來源

PVE macro 定義在 `Firewall.pm` 的 `$pve_fw_macros` Perl hash 中。
**沒有獨立的 `macros.def`。**

策略：Runtime 正則解析 `Firewall.pm` + hardcoded fallback。

---

## 4. 規則體系

### 4.1 核心語意

pvefw-neo 中的每條規則屬於兩類之一：

| | 原生規則（無 @neo tag） | `@neo:notrack` 規則 |
|---|---|---|
| nftables chain | `bridge forward` (priority filter) | `bridge raw_prerouting` (priority raw) |
| conntrack | **有**，`ct state established,related` 生效 | **無**，per-packet 獨立評估 |
| 評估時機 | conntrack 之後 | conntrack 之前 |
| 適用場景 | 傳統有狀態防火牆（允許連出但禁止連入等） | IP/MAC spoofing 防護、stateless ACL |

**不存在「整個 port 都 notrack」的概念。** 每條規則自己決定。
同一個 port 上可以混合兩類規則。

### 4.2 處理順序

```
封包從 tap100i0 出來：

  1) bridge raw_prerouting（@neo:notrack 規則 + 語法糖展開）
     ├── 按 .fw 檔案中的出現順序評估
     ├── 命中 ACCEPT → 封包通過，繼續到下一層
     ├── 命中 DROP   → 封包丟棄，結束
     └── 全部未命中  → 繼續到下一層

  2) bridge forward（原生 stateful 規則）
     ├── ct state established,related → accept
     ├── 按 .fw 檔案中的出現順序評估
     └── 最後 default policy（policy_in / policy_out）
```

### 4.3 方向映射

PVE 和 nftables 的方向定義相反：

| PVE | 語意 | nftables bridge |
|-----|------|----------------|
| `OUT` | 封包從 VM 出去 | `iifname "tapXiY"` |
| `IN` | 封包進入 VM | `oifname "tapXiY"` |

### 4.4 `-iface` 欄位 = per-port

PVE rule 的 `-i net0` / `-iface net0` 指定規則只套用於特定 port。
pvefw-neo 把它映射到對應的 `tap`/`veth` device name。

沒有 `-i` 的規則套用到 VM 的所有 port。

---

## 5. Tag 體系

所有 neo 擴充都放在 PVE rule 的 **comment 欄位**，以 `@neo:` 為 prefix。

### 5.1 兩層設計

**語法糖**：一條規則搞定常見場景，不用管順序。用 Finger dummy（`enable=0`）。

**底層原語**：附加在正常規則上，使用者自己控制順序和組合。

### 5.2 語法糖（Finger dummy, enable=0）

語法糖自動展開成多條 nftables 規則，使用者不需要理解展開細節。
必須搭配 `-i netX` 指定 port。

#### `@neo:ipspoof <ip,...>`

防止 IP spoofing。只允許指定的 source IP，其他 drop。
同時防護 ARP spoofing 和 NDP spoofing（自動展開）。

```
|OUT Finger(DROP) -enable 0 -i net0 # @neo:ipspoof 10.0.0.100/32,fd00::100/128
```

展開為（bridge raw_prerouting, NOTRACK）：

```nft
# ── ARP 防護 ──
# 只允許 VM 用合法 IP 發 ARP request/reply，防止 ARP spoofing
iifname "tap100i0" ether type arp arp operation { request, reply } \
    arp saddr ip 10.0.0.100 accept
iifname "tap100i0" ether type arp drop

# ── IPv4 防護 ──
iifname "tap100i0" ether type ip ip saddr 10.0.0.100/32 accept
iifname "tap100i0" ether type ip drop

# ── IPv6 防護 ──
# 允許 DAD（src :: 的 Neighbor Solicitation 是合法的）
iifname "tap100i0" ether type ip6 ip6 saddr ::0 \
    icmpv6 type nd-neighbor-solicit accept
# 允許 link-local（NDP 必須用 fe80::）
iifname "tap100i0" ether type ip6 ip6 saddr fe80::/10 accept
# 允許 whitelist 中的 global address
iifname "tap100i0" ether type ip6 ip6 saddr fd00::100/128 accept
iifname "tap100i0" ether type ip6 drop
```

多個 IP/prefix 逗號分隔，自動區分 v4/v6。

> **fe80::/10 放行說明**：VM 需要 link-local 地址做 NDP 才能有基本的
> IPv6 connectivity。嚴格限制 link-local 需要 RA Guard / SAVI 等機制，
> 超出 ipspoof 的範圍。搭配 `@neo:macspoof` 已限制 L2 地址，組合防護足夠。

#### `@neo:macspoof [mac]`

防止 MAC spoofing。只允許指定的 source MAC，其他 drop。

```
|OUT Finger(DROP) -enable 0 -i net0 # @neo:macspoof 02:00:00:00:01:00
```

不帶參數時自動從 VM config 讀取 MAC：

```
|OUT Finger(DROP) -enable 0 -i net0 # @neo:macspoof
```

展開為（netdev ingress）：

```nft
# table netdev pvefw-neo-tap100i0
ether saddr != 02:00:00:00:01:00 drop
```

#### `@neo:nodhcp`

禁止 VM 充當 DHCP server。

```
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nodhcp
```

展開為（bridge raw_prerouting, NOTRACK）：

```nft
iifname "tap100i0" ether type ip  udp sport 67  udp dport 68  drop
iifname "tap100i0" ether type ip6 udp sport 547 udp dport 546 drop
```

#### `@neo:nora`

禁止 VM 發送 Router Advertisement。

```
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nora
```

展開為：

```nft
iifname "tap100i0" ether type ip6 icmpv6 type nd-router-advert drop
```

#### `@neo:nondp`

禁止 VM 發送 NDP（Neighbor Solicitation / Advertisement）。

```
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nondp
```

展開為：

```nft
iifname "tap100i0" ether type ip6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } drop
```

#### `@neo:mcast_limit <pps>`

限制 multicast 封包速率。

```
|OUT Finger(DROP) -enable 0 -i net0 # @neo:mcast_limit 100
```

展開為（netdev ingress，最早攔截）：

```nft
# table netdev pvefw-neo-tap100i0
ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00 limit rate over 100/second drop
```

#### `@neo:isolated`

啟用 port isolation。該 port 無法與同 bridge 上的其他 VM port 通訊。

```
|OUT Finger(DROP) -enable 0 -i net2 # @neo:isolated
```

展開為：

```nft
# bridge forward chain
iifname "tap100i2" oifname "tap*"  drop
iifname "tap100i2" oifname "veth*" drop
```

同時執行：

```bash
bridge link set dev tap100i2 isolated on
```

### 5.3 底層原語（附加在正常規則上）

底層原語附加在**真正要執行的規則**上（不是 Finger dummy）。
使用者自己控制規則的順序和組合。

#### `@neo:notrack`

標記這條規則走 raw chain（NOTRACK），不建立也不查詢 conntrack entry。

```
|OUT ACCEPT -i net0 -source 192.168.6.2/32 # @neo:notrack
|OUT DROP   -i net0                        # @neo:notrack
```

翻譯為 bridge raw_prerouting：

```nft
iifname "tap100i0" ether type ip ip saddr 192.168.6.2/32 accept
iifname "tap100i0" drop
```

**順序重要**：多條 `@neo:notrack` 規則按 `.fw` 檔案中的出現順序排列。
使用者有責任確保先 ACCEPT 再 DROP。

#### `@neo:mac <src_mac> [dst_mac]`

為規則附加 MAC 地址 match 條件。必須搭配 `@neo:notrack` 使用。

```
|OUT ACCEPT -i net0 # @neo:notrack @neo:mac 02:00:00:00:01:00
|OUT DROP   -i net0 # @neo:notrack @neo:mac *
```

- 只寫一個參數 → match src MAC
- `*` = any（不加 MAC 條件）
- 兩個參數 → `@neo:mac <src> <dst>`

翻譯為：

```nft
iifname "tap100i0" ether saddr 02:00:00:00:01:00 accept
iifname "tap100i0" drop
```

#### `@neo:vlan <vid|untagged>`

為規則附加 VLAN match 條件。指定規則只套用於特定 VLAN 的流量。

```
|OUT ACCEPT -i net0 -source 10.0.0.100/32 # @neo:notrack @neo:vlan 20
|OUT DROP   -i net0                       # @neo:notrack @neo:vlan 20
```

語法：

- `@neo:vlan 20` — 只匹配 VLAN 20
- `@neo:vlan 100,200` — 匹配 VLAN 100 或 200
- `@neo:vlan untagged` — 只匹配沒有 802.1Q header 的封包
- 不寫 — 全部匹配（tagged + untagged）

> **注意**：`vlan id 0` 是 priority-tagged（有 802.1Q header 但 VID=0），
> 不等於 untagged。要匹配真正的 untagged 封包請用 `@neo:vlan untagged`。

翻譯為：

```nft
# @neo:vlan 20
vlan id 20

# @neo:vlan 100,200
vlan id { 100, 200 }

# @neo:vlan untagged
ether type != 8021q
```

> **使用場景**：`@neo:vlan` 主要用於 trunk port（VM 的 vNIC 沒有在 PVE 設
> tag，VM 自己發帶 VLAN tag 的封包）。如果 PVE 已在 vNIC 設了 `tag=20`，
> tap device 上收發的都是 untagged 封包（VLAN tag 由 bridge 加/去），
> 此時 `@neo:vlan` 無效果。

### 5.4 Tag 總表

| Tag | 類型 | Finger dummy? | Chain | 用途 |
|-----|------|--------------|-------|------|
| `@neo:ipspoof <ip,...>` | 語法糖 | ✅ enable=0 | bridge raw | IP + ARP + NDP spoofing prevention |
| `@neo:macspoof [mac]` | 語法糖 | ✅ enable=0 | netdev ingress | MAC spoofing prevention |
| `@neo:nodhcp` | 語法糖 | ✅ enable=0 | bridge raw | 禁止當 DHCP server |
| `@neo:nora` | 語法糖 | ✅ enable=0 | bridge raw | 禁止發 RA |
| `@neo:nondp` | 語法糖 | ✅ enable=0 | bridge raw | 禁止發 NDP |
| `@neo:mcast_limit <pps>` | 功能 | ✅ enable=0 | netdev ingress | multicast ratelimit |
| `@neo:isolated` | 功能 | ✅ enable=0 | bridge fwd + kernel | port isolation |
| `@neo:disable` | 功能 | ✅ enable=0 | 跳過整個 port | debug：該 port 完全不處理 |
| `@neo:notrack` | 原語 | ❌ 正常規則 | bridge raw | 規則走 raw chain |
| `@neo:mac <src> [dst]` | 原語 | ❌ 正常規則 | 隨所附加規則 | 加 MAC match 條件 |
| `@neo:vlan <vid\|untagged>` | 原語 | ❌ 正常規則 | 隨所附加規則 | 加 VLAN match 條件 |

---

## 6. 展開規則與排序

### 6.1 原地展開

語法糖在 `.fw` 檔案中出現的位置**原地展開**。

例如 `.fw` 中的規則順序：

```
|OUT Finger(DROP) -enable 0 -i net0 # @neo:macspoof 02:00:00:00:01:00
|OUT Finger(DROP) -enable 0 -i net0 # @neo:ipspoof 10.0.0.100/32
|OUT ACCEPT -i net0 -source 10.0.0.0/24 # @neo:notrack
|OUT DROP   -i net0                     # @neo:notrack
|IN  SSH(ACCEPT) -source 10.0.0.0/24 -i net0
|IN  DROP -i net0
```

生成的 nftables 規則按相同順序排列：

```nft
# ── netdev ingress (tap100i0) ──
# @neo:macspoof（原地展開）
ether saddr != 02:00:00:00:01:00 drop

# ── bridge raw_prerouting ──
# @neo:ipspoof（原地展開）
iifname "tap100i0" ether type ip ip saddr 10.0.0.100/32 accept
iifname "tap100i0" ether type ip drop
iifname "tap100i0" ether type ip6 drop

# @neo:notrack 規則（按原始順序）
iifname "tap100i0" ether type ip ip saddr 10.0.0.0/24 accept
iifname "tap100i0" drop

# ── bridge forward ──
# 原生 stateful 規則
ct state established,related accept
oifname "tap100i0" meta l4proto tcp tcp dport 22 ether type ip ip saddr 10.0.0.0/24 accept
oifname "tap100i0" drop
```

### 6.2 不同 chain 的規則分組

雖然在 `.fw` 中穿插排列，生成時按目標 chain 分組：

1. **netdev ingress**（per-device table）：`@neo:macspoof`、`@neo:mcast_limit`
2. **bridge raw_prerouting**：`@neo:ipspoof`、`@neo:nodhcp`、`@neo:nora`、`@neo:nondp`、`@neo:notrack` 規則
3. **bridge forward**：原生 stateful 規則（無 @neo tag）、`@neo:isolated`

同一個 chain 內，規則按 `.fw` 中的出現順序排列。

---

## 7. 整體架構

### 7.1 Pipeline (parser → compiler → IR → backend)

pvefw-neo 採用三層架構，IR (Intermediate Representation) 是後端無關的中間表示：

```
┌──────────────────────────────────────┐
│  PVE WebUI / 直接編輯 .fw 檔案        │
└──────────┬───────────────────────────┘
           │ writes
           ▼
┌──────────────────────────────────────┐
│  /etc/pve/firewall/{cluster,*}.fw    │
│  /etc/pve/{qemu-server,lxc}/*.conf   │
└──────────┬───────────────────────────┘
           │ inotify (write events) + OVS port poll (10s)
           ▼
┌──────────────────────────────────────────────────────┐
│  pvefw-neo daemon (systemd, Python 3)                │
│                                                      │
│  ┌─ parser.py ───────────────────────────────────┐  │
│  │  解析 .fw / .conf：rules, ALIASES, IPSET,      │  │
│  │  security groups, @neo: tags                   │  │
│  └────────────┬───────────────────────────────────┘  │
│               ▼                                      │
│  ┌─ compiler.py ─────────────────────────────────┐  │
│  │  • 展開 sugar tags (@neo:ipspoof 等)          │  │
│  │  • 解析 alias / ipset / security group        │  │
│  │  • 套用 macros (Firewall.pm)                   │  │
│  │  • policy_in/out → 顯式 catch-all rule         │  │
│  │  • 輸出 IR (Ruleset)                           │  │
│  └────────────┬───────────────────────────────────┘  │
│               ▼                                      │
│  ┌─ ir.py: Ruleset (後端無關) ───────────────────┐  │
│  │  netdevs: dict[devname → NetDev]              │  │
│  │    └─ rules: list[Rule]                        │  │
│  │       └─ phase, direction, match, action       │  │
│  │  sets: dict[name → NamedSet]                  │  │
│  └────────────┬───────────────────────────────────┘  │
│               │                                      │
│        detect_bridge() per netdev                    │
│        ┌──────┴──────┐                               │
│        ▼             ▼                               │
│  ┌─ nftgen.py ─┐  ┌─ ovsgen.py ─┐                   │
│  │ Linux       │  │ OVS bridge  │                   │
│  │ bridge ports│  │ ports       │                   │
│  └──────┬──────┘  └──────┬──────┘                   │
└─────────┼────────────────┼──────────────────────────┘
          │                │
          ▼                ▼
       nft -f       ovs-ofctl add-flows
```

### 7.2 IR 設計原則

| 原則 | 說明 |
|------|------|
| **後端無關** | IR 不知道 nftables / OVS 的存在，只描述「規則語意」 |
| **per-NetDev 主軸** | `Ruleset.netdevs[devname]` 為主結構，規則歸屬於某個 netdev |
| **二元 Phase** | `STATELESS` (notrack/sugar 防護) vs `STATEFUL` (普通 firewall)，由 backend 自行決定 hook 點 |
| **Match 結構化** | nested dict `{"l2":{...}, "l3":{...}, "l4":{...}}` |
| **沒有 jump/goto** | backend 自己決定要組成什麼 chain 結構 |
| **沒有隱式 default policy** | 沒規則 = 雙向 accept；`policy_in: DROP` 由 compiler 翻譯成顯式 catch-all rule |
| **isolated 是 NetDev 屬性** | 不是規則，由 backend 各自實作（kernel flag / OF rule） |

### 7.3 核心資料結構

```python
@dataclass
class Rule:
    direction: Direction      # OUT (iif=devname) / IN (oif=devname or dl_dst=mac)
    phase: Phase              # STATELESS / STATEFUL
    match: dict               # {l2:{...}, l3:{...}, l4:{...}}
    action: str               # "accept" / "drop"
    rate_limit_pps: int = None
    comment: str = ""

@dataclass
class NetDev:
    devname: str              # tap100i0 / veth100i0
    mac: str                  # for IN-direction match (dl_dst on OVS)
    vmid: int
    iface: str                # "net0" — PVE 內部 NIC 名
    isolated: bool = False    # Linux bridge isolated 旗標
    rules: list = field(default_factory=list)

@dataclass
class Ruleset:
    netdevs: dict             # devname → NetDev
    sets: dict                # set_name → NamedSet
```

### 7.4 Backend 自動派發

`main.py` 在 apply 時呼叫 `detect_bridge(devname)`：

1. 讀 `/sys/class/net/<dev>/master` 找出 master bridge
2. 若 master 是 `ovs-system` → 用 `ovs-vsctl iface-to-br` 找實際 OVS bridge → `bridge_type="ovs"`
3. 否則 → `bridge_type="linux"`

然後按 bridge type 分組：
- **Linux bridge ports** → 一次 `nftgen.render()` → `nft -f`
- **OVS bridge ports**（每個 OVS bridge 各一份）→ `ovsgen.apply(bridge, devs)` → `ovs-ofctl add-flows`

同一台 VM 的 net0 在 vmbr1 (Linux)、net1 在 vmbr2 (OVS) 是合法的，會自動分流到兩個 backend。

---

## 8. nftables Chain 架構

### 8.1 完整範例

VM 100，三張網卡：

```ini
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT

[ALIASES]
mgmt_gw 10.0.0.1

[IPSET ipfilter-net0]
10.0.0.100

[RULES]
# ── 語法糖 ──
|OUT Finger(DROP) -enable 0 -i net0 # @neo:macspoof
|OUT Finger(DROP) -enable 0 -i net0 # @neo:ipspoof 10.0.0.100/32
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nodhcp
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nora

|OUT Finger(DROP) -enable 0 -i net1 # @neo:macspoof 02:00:00:00:02:00
|OUT Finger(DROP) -enable 0 -i net1 # @neo:nodhcp
|OUT Finger(DROP) -enable 0 -i net1 # @neo:nora

|OUT Finger(DROP) -enable 0 -i net2 # @neo:macspoof
|OUT Finger(DROP) -enable 0 -i net2 # @neo:isolated
|OUT Finger(DROP) -enable 0 -i net2 # @neo:mcast_limit 100

# ── 底層原語：net1 BGP notrack ACL ──
|OUT ACCEPT -i net1 -source 169.254.0.0/16 # @neo:notrack
|OUT ACCEPT -i net1 -source 10.100.0.0/16  # @neo:notrack
|OUT DROP   -i net1                        # @neo:notrack

# ── 原生 stateful rules ──
|IN  SSH(ACCEPT)   -source 10.0.0.0/24 -i net0
|IN  HTTPS(ACCEPT) -source 10.0.0.0/24 -i net0
|IN  BGP(ACCEPT)   -i net1
|OUT ACCEPT
```

生成的 nftables：

```nft
# ═══════════════════════════════════════
# netdev ingress tables
# ═══════════════════════════════════════

table netdev pvefw-neo-tap100i0 {
    chain ingress {
        type filter hook ingress device "tap100i0" priority -300;
        policy accept;
        # @neo:macspoof (auto-read MAC from VM config)
        ether saddr != 02:00:00:00:01:00 drop
    }
}

table netdev pvefw-neo-tap100i1 {
    chain ingress {
        type filter hook ingress device "tap100i1" priority -300;
        policy accept;
        # @neo:macspoof 02:00:00:00:02:00
        ether saddr != 02:00:00:00:02:00 drop
    }
}

table netdev pvefw-neo-tap100i2 {
    chain ingress {
        type filter hook ingress device "tap100i2" priority -300;
        policy accept;
        # @neo:macspoof (auto-read)
        ether saddr != 02:00:00:00:03:00 drop
        # @neo:mcast_limit 100
        ether daddr & 01:00:00:00:00:00 == 01:00:00:00:00:00 \
            limit rate over 100/second drop
    }
}

# ═══════════════════════════════════════
# bridge table
# ═══════════════════════════════════════

table bridge pvefw-neo {

    # ── named sets ──
    set vm100_ipfilter_net0 {
        type ipv4_addr; flags interval;
        elements = { 10.0.0.100 }
    }

    # ── raw_prerouting: NOTRACK rules ──
    chain raw_prerouting {
        type filter hook prerouting priority raw; policy accept;

        # --- net0 sugar ---
        # @neo:ipspoof 10.0.0.100/32
        iifname "tap100i0" ether type arp arp operation { request, reply } \
            arp saddr ip 10.0.0.100 accept
        iifname "tap100i0" ether type arp drop
        iifname "tap100i0" ether type ip ip saddr 10.0.0.100/32 accept
        iifname "tap100i0" ether type ip drop
        iifname "tap100i0" ether type ip6 ip6 saddr ::0 \
            icmpv6 type nd-neighbor-solicit accept
        iifname "tap100i0" ether type ip6 ip6 saddr fe80::/10 accept
        iifname "tap100i0" ether type ip6 drop

        # @neo:nodhcp
        iifname "tap100i0" ether type ip  udp sport 67  udp dport 68  drop
        iifname "tap100i0" ether type ip6 udp sport 547 udp dport 546 drop

        # @neo:nora
        iifname "tap100i0" ether type ip6 icmpv6 type nd-router-advert drop

        # --- net1 sugar ---
        # @neo:nodhcp
        iifname "tap100i1" ether type ip  udp sport 67  udp dport 68  drop
        iifname "tap100i1" ether type ip6 udp sport 547 udp dport 546 drop

        # @neo:nora
        iifname "tap100i1" ether type ip6 icmpv6 type nd-router-advert drop

        # --- net1 notrack ACL ---
        iifname "tap100i1" ether type ip ip saddr 169.254.0.0/16 accept
        iifname "tap100i1" ether type ip ip saddr 10.100.0.0/16 accept
        iifname "tap100i1" drop
    }

    chain raw_output {
        type filter hook output priority raw; policy accept;
        # (mirror notrack for reply path if needed)
    }

    # ── forward: stateful rules ──
    chain forward {
        type filter hook forward priority filter; policy accept;

        # ARP pass-through (essential for L2 learning)
        ether type arp accept

        # conntrack framework
        ct state established,related accept
        ct state invalid drop

        # per-port dispatch:
        # OUT uses 'jump' so the OUT chain returns control to forward
        # after evaluation, allowing the IN check to also fire for
        # VM-to-VM traffic.
        # IN uses 'goto' as the final verdict.
        iifname "tap100i0" jump vm_tap100i0_out
        oifname "tap100i0" goto vm_tap100i0_in

        iifname "tap100i1" jump vm_tap100i1_out
        oifname "tap100i1" goto vm_tap100i1_in

        # net2: @neo:isolated handled by Linux bridge kernel flag
        # (bridge link set dev tap100i2 isolated on), not nft rules.
    }

    # ── per-port stateful rule chains ──

    chain vm_tap100i0_in {
        # |IN SSH(ACCEPT) -source 10.0.0.0/24 -i net0
        ether type ip ip saddr 10.0.0.0/24 meta l4proto tcp tcp dport 22 accept
        # |IN HTTPS(ACCEPT) -source 10.0.0.0/24 -i net0
        ether type ip ip saddr 10.0.0.0/24 meta l4proto tcp tcp dport 443 accept
        # policy_in: DROP — explicit catch-all from compiler
        drop
    }

    chain vm_tap100i0_out {
        # |OUT ACCEPT — converted to 'return' so IN check still runs
        return
    }

    chain vm_tap100i1_in {
        # |IN BGP(ACCEPT) -i net1
        meta l4proto tcp tcp dport 179 accept
        drop
    }

    chain vm_tap100i1_out {
        return
    }
}
```

> **NetDevs without STATEFUL rules** are skipped from the forward chain
> dispatch entirely. Their packets fall through (forward chain default
> policy = `accept`) without entering conntrack, avoiding the overhead.

---

## 9. Config 解析

### 9.1 PVE .fw 檔案格式

```ini
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT

[ALIASES]
myserver = 10.0.1.100

[IPSET ipfilter-net0]
10.0.1.100

[RULES]
|IN SSH(ACCEPT) -source 10.0.0.0/24
|OUT ACCEPT
|OUT Finger(DROP) -enable 0 -i net0 # @neo:ipspoof 10.0.0.100/32
```

### 9.2 解析流程

1. 解析 `[OPTIONS]` → dhcp/macfilter/ipfilter/ndp/radv 預設值
2. 解析 `[ALIASES]` → alias → IP mapping
3. 解析 `[IPSET ...]` → ipset name → member list
4. 解析 `[RULES]`，對每條規則：
   a. 解析 PVE 標準欄位（direction, action, macro, source, dest, proto, port, iface）
   b. 解析 comment 中的 `@neo:` tags
   c. 分類：
      - Finger dummy + `@neo:` sugar tag → 展開成 NOTRACK 規則
      - 正常規則 + `@neo:notrack` → 放入 raw chain
      - 正常規則 + `@neo:mac` → 加上 MAC match
      - 正常規則（無 tag） → 放入 forward chain（stateful）
5. 解析 `cluster.fw` → security groups, cluster-wide aliases/ipsets

### 9.3 Macro 解析

Runtime 正則解析 `/usr/share/perl5/PVE/Firewall.pm` 中的 `$pve_fw_macros`：

```python
import re

def parse_firewall_pm(path="/usr/share/perl5/PVE/Firewall.pm"):
    macros = {}
    content = open(path).read()

    m = re.search(r'\$pve_fw_macros\s*=\s*\{(.+?)\n\};', content, re.DOTALL)
    if not m:
        raise ValueError("Cannot find $pve_fw_macros")

    block = m.group(1)
    for mm in re.finditer(r"'(\w+)'\s*=>\s*\[(.*?)\]", block, re.DOTALL):
        name = mm.group(1)
        entries = []
        for em in re.finditer(
            r"\{\s*action\s*=>\s*'(\w+)'"
            r"(?:,\s*proto\s*=>\s*'(\w+)')?"
            r"(?:,\s*dport\s*=>\s*'([\d:]+)')?"
            r"(?:,\s*sport\s*=>\s*'([\d:]+)')?"
            r"\s*\}",
            entries_block := mm.group(2)
        ):
            entry = {"action": em.group(1)}
            if em.group(2): entry["proto"] = em.group(2)
            if em.group(3): entry["dport"] = em.group(3)
            if em.group(4): entry["sport"] = em.group(4)
            entries.append(entry)
        if entries:
            macros[name] = entries

    return macros
```

### 9.4 PVE Rule → nftables 翻譯

| PVE 語法 | nftables bridge family |
|----------|----------------------|
| `SSH(ACCEPT)` | `meta l4proto tcp tcp dport 22 accept` |
| `Web(ACCEPT)` | 展開成多條（tcp/80, tcp/443） |
| `-source 10.0.0.0/24` | `ether type ip ip saddr 10.0.0.0/24` |
| `-dest 10.0.0.0/24` | `ether type ip ip daddr 10.0.0.0/24` |
| `-proto tcp` | `meta l4proto tcp` |
| `-sport 1024:65535` | `tcp sport 1024-65535` |
| `-dport 443` | `tcp dport 443` |
| `+dc/ipset(name)` | `ip saddr @name` (nftables named set) |
| `+alias(name)` | 展開成 IP |
| Security Group ref | inline 成 jump chain |
| `ACCEPT` / `DROP` | `accept` / `drop` |
| `REJECT` | `drop`（bridge family 不支援 reject） |

> **注意**：bridge family 中做 L3 match 需要前置 `ether type ip` / `ether type ip6`。

---

## 10. Daemon 架構

### 10.1 依賴

```bash
apt install python3-nftables python3-inotify
# OVS backend (optional)
apt install openvswitch-switch
```

| 套件 | 用途 | 必須 |
|------|------|------|
| `python3` | 標準函式庫 | ✅ |
| `python3-nftables` | nftables Python binding | ✅ |
| `python3-inotify` | inotify filesystem watcher | ✅ |
| `openvswitch-switch` | 提供 `ovs-vsctl` / `ovs-ofctl`；只在使用 OVS bridge 時需要 | ⚠️ |

**遵守 PEP 668**：所有依賴透過 `apt` 安裝系統套件，不用 `pip install`。

### 10.2 自動 reload 機制

daemon 同時用兩個機制偵測變動：

#### A. inotify 監聽 .fw / .conf

監聽路徑：
- `/etc/pve/firewall/` (cluster.fw, *.fw)
- `/etc/pve/qemu-server/` (*.conf — VM 設定)
- `/etc/pve/lxc/` (*.conf — CT 設定)

**只看 write 類事件**（`IN_CLOSE_WRITE`, `IN_MODIFY`, `IN_MOVED_TO`, `IN_DELETE`, `IN_CREATE`），過濾 read 事件。
原因：daemon 的 `compile_ir()` 自己會 read 這些檔案，如果不過濾就會 feedback loop。

事件觸發後 **2 秒 debounce** 合併連續變動，再執行 reload。

#### B. OVS port topology polling (每 10 秒)

OVS flow 用 ofport 數字 key，當 VM stop/start 後 ofport 會重新分配，舊 flow 變成 dangling。
nftables 沒有此問題（`iifname/oifname` 在封包評估時解析）。

daemon 每 10 秒呼叫 `ovs-vsctl list-ports + get Interface ... ofport`，比對 snapshot。
變動 → 觸發 reload。

#### Apply check 邏輯

```python
if pending and (now - last_event_time) >= 2:
    # Generate new IR
    new_nft = nftgen.render(ir_rs, linux_devs)
    # Skip apply if nft text unchanged AND OVS topology unchanged
    if new_nft != last_nft_text or ovs_changed:
        apply_ruleset(...)
```

**no-op skip** 避免無謂的 `nft -f`（PVE 內部會 touch 檔案但內容沒變），但 OVS 變動會 bypass 這個 skip。

### 10.3 systemd service

```ini
[Unit]
Description=pvefw-neo nftables firewall manager for Proxmox VE
After=network.target pve-cluster.service
Wants=pve-cluster.service
Conflicts=pve-firewall.service proxmox-firewall.service

[Service]
Type=simple
ExecStartPre=/usr/local/bin/pvefw-neo --preflight-check
ExecStart=/usr/local/bin/pvefw-neo --daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Launcher (`pvefw-neo`) 用 `#!/usr/bin/python3 -u` 確保 stdout 不 buffer，log 即時出現在 journalctl。

### 10.4 Preflight check — node-off + nftables-mode 共存模型

pvefw-neo 允許跟 PVE 原生防火牆在同一個 cluster 共存：這台 node 由
pvefw-neo 管，其他 node 可繼續跑 PVE 原生防火牆。

**拒絕啟動條件**（只看本機 `host.fw`）：

- `/etc/pve/nodes/<this>/host.fw` 的 `[OPTIONS] enable != 0`
- `/etc/pve/nodes/<this>/host.fw` 的 `[OPTIONS] nftables != 1`

**不再檢查的項目**（舊版本會擋，新版不擋）：

- ~~`cluster.fw [OPTIONS] enable` 不能是 1~~ — 現在允許，由使用者決定
- ~~`pve-firewall.service` 不能 active~~ — 可跑，它在 nftables mode 會 defer
- ~~`proxmox-firewall.service` 不能 active~~ — 可跑，host.enable=0 時它跳過這台 node

**為什麼這兩個條件就夠了**：

| 情境 | PVE 行為 | pvefw-neo 影響 |
|------|---------|---------------|
| `host.enable=0` + `nftables=1` | Perl `pve-firewall` 在 `is_enabled_and_not_nftables()` 回 false → 移除自己的 iptables chains 然後 `return`。Rust `proxmox-firewall` 看到 `host.enable=0` 就跳過這台 node，不寫任何 `inet proxmox-firewall` 表 | 乾淨，nftables 空間讓給 pvefw-neo |
| `host.enable=0` + `nftables=0` (iptables mode) | Perl daemon 仍然會安裝一堆 `PVEFW-*` iptables framework chains（`generate_std_chains` 無條件執行），干擾 | 拒絕啟動 |
| `host.enable=1` 任意 mode | PVE 會在這台 node 安裝 host-level 規則 | 拒絕啟動 |

**cluster.fw flag file 的順帶效應**：

當 `cluster.fw enable=1` AND `host.fw nftables=1` 時，PVE 會
`unlink /run/proxmox-nftables-firewall-force-disable`。這個 flag file
影響 `needs_fwbr()` 的計算：

```perl
sub needs_fwbr { !is_nftables() || is_ovs_bridge() }
sub is_nftables { !-e $FORCE_NFT_DISABLE_FLAG_FILE }
```

- Flag file 不存在 → `is_nftables=true` → Linux bridge 上的 `firewall=1`
  **不會**觸發 fwbr 建立
- Flag file 存在 → `is_nftables=false` → `firewall=1` 會建 fwbr

因此「datacenter enable=1」實際上有一個意外的好處：它讓 Linux bridge 上
的 PVE 原生 `firewall=1` 不再自動建 fwbr。對 pvefw-neo 沒有直接好處（我們
只管 `firewall=0`），但對使用者在同一台 host 切換 PVE native ↔ pvefw-neo
更平順。

OVS bridge 無論 flag file 如何，`firewall=1` 都會建 fwbr（PVE 源碼硬編碼
`is_ovs_bridge() → needs_fwbr=true`）。所以 OVS 上的 `firewall=1` port 永遠
無法被 pvefw-neo 管理，使用者必須設 `firewall=0`。

### 10.4.1 NIC firewall flag 硬性要求

pvefw-neo 管理的 VM NIC 必須設 `firewall=0` 或不設：

| | PVE 原生 | pvefw-neo |
|---|---|---|
| `firewall=1` | 建 fwbr + 套 PVE 規則 | **警告 + 跳過**（fwbr 擋著無法管理） |
| `firewall=0` | 略過（直連 vmbr） | **管理** |
| `firewall` 未設 | 略過（直連 vmbr） | **管理** |

原因：
- pvefw-neo 需要 tap/veth 直連 vmbr 才能下 bridge family 規則
- `firewall=1` 會讓 PVE 自動插入 fwbr 中介橋，打破 direct-attach 模型
- 在 `compile_ruleset` 時發現 `firewall=1` 的 NIC 會印警告並 skip

**install.sh 的批次轉換工具**：掃描所有 `.conf`，詢問是否把 `firewall=1`
一次改成 `firewall=0`，用 `qm set / pct set` 即時生效。

### 10.4.2 Per-port 除錯開關：`@neo:disable`

除錯時常常需要「暫時關掉某個 port 的防火牆看看是不是它的問題」。pvefw-neo
提供 `@neo:disable` sugar tag 做這件事，不用動 VM config、不用刪規則：

```ini
[RULES]
|OUT Finger(DROP) -enable 0 -i net0 # @neo:disable
```

加這一行之後：
- compiler 將 `NetDev.disabled = True`
- backend 看到 `disabled=True` 就**完全跳過**該 port
  - nftables: netdev table 被清除、raw chain 不加規則、forward dispatch 不加 jump/goto
  - OVS: tables 0/10/30/31 都不加該 port 的 flow
- 封包走 forward chain 的 default `accept` → 透通

注意是**單向**跳過：CT2003 標記 disable 後，CT2003 的 rules 失效，但別的 VM（CT2004）
的 rules 還是會對進入 CT2004 的流量生效。所以 CT2003→CT2004 的連線可能仍被
CT2004 的 `policy_in DROP` 擋掉。

`--dump-ir` 會顯示 `[disabled]` 標記方便除錯：

```
# ── NetDev veth2003i0  vm2003/net0  mac=02:00:00:AA:03:00 [disabled] ──
  (rules omitted: port is disabled via @neo:disable)
```

### 10.4.3 Orphan cleanup

每次 `apply_ruleset` 時，main.py 會先掃描現有的 `pvefw-neo-*` netdev table
並全部刪除，然後再載入新的 ruleset。這是為了處理：
- `@neo:disable` 標記的 port（不再產生 table）
- NIC 從 `firewall=0` 改成 `firewall=1`（不再管理）
- VM 被刪除或 `.fw` 被移除
- NetDev 消失（下線 / destroy）

如果不做這個 cleanup，舊的 netdev table 會殘留在 kernel 裡持續過濾，變成
silent stale state。

### 10.5 Atomic apply

- **nftables**：生成 `.nft` 文字檔，先 `nft -c -f` 語法檢查，再 `nft -f` 原子載入
- **OVS**：用 cookie `0x4E30` 標記自己的 flow，apply 前 `ovs-ofctl del-flows cookie=0x4E30/-1`，然後 `ovs-ofctl add-flows`
- **Bridge isolation**：reconcile 模式 — 每次 apply 把所有非 isolated 的 linux bridge port 設為 `isolated off`，然後把該 isolated 的設為 `on`，避免 stale state

---

## 11. 檔案配置

### 11.1 安裝後的路徑

```
/usr/local/lib/pvefw_neo/                 # git repo (clone 或 dev symlink)
├── pvefw-neo                              # launcher script
├── pvefw-neo.service                      # systemd unit
├── pvefw_neo_src/                         # Python package
│   ├── __init__.py
│   ├── ir.py                              # IR 定義
│   ├── parser.py                          # .fw / @neo: tag 解析
│   ├── macros.py                          # Firewall.pm macro 解析 + fallback
│   ├── vmdevs.py                          # VM/CT device discovery
│   ├── compiler.py                        # parser 輸出 → IR
│   ├── nftgen.py                          # IR → nftables (linux bridge)
│   ├── ovsgen.py                          # IR → OVS flows
│   ├── bridge.py                          # bridge isolation reconcile
│   └── main.py                            # CLI + daemon loop
├── tests/
│   ├── setup.sh
│   ├── run_tests.sh                       # 36 個 nft 功能測試
│   ├── run_isolation_tests.sh             # 12 個 isolation 測試
│   └── teardown.sh
├── install.sh / upgrade.sh / uninstall.sh
└── DESIGN.md / README.md / README.zh_TW.md

/usr/local/bin/pvefw-neo                  → symlink → /usr/local/lib/pvefw_neo/pvefw-neo
/etc/systemd/system/pvefw-neo.service     → symlink → /usr/local/lib/pvefw_neo/pvefw-neo.service

/run/pvefw-neo/
├── ruleset.nft                           # 最近一次的 nftables 規則
├── ovs-<bridge>.flows                    # 最近一次的 OVS flows (per bridge)
└── state.json                            # 套用狀態
```

### 11.2 內部模組依賴

```
parser ──┐
         ├──> compiler ──> ir ──┬──> nftgen ──> nft -f
macros ──┤                     │
         │                     └──> ovsgen ──> ovs-ofctl
vmdevs ──┘

main: orchestration (CLI, daemon loop, backend dispatch)
bridge: external — kernel bridge isolated flag reconcile
```

`ir.py` 是中心，所有 backend 只認 IR，不認 parser 內部結構。新增 backend (例如 eBPF / VPP) 只需要寫一個新的 `*gen.py` 消費 `ir.Ruleset`。

---

## 11.5 OVS Backend Pipeline

OVS bridge 完全用 OpenFlow 規則實作，不依賴 Linux netfilter。

### Pipeline (5 個 OF tables)

```
封包進入 OVS bridge
   ↓
[Table 0: Ingress macfilter]
  • per in_port, dl_src 比對 (macspoof)
  • 不符 → drop
  • 符合 → resubmit(,10)
   ↓
[Table 10: Stateless filter]
  • per in_port, ipspoof / nodhcp / nora / @neo:notrack ACL
  • drop 或 resubmit(,20)
   ↓
[Table 20: Conntrack send]
  • arp → resubmit(,30)              ← ARP 不走 ct
  • ip  → ct(table=30)               ← 進 conntrack zone
  • ipv6 → ct(table=30)
   ↓
[Table 30: Forward OUT check]
  • per in_port stateful OUT 規則
  • 沒 match → resubmit(,31)
   ↓
[Table 31: Forward IN check]
  • arp → NORMAL
  • ct_state=+est → NORMAL           ← reply packets 短路
  • ct_state=+rel → NORMAL
  • ct_state=+inv → drop
  • per dl_dst stateful IN 規則 → ct(commit),NORMAL
  • 預設 → NORMAL (沒 STATEFUL 規則 = 透通)
```

### 跟 nftables 的差異

| 概念 | nftables | OVS |
|------|---------|-----|
| 介面比對 | `iifname/oifname` (字串，封包評估時解析) | `in_port` (數字，flow 安裝時綁定) |
| IN 方向 match | `oifname "tap100i0"` | `dl_dst=<vm_mac>` (因為 OVS 沒辦法 match output port) |
| Named set | nft set + `@setname` 引用 | 必須展開成 N 條 flows |
| `arp_op` 多值 | `arp operation { request, reply }` 一條 | 必須拆成兩條 flow（OVS 只能 match 單值） |
| Conntrack | hook 自動進 conntrack | 必須顯式 `ct(table=N)` 和 `ct(commit)` |
| isolated | kernel `bridge link set isolated on` | reg0[0] mark + dl_dst drop（語意 A 模擬） |

### Port lifecycle 處理

OVS ofport 在 VM stop/start 時會重新分配，舊 flow 變成 dangling。daemon 用 10 秒 polling 偵測這個情況（見 §10.2）。

### Cookie

所有 pvefw-neo 安裝的 flow 帶 `cookie=0x4E30`（"NE0" 編碼），以便用 `del-flows cookie=0x4E30/-1` 一次清除自己的 flow，不影響其他控制器的 flow。

---

## 12. 已知限制

| 限制 | 原因 | 影響 |
|------|------|------|
| REJECT → DROP | bridge family 不支援 reject | 對方只能 timeout |
| bridge conntrack ≥ kernel 5.3 | nftables 限制 | PVE 7+ 滿足 |
| Finger macro 佔用 | dummy rule 載體 | TCP/79 無人使用 |
| comment 欄位長度 | PVE WebUI 限制 | 複雜規則拆多條 |

---

## 13. 與官方 proxmox-firewall 的差異

| 功能 | proxmox-firewall（官方） | pvefw-neo |
|------|--------------------------|-----------|
| Per-port rules | ❌ per-VM | ✅ per-port |
| NOTRACK | ❌ 全 conntrack | ✅ per-rule |
| 非對稱路由 | ❌ conntrack 問題 | ✅ notrack rules |
| Multicast ratelimit | ❌ | ✅ |
| Port isolation | ❌ | ✅ |
| 修改 PVE code | ✅ | ❌ 完全外部 |

---

## 13.5 與官方 proxmox-firewall 的對比（詳細）

| 功能 | proxmox-firewall (官方) | pvefw-neo |
|------|------------------------|-----------|
| 後端 | nftables only | nftables + OVS |
| Per-port rules | ❌ per-VM | ✅ per-port (per vNIC) |
| NOTRACK | ❌ 全 conntrack | ✅ per-rule (`@neo:notrack`) |
| 非對稱路由 | ❌ conntrack drop invalid | ✅ STATELESS rules 繞過 ct |
| Multicast ratelimit | ❌ | ✅ `@neo:mcast_limit` |
| Port isolation | ❌ | ✅ `@neo:isolated` (語意 A) |
| MAC spoof per-port | ❌ per-VM | ✅ `@neo:macspoof` per-vNIC |
| IP spoof per-port | ❌ per-VM | ✅ `@neo:ipspoof` per-vNIC + 自帶 ARP/NDP 防護 |
| OVS bridge | ❌ | ✅ |
| 修改 PVE code | ✅ Rust 改 PVE 內部 | ❌ 完全外部，只讀 .fw |

---

## 14. 實作狀態

### Phase 1：核心 ✅
- [x] `parser.py`：.fw 解析 + @neo: tag 解析 + ALIASES + IPSET + GROUP
- [x] `macros.py`：Firewall.pm runtime 解析 + hardcoded fallback
- [x] `vmdevs.py`：VM/CT device discovery（tap/veth, MAC, bridge）
- [x] `compiler.py`：parser → IR
- [x] `ir.py`：後端無關中間表示
- [x] `nftgen.py`：IR → nftables (linux bridge)
- [x] `main.py`：CLI `--dry-run` / `--apply` / `--dump-ir`

### Phase 2：daemon + sugar ✅
- [x] Sugar tag 展開：`@neo:macspoof`, `ipspoof`, `nodhcp`, `nora`, `nondp`
- [x] inotify watch (`/etc/pve/firewall/`, `/etc/pve/{qemu-server,lxc}/`)
- [x] 2 秒 debounce
- [x] systemd service + preflight check
- [x] `--apply` 自動 backend dispatch

### Phase 3：進階 ✅
- [x] `@neo:mcast_limit` (netdev ingress rate limit)
- [x] `@neo:isolated` (kernel `bridge link isolated`)
- [x] alias / ipset / security group 完整支援
- [x] OVS backend (`ovsgen.py`)
- [x] OVS port topology polling (10 秒)
- [x] `@neo:isolated` 在 OVS 用 reg0 mark + dl_dst drop 模擬

### 測試覆蓋

| 測試套件 | 數量 | 狀態 |
|---------|------|------|
| nft functional + structural | 36 | ✅ all pass |
| OVS functional | 4 | ✅ all pass |
| Isolation (Linux + OVS) | 12 | ✅ all pass |
| **總計** | **52** | |

測試腳本：`tests/run_tests.sh`, `tests/run_isolation_tests.sh`
