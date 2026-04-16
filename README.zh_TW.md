# pvefw-neo

為 Proxmox VE 設計的 nftables / OVS 防火牆管理器。支援 per-port
macspoof / ipspoof、stateless 旁路（解決非對稱路由）、OVS bridge、多後端
（Linux bridge 走 nftables，OVS 走 OpenFlow），直接讀取既有的 PVE
`.fw` 設定檔。

> 🌐 [English](README.md)
> 🏗️ 架構與內部細節：[DESIGN.md](DESIGN.md)

---

## 前置需求

不論是否啟用 PVE 原生防火牆，**主機上必須打開 nftables (tech preview)**：

PVE WebUI → **Host → Firewall → Options → nftables (tech preview) → yes**

pvefw-neo 與原生防火牆並存，不修改 PVE 原始碼。詳細的共存模型
(node-off + nftables mode) 以及為何 port-level 的 `firewall=` 旗標
必須留空或 `0`，請見 [DESIGN.md](DESIGN.md)。

---

## 安裝

```bash
curl -sSL https://raw.githubusercontent.com/PoemaIX/pvefw-neo/refs/heads/main/install.sh | bash
```

`install.sh` 是互動式的：安裝相依套件、建立 symlink、詢問是否把
`host.fw` 設為 `enable=0, nftables=1`、詢問是否把既有 `firewall=1`
的 vNIC 全部改成 `firewall=0`。接著啟用 daemon：

```bash
systemctl enable --now pvefw-neo
```

升級 / 解除安裝：

```bash
bash /usr/local/lib/pvefw_neo/upgrade.sh
bash /usr/local/lib/pvefw_neo/uninstall.sh
```

---

## 使用方式

用 **PVE WebUI**（VM → Firewall）或直接編輯 `/etc/pve/firewall/*.fw`
管理規則；daemon 會在數秒內偵測變動並重新套用。

標準 PVE 規則可直接使用：所有 macro、`[ALIASES]`、`[IPSET]`、
`[GROUP]`、`policy_in/out`、per-vNIC `-i netN`、protocol/port 匹配、
`-icmp-type`、`-log <level>` 都支援。

此外 pvefw-neo 提供兩類規則擴充，都放在 PVE 規則的 **comment 欄位**
中，統一以 `@neo:` 為前綴。

### 第一類 — Extension rules（`@neo:` 語法糖）

這類規則是 PVE GUI 沒提供的功能。因為它們不對應任何真實協定，我們
借用幾十年前已經沒人用的 **Finger** 協定（TCP/79）作為載體，並把載體
規則在 PVE 裡標記為 **disabled**（PVE 會忽略它），真正的意思寫在
comment 欄位裡。

**WebUI 操作步驟**（`VM → Firewall → Add`）— 所有 extension rule 共
用的固定骨架：

| 欄位 | 值 |
|---|---|
| Direction | `out` |
| **Enable** | **不要打勾** ← 重要 |
| Action | `DROP` |
| Macro | `Finger` |
| Source / Comment | 依 tag 填寫（見下） |

> PVE 透過在底層 `.fw` 行首加 `|` 表示 rule disabled — 這正是我們想要
> 的：PVE 自己跳過它，pvefw-neo 接手。

| Tag | 效果 |
|---|---|
| `@neo:disable` | **除錯開關。** 關閉 pvefw-neo 對此 port 的管理，該 port 上其他規則全部忽略，流量直接放行。等同 PVE 的 "port-level firewall disable"（之所以不能用 PVE GUI 那個旗標：勾掉之後 PVE 會建立 fwbr，我們不能接受）。 |
| `@neo:isolated` | 設定 kernel bridge `isolated on`（Linux）或對應的 OF 規則（OVS）。同 bridge 上兩個 isolated port 互相不通；isolated ↔ 非 isolated 仍可通。 |
| `@neo:macspoof [mac,...]` | 只允許列表中的 source MAC 通過，其餘 drop。沒給參數 = 自動從 VM config 讀。 |
| `@neo:ipspoof` | 只允許列出的 source IP 通過（把 IP 清單填在 **Source** 欄位）。自動處理 ARP / IPv4 / IPv6（含 DAD、link-local、白名單）。 |
| `@neo:nodhcp` | 阻止 VM 當 DHCP server（drop UDP sport 67/547 → dport 68/546）。 |
| `@neo:nora` | 阻止外送 IPv6 Router Advertisement。 |
| `@neo:nondp` | 阻止外送 IPv6 NS/NA（防偽造 NDP）。 |
| `@neo:mcast_limit <pps>` | 對 netdev ingress 的 multicast 封包做 rate limit。 |
| `@neo:ctinvalid` | 在此 port 上丟棄 `ct_state=invalid` 封包（IN + OUT 都擋）。未設時 invalid 封包（如非對稱路由 return traffic）會被正常規則接受，等同 PVE 的 `nf_conntrack_allow_invalid=1`。 |

**範例**（每條規則只列出需要填的欄位，其他欄位照上面的骨架）：

**ipspoof** — 只允許部分 source IP：

| Source | `192.168.5.6,192.168.5.7,192.168.20.0/24` |
|---|---|
| Comment | `@neo:ipspoof` |

**macspoof** — 只允許部分 source MAC：

| Source | *(留空)* |
|---|---|
| Comment | `@neo:macspoof 22:44:66:88:aa:bb,22:44:66:88:aa:cc` |

**macspoof** — 自動從 VM config 讀取 MAC（不給參數）：

| Source | *(留空)* |
|---|---|
| Comment | `@neo:macspoof` |

**nodhcp** — 禁止此 VM 成為 DHCP server：

| Source | *(留空)* |
|---|---|
| Comment | `@neo:nodhcp` |

**mcast_limit** — multicast 限速 100 pps：

| Source | *(留空)* |
|---|---|
| Comment | `@neo:mcast_limit 100` |

### 第二類 — Decorator tags

Decorator 附加在**真正的** (非 Finger) PVE 規則上。有的改變規則行
為，有的限縮匹配範圍。

#### 規則評估模式

| Tag | 效果 |
|---|---|
| `@neo:stateless` | 在 **conntrack 之前**評估，純 per-packet 匹配。放在 `bridge raw_prerouting` (nft) 或 table 10 (OVS)。沒有 ct state 概念。順序很重要 — 具體的先寫，catch-all 最後。別名：`@neo:noct`、`@neo:notrack`。 |
| `@neo:ct new` | Stateful 規則，但只匹配 `ct_state=new` 的封包。`invalid` 封包（如非對稱路由 return traffic）不匹配，落到下一條規則。 |
| `@neo:ct invalid` | Stateful 規則，只匹配 `ct_state=invalid` 的封包。搭配 `DROP` 可 per-rule 精細控制（比 `@neo:ctinvalid` sugar 更靈活，可搭配 `@neo:vlan` 等）。 |
| *(不寫)* | 預設：stateful 規則匹配**所有**到達 per-port chain 的封包（`new` + `invalid`）。`established`/`related` 已被 global accept 攔走，永遠不會到達你的規則。 |

#### 額外匹配類（限縮範圍）

| Tag | 效果 |
|---|---|
| `@neo:srcmac exact <mac>` | 此規則只套用到 source MAC 等於 `<mac>` 的封包。適用於 VM 內有多個 MAC、不同 MAC 套用不同規則的情況。 |
| `@neo:srcmac bitmask <mac>` | 以 bitmask 匹配 source MAC（`field & mac == mac`）。 |
| `@neo:dstmac exact <mac>` | 只套用到 dst MAC 等於 `<mac>` 的封包。 |
| `@neo:dstmac bitmask <mac>` | bitmask 匹配 dst MAC。 |
| `@neo:vlan <vid\|untagged\|vid1,vid2>` | 只套用到指定 VLAN 的流量。用於 trunk port 給 VM 時，規則只作用在內層某 VLAN。 |
| `@neo:rateexceed <pps>` | 只匹配規則條件中**超過** `<pps>` 的部分；rate 內的封包落到下一條規則。**僅限 `@neo:stateless`**，stateful 規則不支援。 |

**範例** — decorator 附加在**真實**的 PVE 規則上：用真的 macro / action，
WebUI 中要**打勾 enable**（不是 `|` disabled）：

**Stateless per-MAC 白名單** + catch-all drop：

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `ACCEPT` | *(無)* | `10.0.0.10/32` | `@neo:stateless @neo:srcmac exact aa:bb:cc:dd:ee:ff` |
| `out` | `DROP`   | *(無)* | *(無)*          | `@neo:stateless` |

**VLAN-scoped** stateless 規則（trunk port，只套用在內層 VLAN 20）：

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `ACCEPT` | *(無)* | `10.0.0.0/24` | `@neo:stateless @neo:vlan 20` |

**丟棄 ct invalid**（per-port，stateful）：

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `in`  | `DROP` | *(無)* | *(無)* | `@neo:ct invalid` |
| `out` | `DROP` | *(無)* | *(無)* | `@neo:ct invalid` |

**只接受 new 連線**（拒絕 invalid return traffic）：

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `in`  | `ACCEPT` | `SSH` | *(無)* | `@neo:ct new` |

### 語法糖 = decorator 組合

`macspoof`、`ipspoof`、`nodhcp`、`nora`、`nondp`、`mcast_limit`、
`ctinvalid` 實際上都是 decorator 組合的**語法糖**。編譯期會展開：

```
# @neo:macspoof mac1,mac2
→ 單一 stateless 規則：src_mac ∉ {mac1, mac2} 就 drop

# @neo:ipspoof ip1,cidr2
→ 3 條 stateless 規則 (ARP/IPv4/IPv6)：src_ip ∉ 允許清單就 drop
  （內部使用 pure-nomatch ipset）

# @neo:mcast_limit 100
→ 單一 stateless 規則：multicast 超過 100 pps 就 drop

# @neo:ctinvalid
→ IN DROP # @neo:ct invalid
  OUT DROP # @neo:ct invalid
```

所以編譯流程是：

1. 語法糖展開（之後只剩 `@neo:disable` / `@neo:isolated` 這兩個原生
   extension rule，其他都是「正常規則 + decorator」）。
2. Parser + decorator → IR。
3. IR → 後端（nftables 或 OVS flows）。
4. 套用。

完整 pipeline、IR 契約、後端實作請見 [DESIGN.md](DESIGN.md)。

---

## CLI

```bash
pvefw-neo --apply             # 套用規則（自動分派 nft + OVS）
pvefw-neo --dry-run           # 印出產生的 nftables ruleset
pvefw-neo --dump-ir           # 印出 IR（除錯用）
pvefw-neo --dump-ovs vmbr2    # 印出某個 bridge 的 OVS flows
pvefw-neo --flush             # 移除所有 pvefw-neo 狀態
pvefw-neo --preflight-check   # 檢查 host.fw enable=0 + nftables=1
```

---

## 限制

| 限制 | 原因 |
|---|---|
| `REJECT` 變成 `DROP` | `bridge` family 和 OVS 都不支援 REJECT，對端只會 timeout。 |
| `Finger` macro 保留作為語法糖載體 | TCP/79 實際沒人用。 |
| OVS isolation 需要 ≥2 個 isolated port 才生效 | 「兩個 isolated port 互相不通」— 只有一個 isolated port 沒意義。 |
| `@neo:rateexceed` 只支援 `@neo:stateless` | stateful + rate limit 的語意在 OVS meter 模型下無法乾淨表達。 |
| OVS 後端以 CIDR 預先相減展開 ipset | 流量表大小隨 ipset 成員數成長；小集合沒問題，大集合編譯會慢。 |
| `@neo:` 標籤寫在 comment 欄位 | PVE WebUI 的 comment 欄有長度限制，複雜規則要拆多行。 |

---

## 疑難排解

```bash
systemctl status pvefw-neo
journalctl -u pvefw-neo -f

pvefw-neo --dump-ir              # 後端無關的 IR
pvefw-neo --dry-run              # nftables 文字
pvefw-neo --dump-ovs vmbr2       # 某個 bridge 的 OVS flows

nft list table bridge pvefw-neo
ovs-ofctl dump-flows vmbr2 | grep "cookie=0x4e30"

pvefw-neo --flush && systemctl restart pvefw-neo
```

---

## 授權

請見 [LICENSE](LICENSE)。
