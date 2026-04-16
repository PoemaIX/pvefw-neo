# pvefw-neo

為解決 Proxmox VE 設計痛點，重新實作的防火牆

不修改 PVE 原始碼，不修改設定文件。  
單純讀取 .fw 並生成相應規則

> 🌐 [English](README.md)  
> 🏗️ 架構與內部細節：[DESIGN.md](DESIGN.md)
---

解決了以下痛點:  

1. 不使用 `tap → 🧱fwbr🧱→ fwpr ↔ fwln → vmbr0` 這套架構
    * 原生 iptables 能力有限，只好引入 `fwbr` 在上面做防火牆
    * 但也因此導致封包要經過5個虛擬網卡，嚴重浪費
2. 針對 linux bridge ，使用 nftables bridge table
    * 改用 `tab🧱 -> vmbr0` 直達
3. 針對 ovs bridge，使用 openflow rules 原生過濾協議
    * 避免了 `fwbr` ，繞回 linux kernel 走 nftables 的開銷  
4. 所有規則都改成 per-port 單獨設定，不像 PVE 原生防火牆只能整台 VM 啟用/停用
    1. macspoof : 只允許特定 src mac ，阻止 mac 偽造
    2. ipspoof : 只允許特定 src ip ，阻止 ip 偽造
    3. nodhcp : 阻止 DHCP server
    4. nora : 阻止發送 RA
---

目前有以下限制:

1. REJECT 規則無效，會替換成 DROP
    * nftables 無法在 `bridge` family 做 REJECT ， `inet` 才有
    * 但要用 `inet` 只能用回 `fwbr` 架構，只好放棄
2. **PVE 必須打開 nftables (tech preview)**
    * 就算 node firewall / vm firewall 停用也要打開
    * 因為 iptables 模式會導致 `pve-firewall` 生成規則(就算 node/vm 防火牆關閉也會生成)
    * 因此 `pvefw-neo`和 pve-firewall 的 iptables 模式不相容，必須改用 nftables 模式
3. VM nic **必須關閉防火牆**
    * `pvwfw-neo` 的設計邏輯是 nic 打勾的，交由 `proxmox-firewall` 管理。
    * 而且無論 cluster/node/vm 防火牆關閉與否，nic 防火牆只要打勾，ovs 都會生成 `fwbr` ，會導致 openflow 無法套用
    * 為避免衝突，只有 nic 沒打勾的，才由 `pvefw-neo` 控制
        * `pvefw-neo` 自己的 port level 啟用控制則寫在 `@neo:disable`
---

運作方式:  

1. 讀取現有的 PVE `/etc/pve/firewall/*.fw` 設定檔
2. 前處理
3. 編譯成 IR
4. 查詢 port 屬於 linux bridge 還是 ovs，呼叫各自後端
5. 編譯成 nftables / openflow rules

---

## 前置需求

不論是否啟用 PVE 原生防火牆，**主機上必須打開 nftables (tech preview)**：

PVE WebUI → **Host → Firewall → Options → nftables (tech preview) → yes**

---

## 安裝

```bash
curl -sSL https://raw.githubusercontent.com/PoemaIX/pvefw-neo/refs/heads/main/install.sh | bash
```
腳本會詢問是否遷移設定檔

啟用防火牆
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

使用 **PVE WebUI**（VM → Firewall) 並編輯防火牆規則即可  
daemon 會在數秒內偵測變動並重新套用。

1. 原本的 PVE 規則，可直接使用
2. pvefw-neo 提供兩類擴充，都放在 PVE 規則的 **comment 欄位**
中，統一以 `@neo:` 為前綴

### 第一類 — Extension rules

這類規則是 PVE native firewall 沒提供的功能  
因為 PVE WebUI 沒有對應欄位，我們無法直接編輯  
所以我們借用幾十年前已經沒人用的 **Finger** 協定（TCP/79）作為載體(並標記為 **disabled**（PVE 會忽略)，把真正的規則寫在 comment 欄位  

**WebUI 操作步驟**（`VM → Firewall → Add`)

首先按照以下欄位填入(所有 extension rule 共用的固定骨架)：

| 欄位 | 值 |
|---|---|
| Direction | `out` |
| **Enable** | **不要打勾** ← 重要 |
| Action | `DROP` |
| Macro | `Finger` |
| Source / Comment | 依 tag 填寫（見下） |


| Tag | 效果 |
|---|---|
| `@neo:disable` | 關閉 pvefw-neo 對此 port 的管理，該 port 上其他規則全部忽略，流量直接放行。<br>等同 PVE 的 "port-level firewall disable"(之所以不能用 PVE GUI 那個旗標：打勾之後 PVE 會建立 fwbr，我們不能接受) |
| `@neo:isolated` | 設定 kernel bridge `isolated on`（Linux）或對應的 OF 規則（OVS）。<br>同 bridge 上兩個 isolated port 互相不通；isolated ↔ 非 isolated 可通 |
| `@neo:macspoof [macs]` | 只允許列表中的 source MAC 通過，其餘 drop。沒給參數 = 自動從 VM config 讀。 |
| `@neo:ipspoof` | 只允許列出的 source IP 通過（把 IP 清單填在 **Source** 欄位）。自動處理 ARP / IPv4 / IPv6（含 DAD、link-local、白名單）。 |
| `@neo:nodhcp` | 阻止 VM 當 DHCP server（drop UDP sport 67/547 → dport 68/546）。 |
| `@neo:nora` | 阻止外送 IPv6 Router Advertisement。 |
| `@neo:nondp` | 阻止外送 IPv6 NS/NA（防偽造 NDP）。 |
| `@neo:mcast_limit <pps>` | 對 netdev ingress 的 multicast 封包做 rate limit。 |
| `@neo:ct invalid` | 在此 port 上丟棄 `ct_state=invalid` 封包（IN + OUT 都擋）。未設時 invalid 封包（如非對稱路由 return traffic）會被正常規則接受，等同 PVE 的 `nf_conntrack_allow_invalid=0`。 |

**範例**（每條規則只列出需要填的欄位，其他欄位照上面的骨架）：

**ipspoof** — 只允許部分 source IP：

| 欄位 | 值 |
|---|---|
| Source | `192.168.5.6,192.168.5.7,192.168.20.0/24` |
| Comment | `@neo:ipspoof` |

**macspoof** — 只允許部分 source MAC：

| 欄位 | 值 |
|---|---|
| Comment | `@neo:macspoof 22:44:66:88:aa:bb,22:44:66:88:aa:cc` |

**macspoof** — 自動從 VM config 讀取 MAC（不給參數）：

| 欄位 | 值 |
|---|---|
| Comment | `@neo:macspoof` |

**nodhcp** — 禁止此 VM 成為 DHCP server：

| 欄位 | 值 |
|---|---|
| Comment | `@neo:nodhcp` |

**mcast_limit** — multicast 限速 100 pps：

| 欄位 | 值 |
|---|---|
| Comment | `@neo:mcast_limit 100` |

### 第二類 — Decorator tags

Decorator 附加在**真正的** (非 Finger) PVE 規則上。有的改變規則行為，有的限縮匹配範圍。  
用真的 macro / action，WebUI 中要**打勾 enable**

#### 行為改變類

| Tag | 效果 |
|---|---|
| `@neo:noct` | 在 **conntrack 之前**評估，純 per-packet 匹配<br>別名：`@neo:stateless` |
| `@neo:ct` | stateful 規則，匹配所有到達 `ct_state` 的封包<br>別名：不寫。<br>沒寫 `@neo:noct` 或 `@neo:ct` ，預設就是這個|
| `@neo:ct new` | Stateful 規則，匹配 `ct_state=new` 的封包。 |
| `@neo:ct invalid` | Stateful 規則，匹配 `ct_state=invalid` 的封包 |

#### 限縮範圍類

| Tag | 效果 |
|---|---|
| `@neo:srcmac in <mac1,mac2>` | 此規則只套用到 source MAC 等於 `<mac>` 的封包  |
| `@neo:srcmac notin <mac1s>` | 此規則只套用到 source MAC 不等於 `<mac>` 的封包 |
| `@neo:srcmac bitmask <mask>` | 以 bitmask 匹配 source MAC（`field & mac == mac`） |
| `@neo:dstmac in <mac1,mac2>` | 此規則只套用到 destnation MAC 等於 `<mac>` 的封包 |
| `@neo:dstmac notin <mac1s>` | 此規則只套用到 destnation MAC 不等於 `<mac>` 的封包 |
| `@neo:dstmac bitmask <mask>` | 以 bitmask 匹配 destnation MAC（`field & mac == mac`）。 |
| `@neo:vlan <untagged\|vid1,vid2>` | 只套用到指定 VLAN 的流量<br>用於 trunk port 給 VM 時，規則只作用在內層某 VLAN |
| `@neo:rateexceed <pps>` | 只匹配規則條件中**超過** `<pps>` 的部分<br>rate 內的封包不匹配，落到下一條規則<br>**僅限 `@neo:stateless`**，`@neo:ct` 規則不支援。 |

**範例** — ：

**Stateless Src MAC 白名單**：

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `DROP` | *(無)* | *(無)* | `@neo:stateless @neo:srcmac notin aa:bb:cc:dd:ee:ff` |

**Stateless Src IP 白名單**：

| IPSet | IPs |
|---|---|
`nonself`|`!192.168.66.1/32`

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `DROP` | *(無)* | `+guest/nonself` | `@neo:stateless` |

**VLAN-scoped** stateless 規則（trunk port，只套用在內層 VLAN 20）：

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `ACCEPT` | *(無)* | `10.0.0.0/24` | `@neo:stateless @neo:vlan 20` |

**丟棄 ct invalid**（per-port，stateful）：

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `in`  | `DROP` | *(無)* | *(無)* | `@neo:ct invalid` |
| `out` | `DROP` | *(無)* | *(無)* | `@neo:ct invalid` |

**只接受連出，不開放連入**(拒絕入方向的 `ct_state=new` )：

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `in`  | `DROP` |  *(無)* | *(無)* | `@neo:ct new` |

### 語法糖

Extension rules 中，有相當多的規則期實是語法糖，編譯期會展開：  
`macspoof`、`ipspoof`、`nodhcp`、`nora`、`nondp`、`mcast_limit`



語法糖
```
# @neo:macspoof
```
展開後:

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `DROP` | *(無)* | *(無)* | `@neo:noct @neo:srcmac notin aa:bb:cc:dd:ee:ff`<br> mac自動從網卡上面抓 |

語法糖
```
# @neo:ipspoof 192.168.16.3,192.168.30.0/24
```
展開後:
```
[IPSET vm100_ipspoof_1]

!192.168.1.2
!192.168.30.0/24
```

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `DROP` | *(無)* | `+guest/vm100_ipspoof_1` | `@neo:noct` |

語法糖: 阻止 VM 當 DHCP server
```
# @neo:nodhcp
```
展開後（v4 + v6 各一條）:

| Direction | Action | Source | Comment |
|---|---|---|---|
| `out` | `DROP` | *(無)* | `@neo:noct` + match `udp sport 67 dport 68` (v4) |
| `out` | `DROP` | *(無)* | `@neo:noct` + match `udp sport 547 dport 546` (v6) |

語法糖: 阻止 VM 發送 Router Advertisement
```
# @neo:nora
```
展開後:

| Direction | Action | Source | Comment |
|---|---|---|---|
| `out` | `DROP` | *(無)* | `@neo:noct` + match `icmpv6 type nd-router-advert` |

語法糖: 阻止 VM 發送 NDP (Neighbor Solicit / Advert)
```
# @neo:nondp
```
展開後:

| Direction | Action | Source | Comment |
|---|---|---|---|
| `out` | `DROP` | *(無)* | `@neo:noct` + match `icmpv6 type {nd-neighbor-solicit, nd-neighbor-advert}` |

語法糖: 限制 multicast 封包最多 100 pps
```
# @neo:mcast_limit 100
```
展開後:

| Direction | Action | Macro | Source | Comment |
|---|---|---|---|---|
| `out` | `DROP` | *(無)* | *(無)* | `@neo:noct @neo:rateexceed 100 @neo:dstmac bitmask 01:00:00:00:00:00` |

所以編譯流程是：

1. 語法糖展開（之後只剩 `@neo:disable` / `@neo:isolated` 這兩個原生 extension rule）。
2. Parser + decorator → IR。
3. IR → 後端（nftables 或 OVS flows）。
4. 套用。

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
