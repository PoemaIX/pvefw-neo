# pvefw-neo

針對 Proxmox VE 的獨立 nftables / OVS 防火牆管理器，補足 PVE 內建防火牆的缺陷：
per-port 規則、NOTRACK (stateless) 繞過 conntrack（解非對稱路由問題）、
per vNIC 的 MAC/IP 防偽、port isolation、OVS bridge 支援。

> 🌐 [English version](README.md)
> 🏗️ 架構與運作原理：[DESIGN.md](DESIGN.md)

---

## 為什麼?

PVE 內建防火牆有三個根本問題：

1. **強制 conntrack** — 非對稱路由（BGP、multipath）的封包會被當作 `invalid` 丟掉。
   即使在 port 層級關閉防火牆也無解，因為全域的 `drop invalid` 規則仍然套用。
2. **五個安全規則只能 per-VM**（DHCP / RA / IP spoof / MAC spoof / NDP）。
   無法做到「net0 禁止當 DHCP server，net1 允許」。
3. **沒有 NOTRACK 路徑** — 純 stateless ACL（src-ip、src-mac）也要走 conntrack table，
   浪費 CPU 跟 hash 空間。

pvefw-neo 透過讀取相同的 `.fw` 設定檔、自己生成獨立的 nftables / OVS 規則來解決。
提供 per-port 控制、NOTRACK 繞過，以及透過規則 comment 中 `@neo:` tag 的擴充機制。

**完全不修改 PVE 程式碼** — 只讀取 `/etc/pve/firewall/*.fw` 和
`/etc/pve/{qemu-server,lxc}/*.conf`。

---

## 狀態

| | |
|---|---|
| **後端** | nftables (Linux bridge), OVS bridge |
| **自動 reload** | inotify 監聽 .fw / .conf + 10 秒 OVS port poll |
| **測試** | 52/52 通過 (36 nft + 4 OVS + 12 isolation) |
| **依賴** | `python3-nftables`, `python3-inotify`, 選用 `openvswitch-switch` |

---

## 安裝

```bash
git clone https://github.com/PoemaIX/pvefw-neo.git /tmp/pvefw-neo
cd /tmp/pvefw-neo
bash install.sh
```

`install.sh` 會：

1. `apt install python3-nftables python3-inotify`
2. `git clone https://github.com/PoemaIX/pvefw-neo.git /usr/local/lib/pvefw_neo`
3. Symlink launcher → `/usr/local/bin/pvefw-neo`
4. Symlink systemd unit → `/etc/systemd/system/pvefw-neo.service`
5. 跑一次驗證

### 開發模式（symlink 而非 clone）

```bash
DEV_LINK=/path/to/your/pvefw-neo bash install.sh
```

把 `/usr/local/lib/pvefw_neo` 軟連結到你的 working dir，編輯立即生效。

### 停掉衝突的服務

`pvefw-neo` 要求 PVE 內建防火牆**已關閉**：

```bash
systemctl disable --now pve-firewall.service proxmox-firewall.service
```

如果這兩個還在跑，daemon 會拒絕啟動。

### 啟用 daemon

```bash
systemctl enable --now pvefw-neo
journalctl -u pvefw-neo -f          # 看 log
```

daemon 會：
- 監聽 `/etc/pve/firewall/`、`/etc/pve/qemu-server/`、`/etc/pve/lxc/` 的寫入事件
  （2 秒 debounce 合併）
- 每 10 秒輪詢 OVS port 變動
- 自動套用變更

---

## 升級

```bash
bash /usr/local/lib/pvefw_neo/upgrade.sh
```

會在安裝目錄執行 `git pull` 並 restart daemon。

---

## 移除

```bash
bash /usr/local/lib/pvefw_neo/uninstall.sh
```

會：
1. 停止 + disable daemon
2. 清除所有 pvefw-neo 的 nftables 規則和 OVS flows
3. 移除 symlink
4. 刪除 `/usr/local/lib/pvefw_neo/`

`/etc/pve/firewall/` 內的 `.fw` 檔**不會動**。要恢復 PVE 自己的防火牆需要手動 enable。

---

## 使用方法

### CLI 命令

```bash
pvefw-neo --apply             # 套用規則 (自動派發 nft + OVS)
pvefw-neo --dry-run           # 輸出 nftables 規則文字
pvefw-neo --dump-ir           # 輸出 IR 中間表示 (除錯用)
pvefw-neo --dump-ovs vmbr2    # 輸出某個 OVS bridge 的 flows
pvefw-neo --flush             # 清除所有 pvefw-neo 狀態 (nft + OVS)
pvefw-neo --preflight-check   # 檢查 PVE firewall 是否已停
pvefw-neo --daemon            # 啟動 daemon (給 systemd 用)
```

正常使用時只需要啟動 systemd service，其他都自動。

### 編輯防火牆規則

透過 **PVE WebUI** 編輯（Datacenter → Firewall，或 VM/CT → Firewall），
或者直接編輯 `/etc/pve/firewall/*.fw`。daemon 會在 2-3 秒內自動套用變更。

---

## 規則類型

pvefw-neo 同時支援**普通 PVE 規則**和 **`@neo:` 擴充 tag**。

### 1. 普通 PVE 規則

PVE 標準語法可以直接用，pvefw-neo 讀的是相同的設定檔：

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

支援的功能：
- 所有標準 macros（SSH, HTTP, HTTPS, DNS, BGP, BitTorrent, …）—
  runtime 從 `/usr/share/perl5/PVE/Firewall.pm` 解析
- `[ALIASES]` — 在 `-source` / `-dest` 用名稱引用
- `[IPSET name]` — 用 `+name` 或 `+guest/name` 引用
- `[GROUP name]` security group — 引用處 inline 展開
- `policy_in` / `policy_out` — compiler 轉成顯式 catch-all 規則
- `-i net0` per-vNIC 範圍限定
- 協定 + port 比對 (`-p tcp -dport 80`、`-sport 1024:65535`、port list `-dport 80,443`)

### 2. `@neo:` 擴充 tag

寫在規則的 **comment 欄位**。分兩類：

#### 語法糖（sugar）— 一行解決常見場景

語法糖會展開成多條底層規則。它用 Finger dummy 規則作為載體
（`-enable 0` 讓 PVE 自己忽略）：

```ini
[RULES]
# net0 的防偽：
|OUT Finger(DROP) -enable 0 -i net0 # @neo:macspoof
|OUT Finger(DROP) -enable 0 -i net0 # @neo:ipspoof 10.0.0.10/32
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nodhcp
|OUT Finger(DROP) -enable 0 -i net0 # @neo:nora

# Port isolation：
|OUT Finger(DROP) -enable 0 -i net2 # @neo:isolated
```

| 語法糖 | 效果 |
|--------|------|
| `@neo:macspoof [mac]` | 只允許指定的源 MAC，其他丟掉。沒給 MAC 時自動從 VM config 讀。 |
| `@neo:ipspoof <ip,...>` | 只允許列出的源 IP。自動處理 ARP / IPv4 / IPv6（含 DAD、link-local、白名單）。 |
| `@neo:nodhcp` | 阻止 VM 當 DHCP server（drop UDP src-port 67/547 dst-port 68/546）。 |
| `@neo:nora` | 阻止 IPv6 Router Advertisement。 |
| `@neo:nondp` | 阻止 IPv6 Neighbor Solicit/Advert（防偽 NDP）。 |
| `@neo:mcast_limit <pps>` | netdev ingress 對 multicast 封包做 rate limit。 |
| `@neo:isolated` | 設定 kernel bridge `isolated on`（Linux）或對應的 OF 規則（OVS）。兩個 isolated port 互相不通；isolated ↔ 非 isolated 仍可通。 |

#### 底層原語（primitive）— 附加在真正規則上做精細控制

```ini
[RULES]
# NOTRACK ACL 用於非對稱路由（不走 conntrack）
|OUT ACCEPT -i net1 -source 10.0.0.0/24    # @neo:notrack
|OUT ACCEPT -i net1 -source 169.254.0.0/16 # @neo:notrack
|OUT DROP   -i net1                        # @neo:notrack

# MAC + IP 組合比對 (notrack)
|OUT ACCEPT -i net0 -source 10.0.0.10/32 # @neo:notrack @neo:mac aa:bb:cc:dd:ee:ff

# VLAN 範圍限定
|OUT ACCEPT -i net0 -source 10.0.0.0/24 # @neo:notrack @neo:vlan 20
```

| 原語 | 效果 |
|------|------|
| `@neo:notrack` | 標記為 stateless 規則。放進 `bridge raw_prerouting` (nft) 或 table 10 (OVS)。完全繞過 conntrack。**順序很重要** — 寫精細規則在前，catch-all 在後。 |
| `@neo:mac <src> [dst]` | 加 MAC 來源/目的比對。`*` = any。配合 `@neo:notrack` 使用。 |
| `@neo:vlan <vid|untagged|vid1,vid2>` | 加 VLAN tag 比對。`untagged` = 沒有 802.1Q header。 |

### STATELESS vs STATEFUL 的選擇

| 用 STATELESS (`@neo:notrack` / sugar) | 用 STATEFUL (普通規則) |
|-----------|-----------|
| 防偽（`@neo:ipspoof`、`macspoof`） | 開放服務，期望回應流量自動通過 |
| 非對稱路由（BGP multipath） | 一般 server 防火牆（允許 X 連 SSH，其他擋掉） |
| 「只有這幾個源 IP 可以送」這類 ACL | 任何想要 conntrack O(1) 短路的場景 |
| 純 L2 / L3 過濾，不在乎回應流量 | NAT 類似情境（PVE 自己不 NAT，但有狀態防火牆會放行 reply） |

**不要混用錯誤**：在某 port 上寫 `@neo:notrack DROP` catch-all 會擋掉
所有 stateful 服務的入站連線。原因：NOTRACK 比 conntrack 早執行，
stateful 框架根本沒機會評估那些被 NOTRACK 擋掉的回應封包。

---

## Backend 自動派發

pvefw-neo 自動偵測每個 VM port 在 Linux bridge 還是 OVS bridge，
用對應的 backend 套用規則：

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

一台 VM 的 `net0` 在 `vmbr1`（Linux）、`net1` 在 `vmbr2`（OVS）完全支援 —
每個 port 各自走對應的 backend。

---

## 已知限制

| 限制 | 原因 |
|------|------|
| `REJECT` 變成 `DROP` | nftables bridge family 不支援 REJECT，OVS 也不支援。對方只能 timeout。 |
| bridge family conntrack 需要 kernel ≥ 5.3 | nftables 限制。PVE 7+ 都符合。 |
| `Finger` macro 被佔用作為 sugar 載體 | TCP/79 實務上沒人用。 |
| OVS isolation 至少要 2 個 isolated port 才生效 | 語意 A：「兩個 isolated port 不能互通」 — 單一 isolated port 沒意義。 |
| `@neo:` tag 寫在 comment 欄位 | PVE WebUI 的 comment 欄有長度限制。複雜規則拆成多條。 |

---

## 除錯

```bash
# Daemon 狀態 + log
systemctl status pvefw-neo
journalctl -u pvefw-neo -f

# 檢查產生的規則
pvefw-neo --dump-ir              # IR (後端無關)
pvefw-neo --dry-run              # nftables 文字
pvefw-neo --dump-ovs vmbr2       # 某 OVS bridge 的 flows

# 檢查 kernel 實際狀態
nft list table bridge pvefw-neo
ovs-ofctl dump-flows vmbr2
ip -d link show veth100i0 | grep isolated

# 看實際安裝的規則
nft list ruleset | grep pvefw-neo
ovs-ofctl dump-flows vmbr2 | grep "cookie=0x4e30"

# 全部重置（不會動 .fw 檔）
pvefw-neo --flush
systemctl restart pvefw-neo
```

---

## 專案結構

```
pvefw-neo/
├── pvefw-neo                # launcher
├── pvefw-neo.service        # systemd unit
├── pvefw_neo_src/           # Python package
│   ├── ir.py                # 中間表示
│   ├── parser.py            # .fw / @neo: parser
│   ├── compiler.py          # parser → IR
│   ├── nftgen.py            # IR → nftables
│   ├── ovsgen.py            # IR → OVS flows
│   ├── bridge.py            # bridge isolation
│   ├── macros.py            # PVE macro 解析
│   ├── vmdevs.py            # VM device discovery
│   └── main.py              # CLI + daemon
├── tests/                   # 測試套件 (任何 PVE host 都能跑)
├── install.sh / upgrade.sh / uninstall.sh
└── DESIGN.md                # 架構與設計理由
```

內部運作、規則語意、設計取捨請見 [DESIGN.md](DESIGN.md)。

---

## 授權

（請見專案 license 說明）
