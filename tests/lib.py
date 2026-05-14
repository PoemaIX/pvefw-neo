"""pvefw-neo test suite — shared library.

Holds the single source of configuration (``Config``, every knob overridable
via an environment variable) plus the host/guest helpers used by setup.py,
test.py and clean.py. Pure stdlib — no ``pip install`` required.

IP / interface scheme
---------------------
Every slot gets its own /24 so parallel slots never share an L3 broadcast
domain::

    mgmt        <MGMT_PREFIX>.<host>/24                 host = .1
    linux slot  <LINUX_SUBNET_PREFIX>.<slot>.<host>/24  slot = 1..N_SLOTS
    ovs   slot  <OVS_SUBNET_PREFIX>.<slot>.<host>/24

Guest NICs: net0 = mgmt, net1..N = linux slots, net(N+1)..2N = ovs slots.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass, field


# ─────────────────────────── Configuration ───────────────────────────
def _env(name, default):
    return os.environ.get(name, default)


def _env_int(name, default):
    return int(os.environ.get(name, default))


def _env_bool(name, default):
    return os.environ.get(name, default) == "1"


@dataclass
class Config:
    """Every test-environment knob. Override by exporting the matching env var
    before invoking any of the scripts — see the field comments for names."""

    # Bridges — pick names that don't clash with the host's real bridges.
    br_mgmt: str = field(default_factory=lambda: _env("BR_MGMT", "vmbr1"))
    br_linux: str = field(default_factory=lambda: _env("BR_LINUX", "vmbr2"))
    br_ovs: str = field(default_factory=lambda: _env("BR_OVS", "vmbr3"))

    # Subnets — per-slot /24 bases and the host octet of each guest.
    mgmt_prefix: str = field(default_factory=lambda: _env("MGMT_PREFIX", "10.99.0"))
    linux_prefix: str = field(default_factory=lambda: _env("LINUX_SUBNET_PREFIX", "172.20"))
    ovs_prefix: str = field(default_factory=lambda: _env("OVS_SUBNET_PREFIX", "172.30"))
    vm_octet: int = field(default_factory=lambda: _env_int("VM_HOST_OCTET", "10"))
    ct_octet: int = field(default_factory=lambda: _env_int("CT_HOST_OCTET", "11"))

    # Topology / guests.
    n_slots: int = field(default_factory=lambda: _env_int("N_SLOTS", "3"))
    vmid_vm: int = field(default_factory=lambda: _env_int("VMID_VM", "2010"))
    vmid_ct: int = field(default_factory=lambda: _env_int("VMID_CT", "2011"))
    template_vmid: int = field(default_factory=lambda: _env_int("TEMPLATE_VMID", "90013"))
    linked_clone: bool = field(default_factory=lambda: _env_bool("LINKED_CLONE", "1"))
    ct_storage: str = field(default_factory=lambda: _env("CT_STORAGE", "local-lvm"))
    ct_rootfs_size: int = field(default_factory=lambda: _env_int("CT_ROOTFS_SIZE", "2"))
    ct_template: str = field(default_factory=lambda: _env("CT_TEMPLATE", ""))
    # Guests run many concurrent exec sessions under the parallel runner — a
    # single core starves the ping/tcpdump processes and flakes timeouts.
    vm_cores: int = field(default_factory=lambda: _env_int("VM_CORES", "4"))
    ct_cores: int = field(default_factory=lambda: _env_int("CT_CORES", "2"))
    ct_memory: int = field(default_factory=lambda: _env_int("CT_MEMORY", "512"))
    ci_user: str = field(default_factory=lambda: _env("CI_USER", "debian"))
    ci_pass: str = field(default_factory=lambda: _env("CI_PASS", "changeme"))
    ct_pass: str = field(default_factory=lambda: _env("CT_PASS", "changeme"))
    node: str = field(default_factory=lambda: _env("NODE", socket.gethostname()))

    # Runner.
    parallel: bool = field(default_factory=lambda: _env_bool("PARALLEL", "1"))
    test_tmp: str = field(default_factory=lambda: _env("TEST_TMP", "/tmp/pvefw-neo-test"))

    # ── Derived ──
    @property
    def mgmt_net(self) -> str:
        return f"{self.mgmt_prefix}.0/24"

    @property
    def mgmt_host_ip(self) -> str:
        return f"{self.mgmt_prefix}.1"

    @property
    def vm_mgmt_ip(self) -> str:
        return os.environ.get("VM_MGMT_IP", f"{self.mgmt_prefix}.{self.vm_octet}")

    @property
    def test_ssh_key(self) -> str:
        return os.environ.get("TEST_SSH_KEY", os.path.join(self.test_tmp, "id_test"))

    @property
    def pvefw_neo_bin(self) -> str:
        if "PVEFW_NEO_BIN" in os.environ:
            return os.environ["PVEFW_NEO_BIN"]
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        local = os.path.join(root, "pvefw-neo")
        return local if os.access(local, os.X_OK) else "pvefw-neo"

    def summary(self) -> str:
        return (
            f"node={self.node}  VM={self.vmid_vm} (clone of {self.template_vmid}, "
            f"linked={int(self.linked_clone)})  CT={self.vmid_ct}\n"
            f"  bridges: mgmt={self.br_mgmt} linux={self.br_linux} ovs={self.br_ovs}  "
            f"N_SLOTS={self.n_slots}  parallel={int(self.parallel)}\n"
            f"  subnets: mgmt={self.mgmt_prefix}.0/24  "
            f"linux={self.linux_prefix}.<slot>.0/24  ovs={self.ovs_prefix}.<slot>.0/24"
        )


CFG = Config()

SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=5",
    "-o", "LogLevel=ERROR",
    "-o", "BatchMode=yes",
]

# Locks — single process, so plain threading locks instead of flock files.
APPLY_LOCK = threading.Lock()   # serialises pvefw-neo --apply (whole-ruleset rebuild)
CFG_LOCK = threading.Lock()     # serialises pvesh .fw mutations
QGA_LOCK = threading.Lock()     # serialises qemu-guest-agent exec (one client only)

# VM exec channel: "ssh" (parallel-safe) or "qga" (fallback). setup.py probes
# this and writes it to <test_tmp>/env; we pick it up here on import.
VM_EXEC_MODE = "qga"

# PVE API token (`user!tokenid=secret`). setup.py creates one and writes it to
# <test_tmp>/env; with it, firewall ops hit the HTTP API directly (~30x faster
# than the pvesh CLI — same endpoint the WebUI uses). Empty → pvesh CLI fallback.
_PVE_API_TOKEN = os.environ.get("PVE_API_TOKEN", "")


def _load_env_file():
    global VM_EXEC_MODE, _PVE_API_TOKEN
    path = os.path.join(CFG.test_tmp, "env")
    if not os.path.exists(path):
        return
    for line in open(path):
        line = line.rstrip("\n")
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        if key == "VM_EXEC_MODE":
            VM_EXEC_MODE = val
        elif key == "PVE_API_TOKEN":
            _PVE_API_TOKEN = val


os.makedirs(os.path.join(CFG.test_tmp, "ifcache"), exist_ok=True)
_load_env_file()


# ─────────────────────────── Logging ───────────────────────────
_print_lock = threading.Lock()


def _emit(s):
    with _print_lock:
        print(s, flush=True)


def log(msg):
    _emit(f"\033[36m[{time.strftime('%H:%M:%S')}]\033[0m {msg}")


def ok(msg):
    _emit(f"\033[32m  ✓\033[0m {msg}")


def fail(msg):
    _emit(f"\033[31m  ✗\033[0m {msg}")


def warn(msg):
    _emit(f"\033[33m  !\033[0m {msg}")


# ─────────────────────────── Host command helpers ───────────────────────────
def sh(cmd, check=False, input=None, timeout=None):
    """Run a host command (list form). Returns CompletedProcess."""
    return subprocess.run(
        cmd, capture_output=True, text=True, input=input,
        timeout=timeout, check=check,
    )


def sh_ok(cmd, **kw):
    """Run a host command, return True on exit 0."""
    try:
        return sh(cmd, **kw).returncode == 0
    except subprocess.SubprocessError:
        return False


# ─────────────────────────── IP / iface scheme ───────────────────────────
def slot_subnet(backend, slot):
    return f"{CFG.linux_prefix}.{slot}" if backend == "linux" else f"{CFG.ovs_prefix}.{slot}"


def slot_ip(backend, slot, host_octet):
    return f"{slot_subnet(backend, slot)}.{host_octet}"


def slot_cidr(backend, slot):
    return f"{slot_subnet(backend, slot)}.0/24"


def slot_iface(backend, slot):
    """PVE NIC name (netN)."""
    return f"net{slot}" if backend == "linux" else f"net{slot + CFG.n_slots}"


def slot_netindex(backend, slot):
    """The integer N in netN — also the tapXiN device suffix."""
    return slot if backend == "linux" else slot + CFG.n_slots


def slot_bridge(backend):
    return CFG.br_linux if backend == "linux" else CFG.br_ovs


def vm_tap(backend, slot):
    return f"tap{CFG.vmid_vm}i{slot_netindex(backend, slot)}"


# ─────────────────────────── Guest exec ───────────────────────────
def exec_vm(script):
    """Run a shell script as root inside the VM. SSH when available (parallel-
    safe), else qemu-guest-agent (serialised — the qga socket is single-client).

    The SSH path retries once on an empty result: under heavy parallel load a
    connection can occasionally fail to establish. A real command that yields
    no stdout at all is rare, so the retry is cheap insurance against flakes."""
    if VM_EXEC_MODE == "ssh":
        p = None
        for _ in range(2):
            p = subprocess.run(
                ["ssh", "-i", CFG.test_ssh_key, *SSH_OPTS,
                 f"{CFG.ci_user}@{CFG.vm_mgmt_ip}", "sudo", "/bin/sh"],
                input=script, capture_output=True, text=True,
            )
            if p.returncode == 0 or p.stdout.strip():
                return p.stdout
            time.sleep(0.5)
        return p.stdout
    with QGA_LOCK:
        # Generous timeout — a quick command still returns immediately; this
        # only bounds genuinely slow ones (e.g. apt-get in the qga fallback).
        p = sh(["qm", "guest", "exec", str(CFG.vmid_vm), "--timeout", "120",
                "--", "/bin/sh", "-c", script])
    try:
        return json.loads(p.stdout).get("out-data", "")
    except (ValueError, AttributeError):
        return ""


def exec_ct(script):
    """Run a shell script as root inside the CT. pct exec is parallel-safe but
    can occasionally hiccup under heavy concurrency — retry once on an empty
    result, same as the VM's SSH path."""
    p = None
    for _ in range(2):
        p = sh(["pct", "exec", str(CFG.vmid_ct), "--", "/bin/sh", "-c", script])
        if p.returncode == 0 or p.stdout.strip():
            return p.stdout
        time.sleep(0.5)
    return p.stdout


def exec_on(kind, script):
    return exec_vm(script) if kind == "vm" else exec_ct(script)


def detect_vm_exec():
    """Probe the SSH channel; return 'ssh' or 'qga'."""
    if os.path.exists(CFG.test_ssh_key) and sh_ok(
        ["ssh", "-i", CFG.test_ssh_key, *SSH_OPTS,
         f"{CFG.ci_user}@{CFG.vm_mgmt_ip}", "true"]
    ):
        return "ssh"
    return "qga"


def wait_for_guest(kind, tries=60):
    """Block until the guest answers an exec. For the VM, upgrades to the SSH
    channel as soon as it comes up."""
    global VM_EXEC_MODE
    for _ in range(tries):
        if kind == "vm" and VM_EXEC_MODE != "ssh" and detect_vm_exec() == "ssh":
            VM_EXEC_MODE = "ssh"
        if "READY" in exec_on(kind, "echo READY"):
            return True
        time.sleep(2)
    return False


def guest_mac(kind, net):
    """Lower-case MAC of a guest NIC, read from PVE config (authoritative)."""
    if kind == "vm":
        out = sh(["qm", "config", str(CFG.vmid_vm)]).stdout
    else:
        out = sh(["pct", "config", str(CFG.vmid_ct)]).stdout
    for line in out.splitlines():
        if line.startswith(f"{net}:"):
            m = re.search(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", line)
            if m:
                return m.group(0).lower()
    return ""


def slot_mac(kind, backend, slot):
    return guest_mac(kind, slot_iface(backend, slot))


def guest_ifname(kind, backend, slot):
    """Interface name *inside* the guest for this slot, resolved by MAC (no
    reliance on ethN ordering). Cached on disk so the parallel runner is cheap."""
    cf = os.path.join(CFG.test_tmp, "ifcache", f"{kind}_{backend}_{slot}")
    if os.path.exists(cf):
        val = open(cf).read().strip()
        if val:
            return val
    mac = slot_mac(kind, backend, slot)
    if not mac:
        return ""
    out = exec_on(kind, "ip -o link 2>/dev/null")
    name = ""
    for line in out.splitlines():
        if mac in line.lower():
            # line: "3: eth1@if122: <...> ... link/ether bc:24:.. ..."
            # veth interfaces carry an "@ifN" peer suffix — strip it, the
            # bare name is what `ping -I` / `tcpdump -i` expect.
            parts = line.split(":")
            if len(parts) >= 2:
                name = parts[1].strip().split("@")[0]
                break
    if name:
        with open(cf, "w") as fh:
            fh.write(name)
    return name


# ─────────────────────────── PVE firewall API ───────────────────────────
def fw_base(kind):
    if kind == "vm":
        return f"/nodes/{CFG.node}/qemu/{CFG.vmid_vm}/firewall"
    return f"/nodes/{CFG.node}/lxc/{CFG.vmid_ct}/firewall"


def vmid_of(kind):
    return CFG.vmid_vm if kind == "vm" else CFG.vmid_ct


# ── PVE API transport ──
# Every firewall mutation goes through the PVE API — the exact path the WebUI
# uses — so tests exercise what a real user does. The HTTP API (token auth) is
# ~30x faster than spawning the `pvesh` CLI per call; `pvesh` stays as a
# fallback when no token is configured.
def _pve_http(method, path, params):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection("localhost", 8006, context=ctx, timeout=20)
    headers = {"Authorization": f"PVEAPIToken={_PVE_API_TOKEN}"}
    url = "/api2/json" + path
    body = None
    if method in ("GET", "DELETE"):
        if params:
            url += "?" + urllib.parse.urlencode(params)
    elif params:
        body = urllib.parse.urlencode(params)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        conn.request(method, url, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", "replace")
        ok = resp.status < 400
        if method == "GET":
            if not ok or not raw.strip():
                return None
            try:
                return json.loads(raw).get("data")
            except ValueError:
                return None
        return ok
    except (OSError, ValueError):
        return None if method == "GET" else False
    finally:
        conn.close()


def _api(method, path, params=None):
    """PVE API call. method=GET/POST/PUT/DELETE; params is a dict with keys in
    API form (e.g. 'icmp-type'). GET → parsed `data` (or None); other methods
    → True/False. Uses the HTTP API when a token is set, else the pvesh CLI."""
    params = params or {}
    if _PVE_API_TOKEN:
        return _pve_http(method, path, params)
    verb = {"GET": "get", "POST": "create", "PUT": "set", "DELETE": "delete"}[method]
    args = ["pvesh", verb, path]
    for k, v in params.items():
        args += [f"--{k}", str(v)]
    if method == "GET":
        args += ["--output-format", "json"]
        p = sh(args)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return None
    return sh(args).returncode == 0


def pvesh_json(path):
    """GET a PVE API path, return parsed data ([] on failure)."""
    data = _api("GET", path)
    return data if data is not None else []


def fw_rule(kind, action, type_, **opts):
    """Create a firewall rule. opts pass through as API params (iface, proto,
    dport, source, dest, macro, comment, icmp_type → icmp-type ...).

    NOTE: rule create always PREPENDS (position 0). Order-sensitive tests must
    create bottom-up (catch-all first). Parallel tests MUST always pass iface=
    — an iface-less rule fans out to every NIC and clobbers other slots."""
    params = {"action": action, "type": type_, "enable": "1"}
    for k, v in opts.items():
        params[k.replace("_", "-")] = v
    with CFG_LOCK:
        _api("POST", f"{fw_base(kind)}/rules", params)


def fw_ext(kind, iface, comment, **opts):
    """Create an @neo: extension carrier rule (Finger macro + @neo: comment)."""
    fw_rule(kind, "DROP", "out", iface=iface, macro="Finger", comment=comment, **opts)


def fw_clear(kind):
    """Delete every rule from the guest's firewall."""
    base = fw_base(kind)
    with CFG_LOCK:
        while pvesh_json(f"{base}/rules"):
            if not _api("DELETE", f"{base}/rules/0"):
                break


def slot_clear(kind, backend, slot):
    """Delete only the rules bound to this slot's iface — lets a test reset its
    own slot mid-run without disturbing concurrently-running slots."""
    base = fw_base(kind)
    iface = slot_iface(backend, slot)
    with CFG_LOCK:
        rules = pvesh_json(f"{base}/rules")
        idxs = [i for i, r in enumerate(rules) if r.get("iface") == iface]
        for i in sorted(idxs, reverse=True):
            _api("DELETE", f"{base}/rules/{i}")


def fw_enable(kind):
    with CFG_LOCK:
        _api("PUT", f"{fw_base(kind)}/options", {"enable": "1"})


def fw_disable(kind):
    with CFG_LOCK:
        _api("PUT", f"{fw_base(kind)}/options", {"enable": "0"})


# Cluster-wide ipset / alias.
def cluster_ipset_create(name):
    with CFG_LOCK:
        _api("POST", "/cluster/firewall/ipset", {"name": name})


def cluster_ipset_add(name, cidr, nomatch=False):
    params = {"cidr": cidr}
    if nomatch:
        params["nomatch"] = "1"
    with CFG_LOCK:
        _api("POST", f"/cluster/firewall/ipset/{name}", params)


def cluster_ipset_del(name):
    with CFG_LOCK:
        _api("DELETE", f"/cluster/firewall/ipset/{name}", {"force": "1"})


def cluster_alias_create(name, cidr):
    with CFG_LOCK:
        _api("POST", "/cluster/firewall/aliases", {"name": name, "cidr": cidr})


def cluster_alias_set(name, cidr):
    with CFG_LOCK:
        _api("PUT", f"/cluster/firewall/aliases/{name}", {"cidr": cidr})


def cluster_alias_del(name):
    with CFG_LOCK:
        _api("DELETE", f"/cluster/firewall/aliases/{name}")


# Per-VM/CT ipset / alias.
def guest_ipset_create(kind, name):
    with CFG_LOCK:
        _api("POST", f"{fw_base(kind)}/ipset", {"name": name})


def guest_ipset_add(kind, name, cidr, nomatch=False):
    params = {"cidr": cidr}
    if nomatch:
        params["nomatch"] = "1"
    with CFG_LOCK:
        _api("POST", f"{fw_base(kind)}/ipset/{name}", params)


def guest_ipset_del(kind, name):
    with CFG_LOCK:
        _api("DELETE", f"{fw_base(kind)}/ipset/{name}", {"force": "1"})


def guest_alias_create(kind, name, cidr):
    with CFG_LOCK:
        _api("POST", f"{fw_base(kind)}/aliases", {"name": name, "cidr": cidr})


def guest_alias_del(kind, name):
    with CFG_LOCK:
        _api("DELETE", f"{fw_base(kind)}/aliases/{name}")


def fw_apply():
    """Recompile + load. Serialised — pvefw-neo --apply rebuilds the entire
    ruleset, so two concurrent applies would race on nft / ovs-ofctl."""
    with APPLY_LOCK:
        sh([CFG.pvefw_neo_bin, "--apply"])


def fw_rule_enabled(kind, pos):
    data = _api("GET", f"{fw_base(kind)}/rules/{pos}")
    try:
        return int(data.get("enable", 0))
    except (AttributeError, TypeError, ValueError):
        return 0


def fw_log_has_quarantine(kind, pos):
    """True if the latest firewall-log entry is a quarantine line for rule #pos."""
    data = _api("GET", f"{fw_base(kind)}/log", {"limit": "50"})
    last = data[-1].get("t", "") if isinstance(data, list) and data else ""
    return bool(re.search(rf"\[pvefw-neo\] invalid rule #{pos} disabled, reason: ", last))


# ─────────────────────────── Reset helpers ───────────────────────────
def _del_tst_sets():
    for kind in ("vm", "ct"):
        base = fw_base(kind)
        for s in pvesh_json(f"{base}/ipset"):
            if s.get("name", "").startswith("tst_"):
                guest_ipset_del(kind, s["name"])
        for a in pvesh_json(f"{base}/aliases"):
            if a.get("name", "").startswith("tst_"):
                guest_alias_del(kind, a["name"])
    for s in pvesh_json("/cluster/firewall/ipset"):
        if s.get("name", "").startswith("tst_"):
            cluster_ipset_del(s["name"])
    for a in pvesh_json("/cluster/firewall/aliases"):
        if a.get("name", "").startswith("tst_"):
            cluster_alias_del(a["name"])


def fw_global_reset():
    """Wipe every rule / tst_ ipset / tst_ alias, flush all conntrack, re-apply.
    Runs SERIALLY between parallel waves, so the global conntrack flush here is
    safe — no test is mid-assertion."""
    fw_clear("vm")
    fw_clear("ct")
    _del_tst_sets()
    fw_apply()
    sh(["conntrack", "-F"])


def slot_ct_flush(backend, slot):
    """Drop conntrack entries for just this slot's IPs, so a prior phase's
    established state can't mask the next phase. Scoped to the slot, so it never
    disturbs a concurrently-running test."""
    for host in (CFG.vm_octet, CFG.ct_octet):
        ip = slot_ip(backend, slot, host)
        sh(["conntrack", "-D", "-s", ip])
        sh(["conntrack", "-D", "-d", ip])


# ─────────────────────────── Packet-test helpers ───────────────────────────
def ping_between(from_kind, iface, to_ip):
    """ICMP echo from a guest iface to an IP. -c 2 covers first-packet ARP;
    one retry smooths a transient parallel-load hiccup. A genuinely blocked
    path stays blocked across both attempts."""
    for _ in range(2):
        out = exec_on(from_kind, f"ping -c 3 -W 2 -I {iface} {to_ip} 2>/dev/null")
        m = re.search(r"(\d+) received", out)
        if m and int(m.group(1)) >= 1:
            return True
    return False


def probe_ping(backend, slot):
    """VM→CT ping on this slot → 'PASS' / 'FAIL'."""
    eth = guest_ifname("vm", backend, slot)
    return "PASS" if ping_between("vm", eth, slot_ip(backend, slot, CFG.ct_octet)) else "FAIL"


def probe_ping_rev(backend, slot):
    """CT→VM ping on this slot → 'PASS' / 'FAIL'. Use for IN-direction rule
    tests: VM→CT replies ride `ct state established,related accept` and bypass
    the IN chain, so a CT-initiated NEW flow is what actually exercises it."""
    eth = guest_ifname("ct", backend, slot)
    return "PASS" if ping_between("ct", eth, slot_ip(backend, slot, CFG.vm_octet)) else "FAIL"


# In-guest agent (tests/agent.py, pushed to the guests by setup.py). It forges
# stateless frames and provides stdlib-socket connect/listen — no scapy, no
# hping3/ncat. Capture stays on tcpdump (below).
AGENT = "/opt/pvefw-agent.py"


def _agent(kind, *args):
    return exec_on(kind, "python3 " + AGENT + " " + " ".join(str(a) for a in args))


def agent_send(guest, kind, iface, eth_src, eth_dst=None, **kw):
    """Forge + send one frame from `guest`. kw pass through to agent.py send
    (ip_src, ip_dst, ip6_src, ip6_dst, tgt, vlan, count → --ip-src ... etc)."""
    args = ["send", "--kind", kind, "--iface", iface, "--eth-src", eth_src]
    if eth_dst:
        args += ["--eth-dst", eth_dst]
    for k, v in kw.items():
        args += [f"--{k.replace('_', '-')}", str(v)]
    return _agent(guest, *args)


def tcp_check(from_kind, from_ip, to_ip, port):
    """TCP connect probe from a guest (bound to from_ip) → 'OPEN' / 'CLOSED'."""
    out = _agent(from_kind, "connect", "--dst", to_ip, "--dport", port, "--src", from_ip)
    return "OPEN" if "OPEN" in out else "CLOSED"


def start_listener(kind, port):
    """Background stdlib-socket echo listener inside a guest (the agent
    self-daemonises, so no nohup needed)."""
    exec_on(kind, f"pkill -f 'pvefw-agent.py listen --port {port}' 2>/dev/null; true")
    _agent(kind, "listen", "--port", port)
    time.sleep(0.5)


def cap_start(kind, iface, tag, bpf):
    """Arm a tcpdump capture inside a guest. The BPF should be MAC-scoped
    (`ether src <mac> and ...`) so a frame leaked from another slot can never
    be miscounted.

    The caller fires traffic, then cap_count() stops + reads the capture —
    the window is however long the firing takes, not a fixed race against a
    `timeout` (which flaked when parallel-load slowed the exec channel). The
    30s timeout is only a safety net for a leaked capture.

    -U writes each packet immediately; -p skips promiscuous mode; all three
    std fds are redirected so the SSH channel closes instead of waiting on
    the backgrounded tcpdump."""
    exec_on(kind,
            f"rm -f /tmp/cap_{tag}.pcap 2>/dev/null; "
            f"nohup timeout 30 tcpdump -i {iface} -nn -p -U -w /tmp/cap_{tag}.pcap "
            f"'{bpf}' </dev/null >/dev/null 2>&1 &")
    time.sleep(1)   # let tcpdump attach before the caller fires


def cap_count(kind, tag):
    """Stop the capture armed by cap_start() and return the packet count."""
    # pkill matches both the `timeout` wrapper and tcpdump (the pcap path is
    # in both their argv); the short sleep lets the final packet flush.
    exec_on(kind, f"pkill -f 'cap_{tag}.pcap' 2>/dev/null; sleep 0.3; true")
    out = exec_on(kind, f"tcpdump -r /tmp/cap_{tag}.pcap 2>/dev/null | wc -l")
    try:
        return int(out.strip())
    except ValueError:
        return 0
