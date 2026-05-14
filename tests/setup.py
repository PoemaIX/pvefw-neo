#!/usr/bin/env python3
"""pvefw-neo test suite — environment setup.

Creates the bridges, clones the test VM, creates the test CT, wires up NICs,
installs in-guest tools, and picks the VM exec channel. Does NOT run tests.

Everything is parameterised — override on your own host by exporting the env
var before invoking. The common knobs (see lib.Config for the full list):

    TEMPLATE_VMID    VM clone source (must be a template)        [90013]
    VMID_VM/VMID_CT  test guest IDs                              [2010/2011]
    BR_MGMT/BR_LINUX/BR_OVS    bridge names                      [vmbr1/2/3]
    MGMT_PREFIX      mgmt /24 prefix                             [10.99.0]
    LINUX_SUBNET_PREFIX / OVS_SUBNET_PREFIX   per-slot /24 base   [172.20/172.30]
    N_SLOTS          parallel slots (NICs) per backend           [3]
    LINKED_CLONE     1 = linked clone (fast), 0 = full clone      [1]
    CT_STORAGE       storage for the CT rootfs                   [local-lvm]
    CT_TEMPLATE      LXC template path; empty = newest in cache  []

Usage:
    python3 tests/setup.py
    TEMPLATE_VMID=9000 BR_LINUX=vmbr20 LINUX_SUBNET_PREFIX=10.50 python3 tests/setup.py
"""

import glob
import json
import os
import sys

from lib import (
    CFG, log, warn, sh, sh_ok,
    slot_iface, slot_ip, slot_netindex, guest_ifname,
    detect_vm_exec, wait_for_guest, exec_vm, exec_ct,
)

API_TOKEN_USER = "root@pam"
API_TOKEN_ID = "pvefw-neo-test"

IF_FILE = "/etc/network/interfaces"

# Marker comments wrap every stanza this script appends to the interfaces file,
# so clean.py can remove exactly what we added — nothing else.
def _mark_begin(br):
    return f"# pvefw-neo-test: BEGIN {br}"


def _mark_end(br):
    return f"# pvefw-neo-test: END {br}"


def _append_iface_stanza(br, lines):
    with open(IF_FILE, "a") as fh:
        fh.write("\n" + _mark_begin(br) + "\n")
        fh.write("\n".join(lines) + "\n")
        fh.write(_mark_end(br) + "\n")


def ensure_linux_bridge(br, addr):
    if sh_ok(["ip", "link", "show", br]):
        log(f"[=] {br} already exists — leaving as-is")
        return
    log(f"[+] Creating Linux bridge {br} ({addr})")
    _append_iface_stanza(br, [
        f"auto {br}",
        f"iface {br} inet static",
        f"\taddress {addr}",
        "\tbridge-ports none",
        "\tbridge-stp off",
        "\tbridge-fd 0",
    ])
    sh(["ifup", br], check=True)


def ensure_ovs_bridge(br):
    if sh_ok(["ovs-vsctl", "br-exists", br]):
        log(f"[=] {br} already exists (OVS) — leaving as-is")
        return
    if sh_ok(["ip", "link", "show", br]):
        sys.exit(f"[!] {br} exists but is NOT an OVS bridge — set BR_OVS to a free name")
    if not sh_ok(["sh", "-c", "command -v ovs-vsctl"]):
        sys.exit("[!] openvswitch-switch not installed — apt install -y openvswitch-switch")
    log(f"[+] Creating OVS bridge {br}")
    _append_iface_stanza(br, [
        f"auto {br}",
        f"iface {br} inet manual",
        "\tovs_type OVSBridge",
    ])
    sh(["ovs-vsctl", "add-br", br], check=True)


def setup_bridges():
    ensure_linux_bridge(CFG.br_mgmt, f"{CFG.mgmt_host_ip}/24")
    ensure_linux_bridge(CFG.br_linux, "0.0.0.0/32")   # no host IP; guests talk peer-to-peer
    ensure_ovs_bridge(CFG.br_ovs)

    # NAT for the mgmt net so guests can reach upstream (apt) via the host.
    if not sh_ok(["iptables", "-t", "nat", "-C", "POSTROUTING",
                  "-s", CFG.mgmt_net, "!", "-d", CFG.mgmt_net, "-j", "MASQUERADE"]):
        sh(["iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", CFG.mgmt_net, "!", "-d", CFG.mgmt_net, "-j", "MASQUERADE"], check=True)
        log(f"[+] NAT: {CFG.mgmt_net} → upstream")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
        fh.write("1")


def ensure_ssh_key():
    # Parallel tests need a per-connection exec channel; the qemu-guest-agent
    # socket only serves one client at a time. A throwaway key injected via
    # cloud-init gives us real concurrency.
    if not os.path.exists(CFG.test_ssh_key):
        log(f"[+] Generating test SSH key {CFG.test_ssh_key}")
        sh(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", CFG.test_ssh_key, "-q"], check=True)


def setup_vm():
    if sh_ok(["qm", "status", str(CFG.vmid_vm)]):
        log(f"[=] VM {CFG.vmid_vm} already exists")
    else:
        full = "0" if CFG.linked_clone else "1"
        log(f"[+] Cloning VM {CFG.template_vmid} → {CFG.vmid_vm} (full={full})")
        r = sh(["qm", "clone", str(CFG.template_vmid), str(CFG.vmid_vm),
                "--name", "pvefw-neo-test-vm", "--full", full])
        if r.returncode != 0:
            if full == "0":
                log("[!] Linked clone failed — retrying as full clone")
                sh(["qm", "clone", str(CFG.template_vmid), str(CFG.vmid_vm),
                    "--name", "pvefw-neo-test-vm", "--full", "1"], check=True)
            else:
                sys.exit(r.stderr.strip() or "qm clone failed")

    # Inject cloud-init credentials + SSH key; size the VM for the parallel
    # runner — a single core starves concurrent exec sessions and flakes pings.
    sh(["qm", "set", str(CFG.vmid_vm),
        "--ciuser", CFG.ci_user, "--cipassword", CFG.ci_pass,
        "--sshkeys", CFG.test_ssh_key + ".pub",
        "--cores", str(CFG.vm_cores)], check=True)

    # Rewrite NICs: net0 = mgmt, net1..N = linux slots, net(N+1)..2N = ovs slots.
    n_ifaces = 2 * CFG.n_slots + 1
    log(f"[+] Configuring VM NICs + ipconfig ({n_ifaces} ifaces)")
    sh(["qm", "set", str(CFG.vmid_vm),
        "--net0", f"virtio,bridge={CFG.br_mgmt},firewall=0",
        "--ipconfig0", f"ip={CFG.mgmt_prefix}.{CFG.vm_octet}/24,gw={CFG.mgmt_host_ip}"],
       check=True)
    for slot in range(1, CFG.n_slots + 1):
        for backend in ("linux", "ovs"):
            iface = slot_iface(backend, slot)
            idx = slot_netindex(backend, slot)
            br = CFG.br_linux if backend == "linux" else CFG.br_ovs
            sh(["qm", "set", str(CFG.vmid_vm),
                f"--{iface}", f"virtio,bridge={br},firewall=0",
                f"--ipconfig{idx}", f"ip={slot_ip(backend, slot, CFG.vm_octet)}/24"],
               check=True)

    if sh(["qm", "status", str(CFG.vmid_vm)]).stdout.split()[-1] != "running":
        log(f"[+] Starting VM {CFG.vmid_vm}")
        sh(["qm", "start", str(CFG.vmid_vm)], check=True)


def setup_ct():
    if sh_ok(["pct", "status", str(CFG.vmid_ct)]):
        log(f"[=] CT {CFG.vmid_ct} already exists")
    else:
        template = CFG.ct_template
        if not template:
            cache = sorted(
                glob.glob("/var/lib/vz/template/cache/*.tar.zst"),
                key=os.path.getmtime, reverse=True,
            )
            template = cache[0] if cache else ""
        if not template or not os.path.isfile(template):
            sys.exit("ERROR: no LXC template found. Set CT_TEMPLATE or run:\n"
                     "       pveam update && pveam download local debian-13-standard")
        log(f"[+] Creating CT {CFG.vmid_ct} from {template}")
        net_args = ["--net0",
                    f"name=eth0,bridge={CFG.br_mgmt},"
                    f"ip={CFG.mgmt_prefix}.{CFG.ct_octet}/24,gw={CFG.mgmt_host_ip},firewall=0"]
        for slot in range(1, CFG.n_slots + 1):
            for backend in ("linux", "ovs"):
                iface = slot_iface(backend, slot)
                idx = slot_netindex(backend, slot)
                br = CFG.br_linux if backend == "linux" else CFG.br_ovs
                net_args += [f"--{iface}",
                             f"name=eth{idx},bridge={br},"
                             f"ip={slot_ip(backend, slot, CFG.ct_octet)}/24,firewall=0"]
        sh(["pct", "create", str(CFG.vmid_ct), template,
            "--hostname", "pvefw-neo-test-ct",
            "--memory", str(CFG.ct_memory), "--swap", "0",
            "--cores", str(CFG.ct_cores),
            "--rootfs", f"{CFG.ct_storage}:{CFG.ct_rootfs_size}",
            "--password", CFG.ct_pass,
            "--unprivileged", "1", *net_args], check=True)

    if sh(["pct", "status", str(CFG.vmid_ct)]).stdout.split()[-1] != "running":
        log(f"[+] Starting CT {CFG.vmid_ct}")
        sh(["pct", "start", str(CFG.vmid_ct)], check=True)


def wait_and_pick_channel():
    log("[*] Waiting for VM (SSH, qga fallback)...")
    if not wait_for_guest("vm", tries=90):
        warn("VM not responding — tests that exercise the VM will fail")
    mode = detect_vm_exec()
    with open(os.path.join(CFG.test_tmp, "env"), "w") as fh:
        fh.write(f"VM_EXEC_MODE={mode}\n")
    log(f"[*] VM exec channel: {mode}")
    # Re-import side effect: subsequent helpers in this process should use it too.
    import lib
    lib.VM_EXEC_MODE = mode

    log("[*] Waiting for CT...")
    if not wait_for_guest("ct", tries=30):
        warn("CT not responding — tests that exercise the CT will fail")


def setup_api_token():
    """Create a PVE API token so the suite hits the HTTP API directly — same
    endpoint the WebUI uses, ~30x faster than spawning the pvesh CLI per call.
    Token managing is scaffolding (not a firewall op), so the CLI is fine here."""
    sh(["pveum", "user", "token", "remove", API_TOKEN_USER, API_TOKEN_ID])  # stale
    r = sh(["pveum", "user", "token", "add", API_TOKEN_USER, API_TOKEN_ID,
            "--privsep", "0", "--output-format", "json"])
    try:
        secret = json.loads(r.stdout)["value"]
    except (ValueError, KeyError):
        warn("could not create API token — suite falls back to the pvesh CLI")
        return
    token = f"{API_TOKEN_USER}!{API_TOKEN_ID}={secret}"
    with open(os.path.join(CFG.test_tmp, "env"), "a") as fh:
        fh.write(f"PVE_API_TOKEN={token}\n")
    log("[+] Created PVE API token for the suite (HTTP API, fast path)")


def _last_line(out):
    lines = out.strip().splitlines()
    return lines[-1] if lines else "(no output)"


def install_tools():
    # Packet crafting / listeners are handled by the in-guest agent (pure
    # stdlib python3), so the guests only need tcpdump for capture plus the
    # base net tooling. python3 is in the base images but listed defensively.
    tools = "tcpdump iproute2 iputils-ping python3"
    log(f"[+] Installing tools in guests: {tools}")
    cmd = (
        "export DEBIAN_FRONTEND=noninteractive\n"
        "if ! which tcpdump >/dev/null 2>&1 || ! which python3 >/dev/null 2>&1; then\n"
        "  apt-get update -qq >/dev/null 2>&1\n"
        f"  apt-get install -y -qq {tools} >/dev/null 2>&1\n"
        "fi\n"
        "echo DONE\n"
    )
    log(f"  VM: {_last_line(exec_vm(cmd))}")
    log(f"  CT: {_last_line(exec_ct(cmd))}")


def push_agent():
    # Ship tests/agent.py into both guests. base64-over-exec works uniformly
    # for SSH, qga and pct — no scp / pct-push special-casing needed.
    import base64
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.py")
    blob = base64.b64encode(open(src, "rb").read()).decode()
    dst = "/opt/pvefw-agent.py"
    log(f"[+] Pushing test agent to guests ({dst})")
    script = (
        f"echo '{blob}' | base64 -d > {dst} && chmod +x {dst} && "
        f"python3 -c 'import ast; ast.parse(open(\"{dst}\").read())' && echo PUSHED"
    )
    log(f"  VM: {_last_line(exec_vm(script))}")
    log(f"  CT: {_last_line(exec_ct(script))}")


def cache_ifnames():
    # Cache netN → in-guest ifname (by MAC) so the parallel runner never has to.
    log("[+] Caching guest interface names")
    cache_dir = os.path.join(CFG.test_tmp, "ifcache")
    for f in glob.glob(os.path.join(cache_dir, "*")):
        os.remove(f)
    for kind in ("vm", "ct"):
        for backend in ("linux", "ovs"):
            for slot in range(1, CFG.n_slots + 1):
                if not guest_ifname(kind, backend, slot):
                    warn(f"could not resolve {kind} {backend} slot{slot} ifname")


def stop_daemon():
    # The pvefw-neo daemon watches the .fw files and auto-applies; that would
    # race the suite's explicit, locked fw_apply() calls. Stop it for the run —
    # clean.py starts it back up.
    if sh(["systemctl", "is-active", "--quiet", "pvefw-neo"]).returncode == 0:
        log("[+] Stopping pvefw-neo daemon for the test run (clean.py restarts it)")
        sh(["systemctl", "stop", "pvefw-neo"])


def main():
    if os.geteuid() != 0:
        sys.exit("setup.py must run as root")
    log("═══ pvefw-neo test environment setup ═══")
    log(CFG.summary())
    stop_daemon()
    setup_bridges()
    ensure_ssh_key()
    setup_vm()
    setup_ct()
    wait_and_pick_channel()
    setup_api_token()
    install_tools()
    push_agent()
    cache_ifnames()
    log("═══ Setup complete — run python3 tests/test.py ═══")


if __name__ == "__main__":
    main()
