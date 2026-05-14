#!/usr/bin/env python3
"""pvefw-neo test suite — teardown.

Full cleanup: destroys the test VM/CT, removes cluster-level tst_ ipsets and
aliases, flushes pvefw-neo state, drops the NAT rule, and removes the test
bridges (both the live devices and the stanzas setup.py appended to
/etc/network/interfaces — only the marked blocks are touched). Finally wipes
the host-side scratch dir.

Honours the same env vars as setup.py — clean with the same overrides you set
up with, e.g.  BR_LINUX=vmbr20 python3 tests/clean.py
"""

import os
import re
import shutil
import sys

from lib import CFG, log, warn, sh, sh_ok

IF_FILE = "/etc/network/interfaces"


def destroy_guests():
    if sh_ok(["qm", "status", str(CFG.vmid_vm)]):
        log(f"[-] Stopping + destroying VM {CFG.vmid_vm}")
        sh(["qm", "stop", str(CFG.vmid_vm), "--skiplock", "1"])
        sh(["qm", "destroy", str(CFG.vmid_vm), "--purge", "1",
            "--destroy-unreferenced-disks", "1"])
    if sh_ok(["pct", "status", str(CFG.vmid_ct)]):
        log(f"[-] Stopping + destroying CT {CFG.vmid_ct}")
        sh(["pct", "stop", str(CFG.vmid_ct)])
        sh(["pct", "destroy", str(CFG.vmid_ct), "--purge", "1"])


def _pvesh_names(path):
    import json
    p = sh(["pvesh", "get", path, "--output-format", "json"])
    try:
        return [x.get("name", "") for x in json.loads(p.stdout)]
    except ValueError:
        return []


def remove_cluster_artifacts():
    log("[-] Removing cluster tst_ ipsets / aliases")
    for name in _pvesh_names("/cluster/firewall/ipset"):
        if name.startswith("tst_"):
            sh(["pvesh", "delete", f"/cluster/firewall/ipset/{name}", "--force", "1"])
    for name in _pvesh_names("/cluster/firewall/aliases"):
        if name.startswith("tst_"):
            sh(["pvesh", "delete", f"/cluster/firewall/aliases/{name}"])


def flush_pvefw_neo():
    log("[-] Flushing pvefw-neo state")
    sh([CFG.pvefw_neo_bin, "--flush"])


def remove_nat():
    rule = ["-t", "nat", "POSTROUTING", "-s", CFG.mgmt_net,
            "!", "-d", CFG.mgmt_net, "-j", "MASQUERADE"]
    if sh_ok(["iptables", rule[0], rule[1], "-C", *rule[2:]]):
        sh(["iptables", *rule[:2], "-D", *rule[2:]])
        log(f"[-] Removed NAT: {CFG.mgmt_net}")


def _marked_bridges():
    """Bridge names that setup.py actually created — identified by the sentinel
    stanza it appended to the interfaces file. A bridge that pre-existed (setup
    left it alone, so there's no marker) is NEVER torn down: clean must not
    destroy the user's own networking just because a name collides."""
    if not os.path.exists(IF_FILE):
        return []
    found = []
    for line in open(IF_FILE):
        m = re.match(r"# pvefw-neo-test: BEGIN (\S+)", line)
        if m:
            found.append(m.group(1))
    return found


def _take_down_bridge(br):
    """Bring a bridge device down + delete it, whichever family it is."""
    if sh_ok(["ovs-vsctl", "br-exists", br]):
        sh(["ovs-vsctl", "del-br", br])
        log(f"[-] Removed OVS bridge {br}")
        return
    if sh_ok(["ip", "link", "show", br]):
        # ifdown is best-effort (reads the stanza we're about to delete).
        sh(["ifdown", br])
        sh(["ip", "link", "set", br, "down"])
        sh(["ip", "link", "del", br])
        log(f"[-] Removed Linux bridge {br}")


def _strip_iface_stanzas():
    """Delete every `# pvefw-neo-test: BEGIN/END` block from the interfaces
    file. Only our marked blocks are touched."""
    if not os.path.exists(IF_FILE):
        return
    lines = open(IF_FILE).read().splitlines()
    out, skip, removed = [], False, []
    for line in lines:
        mb = re.match(r"# pvefw-neo-test: BEGIN (\S+)", line)
        me = re.match(r"# pvefw-neo-test: END (\S+)", line)
        if mb:
            skip = True
            removed.append(mb.group(1))
            # Drop a single blank line we may have inserted before the block.
            if out and out[-1].strip() == "":
                out.pop()
            continue
        if me:
            skip = False
            continue
        if not skip:
            out.append(line)
    if removed:
        with open(IF_FILE, "w") as fh:
            fh.write("\n".join(out) + "\n")
        log(f"[-] Removed interfaces stanzas: {', '.join(removed)}")


def remove_bridges():
    ours = _marked_bridges()
    skipped = [br for br in (CFG.br_mgmt, CFG.br_linux, CFG.br_ovs) if br not in ours]
    for br in skipped:
        if sh_ok(["ip", "link", "show", br]) or sh_ok(["ovs-vsctl", "br-exists", br]):
            warn(f"{br} exists but was not created by setup.py (no marker) — leaving it")
    for br in ours:
        _take_down_bridge(br)
    _strip_iface_stanzas()


def wipe_scratch():
    if os.path.isdir(CFG.test_tmp):
        shutil.rmtree(CFG.test_tmp, ignore_errors=True)
        log(f"[-] Wiped scratch dir {CFG.test_tmp}")


def start_daemon():
    # setup.py stopped the daemon so the suite could drive --apply itself;
    # restore it to its normal running state.
    if sh_ok(["systemctl", "is-enabled", "pvefw-neo"]):
        log("[+] Starting pvefw-neo daemon")
        sh(["systemctl", "start", "pvefw-neo"])


def remove_api_token():
    # The token setup.py created for the HTTP API fast-path.
    if sh(["pveum", "user", "token", "remove",
           "root@pam", "pvefw-neo-test"]).returncode == 0:
        log("[-] Removed PVE API token")


def main():
    if os.geteuid() != 0:
        sys.exit("clean.py must run as root")
    log("═══ pvefw-neo test teardown ═══")
    log(CFG.summary())
    destroy_guests()
    remove_cluster_artifacts()
    remove_api_token()
    flush_pvefw_neo()
    remove_nat()
    remove_bridges()
    wipe_scratch()
    start_daemon()
    log("═══ Teardown complete — VM/CT, rules, NAT and bridges all removed ═══")


if __name__ == "__main__":
    main()
