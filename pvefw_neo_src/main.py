"""pvefw-neo: CLI + daemon loop."""

import argparse
import json
import os
import signal
import subprocess
import sys
import time

from . import compiler
from . import nftgen
from . import ovsgen
from . import bridge
from . import macros as macros_mod
from . import quarantine
from . import vmdevs


RULESET_PATH = "/run/pvefw-neo/ruleset.nft"
STATE_PATH = "/run/pvefw-neo/state.json"
FW_DIR = "/etc/pve/firewall"


def preflight_check():
    """Check preconditions before starting.

    pvefw-neo runs alongside PVE's native firewall using the "node off +
    nftables mode" model:

      - /etc/pve/nodes/<this>/host.fw has [OPTIONS] enable: 0
      - /etc/pve/nodes/<this>/host.fw has [OPTIONS] nftables: 1

    This tells PVE's own firewall daemons to leave THIS node alone:
      - pve-firewall Perl daemon: sees nftables mode → defers, removes its
        legacy iptables chains (verified on-host)
      - proxmox-firewall Rust daemon: sees host.enable=0 → skips this node,
        installs nothing in the inet proxmox-firewall table for this host

    The rest of the cluster can still run PVE native firewall normally.

    datacenter level (cluster.fw enable) is NOT checked — the user is free
    to enable datacenter firewall for other nodes.
    """
    errors = []
    import socket
    nodename = socket.gethostname()
    host_fw_path = f"/etc/pve/nodes/{nodename}/host.fw"

    host_enable, host_nftables = _read_host_fw_options(host_fw_path)

    if host_enable is None:
        errors.append(
            f"{host_fw_path} not found or missing [OPTIONS]. Run install.sh "
            f"to set it up, or add '[OPTIONS]\\nenable: 0\\nnftables: 1'."
        )
    else:
        if host_enable != 0:
            errors.append(
                f"{host_fw_path} must have 'enable: 0' (got {host_enable}). "
                f"pvefw-neo manages this node's firewall — the PVE native "
                f"node-level firewall must be off here."
            )
        if host_nftables != 1:
            errors.append(
                f"{host_fw_path} must have 'nftables: 1' (got {host_nftables}). "
                f"iptables mode installs legacy PVEFW chains that would "
                f"interfere with pvefw-neo's nftables rules."
            )

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        print(
            "\nHint: bash /usr/local/lib/pvefw_neo/install.sh will fix these "
            "interactively.",
            file=sys.stderr,
        )
        return False
    return True


def _read_host_fw_options(path):
    """Parse [OPTIONS] from a host.fw file.

    Returns (enable, nftables) as ints, or (None, None) if file missing.
    """
    if not os.path.isfile(path):
        return None, None
    enable = None
    nftables = None
    in_options = False
    try:
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("["):
                    in_options = line.lower().startswith("[options]")
                    continue
                if not in_options:
                    continue
                if ":" in line:
                    k, _, v = line.partition(":")
                    k = k.strip().lower()
                    v = v.strip()
                    if k == "enable":
                        try:
                            enable = int(v)
                        except ValueError:
                            pass
                    elif k == "nftables":
                        try:
                            nftables = int(v)
                        except ValueError:
                            pass
    except OSError:
        return None, None
    # Missing values default to 0 (PVE default for both)
    return enable or 0, nftables or 0


def compile_ir():
    """Compile .fw configs into IR Ruleset."""
    macros_mod.reset_cache()
    return compiler.compile_ruleset()


def detect_bridge(devname):
    """Look up which bridge a netdev belongs to and its type.

    Returns (bridge_name, bridge_type) where bridge_type is "linux" or "ovs".
    Returns (None, None) if not found.
    """
    # Read /sys/class/net/<dev>/master to find bridge
    master_link = f"/sys/class/net/{devname}/master"
    if not os.path.islink(master_link):
        return None, None
    bridge_name = os.path.basename(os.readlink(master_link))

    # Special case: ovs port master is "ovs-system", not the actual bridge
    if bridge_name == "ovs-system":
        # Use ovs-vsctl to find which OVS bridge owns this port
        ret = subprocess.run(
            ["ovs-vsctl", "iface-to-br", devname],
            capture_output=True, text=True,
        )
        if ret.returncode == 0:
            bridge_name = ret.stdout.strip()
            return bridge_name, "ovs"
        return None, None

    return bridge_name, "linux"


def group_netdevs_by_backend(ir_rs):
    """Group NetDevs by (bridge_type, bridge_name).

    Returns:
      {"linux": [devname, ...], "ovs": {bridge_name: [devname, ...]}}
    """
    linux_devs = []
    ovs_groups = {}
    for devname in ir_rs.netdevs:
        br_name, br_type = detect_bridge(devname)
        if br_type == "ovs":
            ovs_groups.setdefault(br_name, []).append(devname)
        elif br_type == "linux":
            linux_devs.append(devname)
        # else: skip (device may not exist yet, e.g. VM stopped)
    return {"linux": linux_devs, "ovs": ovs_groups}


def generate_and_check():
    """Compile → render (no syntax check).

    Returns (ir_rs, nft_text, isolated_devs, ovs_groups). nft_text is the
    rendered output for the full IR (pre-quarantine); daemon uses it for
    cheap change detection. Apply layer re-renders per iteration as needed.
    """
    ir_rs = compile_ir()
    groups = group_netdevs_by_backend(ir_rs)
    nft_text, isolated_devs = nftgen.render(ir_rs, groups["linux"])
    return ir_rs, nft_text, isolated_devs, groups["ovs"]


def _cleanup_orphaned_netdev_tables():
    """Drop any leftover `table netdev pvefw-neo-*` — they'd otherwise
    accumulate from ports that used to be managed but aren't now (e.g.
    @neo:disable, firewall=1 added, VM deleted). Safe to run before every
    apply: tables we're about to recreate get replaced with fresh content.
    """
    ret = subprocess.run(
        ["nft", "list", "tables"],
        capture_output=True, text=True,
    )
    if ret.returncode != 0:
        return
    for line in ret.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) == 3 and parts[0] == "table" and parts[1] == "netdev" \
                and parts[2].startswith("pvefw-neo-"):
            subprocess.run(
                ["nft", "delete", "table", "netdev", parts[2]],
                capture_output=True, text=True,
            )


def _host_ovs_bridges():
    """Every OVS bridge on this host, or empty set if OVS not installed."""
    try:
        ret = subprocess.run(
            ["ovs-vsctl", "list-br"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return set()
    if ret.returncode != 0:
        return set()
    return {ln.strip() for ln in ret.stdout.splitlines() if ln.strip()}


def apply_ruleset(ir_rs):
    """Apply ruleset with progressive quarantine of bad rules.

    Returns (ok, final_nft_text). On full success (even after quarantining
    some rules), ok=True and final_nft_text reflects the applied state
    (minus quarantined rules). On unrecoverable failure, ok=False.
    """
    os.makedirs("/run/pvefw-neo", exist_ok=True)

    groups = group_netdevs_by_backend(ir_rs)
    # Walk every OVS bridge on the host, not just those currently holding
    # managed NetDevs. Bridges that lost their last VM still need their
    # stale pvefw-neo flows cleaned.
    all_bridges = sorted(set(groups["ovs"].keys()) | _host_ovs_bridges())
    ovs_targets = [(br, groups["ovs"].get(br, [])) for br in all_bridges]

    # Stash the final rendered nft text so the caller can cache it for
    # change detection. Closure receives filtered IR each quarantine round.
    final_text = {"nft": "", "isolated": []}

    def nft_render(filtered):
        text, iso = nftgen.render(filtered, groups["linux"])
        final_text["nft"] = text
        final_text["isolated"] = iso
        return text, iso

    ok, quarantined = quarantine.apply_with_quarantine(
        ir_rs,
        nft_renderer=nft_render,
        ruleset_path=RULESET_PATH,
        ovs_bridges=ovs_targets,
        isolation_hook=bridge.apply_isolation,
        pre_nft_hook=_cleanup_orphaned_netdev_tables,
    )

    if not ok:
        return False, None

    # Fold compile-time rejections (family mismatch, rateexceed+ACCEPT, ...)
    # into the same dict as backend quarantine. Both get identical UX:
    # .fw checkbox unchecked + firewall-log entry. Backend entries have
    # richer error text (from nft/ovs stderr); compile entries have the
    # validator's own reason string.
    all_quarantined = dict(ir_rs.compile_rejections)
    all_quarantined.update(quarantined)

    if all_quarantined:
        quarantine.materialize_quarantine(all_quarantined)
        for sid, err in all_quarantined.items():
            first_line = err.strip().splitlines()[0] if err.strip() else "(no detail)"
            print(f"pvefw-neo: auto-disabled {sid}: {first_line}",
                  file=sys.stderr)

    # ── Save state ──
    netdev_count = len(ir_rs.netdevs)
    state = {
        "applied_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "netdev_count": netdev_count,
        "isolated_devs": final_text["isolated"],
        "linux_bridges": bool(final_text["nft"]),
        "ovs_bridges": list(groups["ovs"].keys()),
        "quarantined": sorted(all_quarantined.keys()),
    }
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)

    ovs_str = (f", {sum(len(d) for d in groups['ovs'].values())} OVS netdevs"
               if groups["ovs"] else "")
    q_str = f", {len(all_quarantined)} quarantined" if all_quarantined else ""
    print(f"Applied ruleset: {netdev_count} netdevs total{ovs_str}, "
          f"{len(final_text['isolated'])} isolated ports{q_str}")
    return True, final_text["nft"]


def flush_ruleset():
    """Remove all pvefw-neo nftables tables and OVS flows."""
    # ── Flush nftables tables ──
    ret = subprocess.run(
        ["nft", "list", "tables"],
        capture_output=True, text=True,
    )
    if ret.returncode == 0:
        for line in ret.stdout.splitlines():
            line = line.strip()
            if "pvefw-neo" in line:
                parts = line.split()
                if len(parts) >= 3:
                    family = parts[1]
                    name = parts[2]
                    subprocess.run(
                        ["nft", "delete", "table", family, name],
                        capture_output=True, text=True,
                    )

    # ── Flush OVS bridges ──
    ret = subprocess.run(
        ["ovs-vsctl", "list-br"],
        capture_output=True, text=True,
    )
    if ret.returncode == 0:
        for br in ret.stdout.strip().splitlines():
            br = br.strip()
            if br:
                ovsgen.flush(br)

    print("Flushed all pvefw-neo state (nftables + OVS)")


def snapshot_ovs_ports():
    """Snapshot {bridge: {portname: ofport}} for all OVS bridges.

    Used to detect ofport reassignment (VM stop/start, live migrate).
    Returns empty dict if OVS not present or no bridges.
    """
    snapshot = {}
    ret = subprocess.run(
        ["ovs-vsctl", "list-br"],
        capture_output=True, text=True,
    )
    if ret.returncode != 0:
        return snapshot

    for br in ret.stdout.strip().splitlines():
        br = br.strip()
        if not br:
            continue
        ports = {}
        ret2 = subprocess.run(
            ["ovs-vsctl", "list-ports", br],
            capture_output=True, text=True,
        )
        if ret2.returncode != 0:
            continue
        for port in ret2.stdout.strip().splitlines():
            port = port.strip()
            if not port:
                continue
            ret3 = subprocess.run(
                ["ovs-vsctl", "get", "Interface", port, "ofport"],
                capture_output=True, text=True,
            )
            if ret3.returncode == 0:
                try:
                    ports[port] = int(ret3.stdout.strip())
                except ValueError:
                    pass
        snapshot[br] = ports
    return snapshot


def daemon_loop():
    """Main daemon loop: inotify (.fw/.conf) + OVS port polling."""
    try:
        import inotify.adapters
    except ImportError:
        print("python3-inotify not installed. Falling back to polling.",
              file=sys.stderr)
        _poll_loop()
        return

    print("pvefw-neo daemon starting (inotify mode)")

    # Initial apply. apply_ruleset returns the final (post-quarantine) text
    # which we cache for change detection on the next iteration.
    ir_rs, _, _, _ = generate_and_check()
    ok, applied_text = apply_ruleset(ir_rs)
    _last_nft_text = applied_text if ok else None

    # Snapshot OVS ports for change detection
    ovs_snapshot = snapshot_ovs_ports()

    # Watch for changes
    i = inotify.adapters.Inotify()
    i.add_watch(FW_DIR)

    # Also watch qemu-server and lxc config dirs
    for d in ("/etc/pve/qemu-server", "/etc/pve/lxc"):
        if os.path.isdir(d):
            i.add_watch(d)

    last_event_time = 0   # When the most recent triggering event arrived
    last_ovs_check = time.time()
    pending = False       # True when a re-apply is needed
    ovs_changed = False   # True if OVS topology changed since last apply
    DEBOUNCE_SECONDS = 2
    OVS_POLL_INTERVAL = 10

    for event in i.event_gen(yield_nones=True):
        now = time.time()

        # ── Periodic OVS port check ──
        if now - last_ovs_check >= OVS_POLL_INTERVAL:
            last_ovs_check = now
            new_snapshot = snapshot_ovs_ports()
            if new_snapshot != ovs_snapshot:
                print("OVS port topology changed, scheduling re-apply")
                ovs_snapshot = new_snapshot
                pending = True
                ovs_changed = True   # bypass nft no-op skip
                last_event_time = now

        # ── inotify event ──
        if event is not None:
            (_, type_names, path, filename) = event
            # Only react to write/move events. Reads are ignored: pvefw-neo's
            # own compile_ir() reads .fw files, generating IN_OPEN/IN_ACCESS
            # events that would otherwise feed back into this loop.
            WRITE_EVENTS = {"IN_CLOSE_WRITE", "IN_MODIFY",
                            "IN_MOVED_TO", "IN_DELETE", "IN_CREATE"}
            if (filename
                    and (filename.endswith(".fw") or filename.endswith(".conf"))
                    and any(t in WRITE_EVENTS for t in type_names)):
                pending = True
                last_event_time = now

        # ── Apply check ──
        # Run on every iteration (event or None) so filtered-out events
        # don't starve the apply check.
        if pending and (now - last_event_time) >= DEBOUNCE_SECONDS:
            ir_rs, nft_text, _, _ = generate_and_check()
            # Three triggers for apply:
            #   (1) rendered nft text changed → backend reload needed
            #   (2) OVS topology changed → reinstall flows
            #   (3) compile rejected any rule → materialize writeback even
            #       if no backend reload is needed. Without this, a user
            #       re-ticking a previously-rejected rule would leave the
            #       IR unchanged (rule still skipped by validator), so the
            #       no-op skip would bypass the .fw writeback + firewall
            #       log and the checkbox would never flip back.
            if (nft_text != _last_nft_text or ovs_changed
                    or ir_rs.compile_rejections):
                print(f"Reloading after {DEBOUNCE_SECONDS}s of quiet...")
                ok, applied_text = apply_ruleset(ir_rs)
                if ok:
                    _last_nft_text = applied_text
            ovs_snapshot = snapshot_ovs_ports()
            pending = False
            ovs_changed = False


def _poll_loop():
    """Fallback polling loop when inotify is not available."""
    print("pvefw-neo daemon starting (poll mode, interval=10s)")
    last_hash = None

    while True:
        ir_rs, nft_text, _, _ = generate_and_check()
        import hashlib
        h = hashlib.sha256(nft_text.encode()).hexdigest()
        # Apply if rendered text changed OR compile rejected any rule
        # (same reason as daemon_loop — IR-invisible rejections still
        # need to reach the writeback/log path).
        if h != last_hash or ir_rs.compile_rejections:
            ok, applied_text = apply_ruleset(ir_rs)
            if ok:
                last_hash = hashlib.sha256(applied_text.encode()).hexdigest()
        time.sleep(10)


def main():
    argp = argparse.ArgumentParser(
        prog="pvefw-neo",
        description="nftables firewall manager for Proxmox VE",
    )
    argp.add_argument("--dry-run", action="store_true",
                      help="Print generated nftables ruleset (linux bridge ports)")
    argp.add_argument("--apply", action="store_true",
                      help="Apply rules: auto-dispatch to nftables/OVS by bridge type")
    argp.add_argument("--daemon", action="store_true",
                      help="Run as daemon, watch for config changes")
    argp.add_argument("--preflight-check", action="store_true",
                      help="Run preflight checks only")
    argp.add_argument("--flush", action="store_true",
                      help="Remove all pvefw-neo state (nftables tables + OVS flows)")
    argp.add_argument("--dump-ir", action="store_true",
                      help="Compile and dump IR (intermediate representation)")
    argp.add_argument("--dump-ovs", metavar="BRIDGE",
                      help="Print generated OVS flows for a specific bridge (debug)")
    argp.add_argument("--apply-ovs", metavar="BRIDGE",
                      help="Apply OVS flows to a single bridge (debug)")
    argp.add_argument("--flush-ovs", metavar="BRIDGE",
                      help="Remove pvefw-neo flows from a single OVS bridge (debug)")

    args = argp.parse_args()

    if args.preflight_check:
        sys.exit(0 if preflight_check() else 1)

    if args.flush:
        flush_ruleset()
        sys.exit(0)

    if args.flush_ovs:
        ovsgen.flush(args.flush_ovs)
        print(f"Flushed pvefw-neo flows from {args.flush_ovs}")
        sys.exit(0)

    if args.dump_ovs:
        ir_rs = compile_ir()
        flows_text, _, _ = ovsgen.render(ir_rs, args.dump_ovs)
        print(flows_text)
        sys.exit(0)

    if args.apply_ovs:
        ir_rs = compile_ir()
        ok, err, _, _ = ovsgen.apply(ir_rs, args.apply_ovs)
        if ok:
            print(f"Applied OVS flows to {args.apply_ovs}")
        else:
            print(f"Failed to apply OVS flows to {args.apply_ovs}:\n{err}",
                  file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    if args.dump_ir:
        ir_rs = compile_ir()
        print(ir_rs.dump())
        sys.exit(0)

    if args.dry_run:
        ir_rs = compile_ir()
        nft_text, _ = nftgen.render(ir_rs)
        print(nft_text)
        sys.exit(0)

    if args.apply:
        if not preflight_check():
            sys.exit(1)
        ir_rs, _, _, _ = generate_and_check()
        ok, _ = apply_ruleset(ir_rs)
        sys.exit(0 if ok else 1)

    if args.daemon:
        if not preflight_check():
            sys.exit(1)

        # Handle signals
        def handle_hup(signum, frame):
            print("Received SIGHUP, reloading...")
            ir_rs, _, _, _ = generate_and_check()
            apply_ruleset(ir_rs)

        def handle_term(signum, frame):
            print("Received SIGTERM, flushing and exiting...")
            flush_ruleset()
            sys.exit(0)

        signal.signal(signal.SIGHUP, handle_hup)
        signal.signal(signal.SIGTERM, handle_term)

        daemon_loop()
        sys.exit(0)

    argp.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
