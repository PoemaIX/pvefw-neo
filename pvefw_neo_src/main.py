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
from . import vmdevs


RULESET_PATH = "/run/pvefw-neo/ruleset.nft"
STATE_PATH = "/run/pvefw-neo/state.json"
FW_DIR = "/etc/pve/firewall"


def preflight_check():
    """Check preconditions before starting."""
    errors = []

    # Check conflicting services
    for svc in ("pve-firewall.service", "proxmox-firewall.service"):
        ret = subprocess.run(
            ["systemctl", "is-active", svc],
            capture_output=True, text=True,
        )
        if ret.stdout.strip() == "active":
            errors.append(f"{svc} is still running. Stop it first.")

    # Check cluster.fw enable flag
    from . import parser
    cluster = parser.parse_cluster_fw()
    if cluster.options.enable:
        errors.append(
            "cluster.fw has 'enable: 1'. pvefw-neo requires PVE firewall "
            "to be disabled at datacenter level."
        )

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return False
    return True


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
    """Compile → render → syntax-check.

    Returns (ir_rs, nft_text, isolated_devs, ovs_groups) or (ir_rs, None, ...) on failure.
    """
    ir_rs = compile_ir()
    groups = group_netdevs_by_backend(ir_rs)

    # Render nftables for linux bridge ports
    nft_text, isolated_devs = nftgen.render(ir_rs, groups["linux"])

    # Syntax check
    os.makedirs("/run/pvefw-neo", exist_ok=True)
    tmp_path = RULESET_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(nft_text)

    ret = subprocess.run(
        ["nft", "-c", "-f", tmp_path],
        capture_output=True, text=True,
    )
    if ret.returncode != 0:
        print(f"nft syntax check failed:\n{ret.stderr}", file=sys.stderr)
        return ir_rs, None, isolated_devs, groups["ovs"]

    return ir_rs, nft_text, isolated_devs, groups["ovs"]


def apply_ruleset(ir_rs, nft_text, isolated_devs, ovs_groups):
    """Apply nftables ruleset, OVS flows, and bridge isolation."""
    os.makedirs("/run/pvefw-neo", exist_ok=True)

    # ── Apply nftables (linux bridge ports) ──
    with open(RULESET_PATH, "w") as f:
        f.write(nft_text)

    ret = subprocess.run(
        ["nft", "-f", RULESET_PATH],
        capture_output=True, text=True,
    )
    if ret.returncode != 0:
        print(f"nft apply failed:\n{ret.stderr}", file=sys.stderr)
        return False

    # ── Apply OVS flows (per OVS bridge) ──
    ovs_ok = True
    for br_name, devs in ovs_groups.items():
        if not ovsgen.apply(ir_rs, br_name, devs):
            print(f"OVS apply failed for {br_name}", file=sys.stderr)
            ovs_ok = False

    # ── Apply bridge isolation (always reconcile, even if empty) ──
    bridge.apply_isolation(isolated_devs)

    # ── Save state ──
    netdev_count = len(ir_rs.netdevs)
    state = {
        "applied_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "netdev_count": netdev_count,
        "isolated_devs": isolated_devs,
        "linux_bridges": True if nft_text else False,
        "ovs_bridges": list(ovs_groups.keys()),
    }
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)

    ovs_str = (f", {sum(len(d) for d in ovs_groups.values())} OVS netdevs"
               if ovs_groups else "")
    print(f"Applied ruleset: {netdev_count} netdevs total{ovs_str}, "
          f"{len(isolated_devs)} isolated ports")
    return ovs_ok


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

    # Initial apply
    ir_rs, nft_text, iso_devs, ovs_groups = generate_and_check()
    if nft_text is not None:
        apply_ruleset(ir_rs, nft_text, iso_devs, ovs_groups)
    _last_nft_text = nft_text

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
            ir_rs, nft_text, iso_devs, ovs_groups = generate_and_check()
            # Apply if nft text changed OR OVS topology changed
            if nft_text is not None and (nft_text != _last_nft_text or ovs_changed):
                print(f"Reloading after {DEBOUNCE_SECONDS}s of quiet...")
                apply_ruleset(ir_rs, nft_text, iso_devs, ovs_groups)
                _last_nft_text = nft_text
            ovs_snapshot = snapshot_ovs_ports()
            pending = False
            ovs_changed = False


def _poll_loop():
    """Fallback polling loop when inotify is not available."""
    print("pvefw-neo daemon starting (poll mode, interval=10s)")
    last_hash = None

    while True:
        ir_rs, nft_text, iso_devs, ovs_groups = generate_and_check()
        if nft_text is not None:
            import hashlib
            h = hashlib.sha256(nft_text.encode()).hexdigest()
            if h != last_hash:
                apply_ruleset(ir_rs, nft_text, iso_devs, ovs_groups)
                last_hash = h
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
        flows_text = ovsgen.render(ir_rs, args.dump_ovs)
        print(flows_text)
        sys.exit(0)

    if args.apply_ovs:
        ir_rs = compile_ir()
        if ovsgen.apply(ir_rs, args.apply_ovs):
            print(f"Applied OVS flows to {args.apply_ovs}")
        else:
            print(f"Failed to apply OVS flows to {args.apply_ovs}", file=sys.stderr)
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
        ir_rs, nft_text, iso_devs, ovs_groups = generate_and_check()
        if nft_text is None:
            sys.exit(1)
        if not apply_ruleset(ir_rs, nft_text, iso_devs, ovs_groups):
            sys.exit(1)
        sys.exit(0)

    if args.daemon:
        if not preflight_check():
            sys.exit(1)

        # Handle signals
        def handle_hup(signum, frame):
            print("Received SIGHUP, reloading...")
            ir_rs, nft_text, iso_devs, ovs_groups = generate_and_check()
            if nft_text is not None:
                apply_ruleset(ir_rs, nft_text, iso_devs, ovs_groups)

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
