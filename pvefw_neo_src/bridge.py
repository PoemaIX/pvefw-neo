"""Bridge port isolation management."""

import os
import subprocess


def set_isolated(devname, isolated=True):
    """Set bridge port isolation on/off for a single device."""
    val = "on" if isolated else "off"
    try:
        subprocess.run(
            ["bridge", "link", "set", "dev", devname, "isolated", val],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Warning: failed to set isolation on {devname}: {e.stderr}")
        return False


def list_bridge_ports():
    """List all linux bridge ports (devnames mastered by a bridge).

    Excludes OVS-managed ports (master = ovs-system).
    """
    devs = []
    if not os.path.isdir("/sys/class/net"):
        return devs
    for entry in os.listdir("/sys/class/net"):
        master_link = f"/sys/class/net/{entry}/master"
        if not os.path.islink(master_link):
            continue
        master = os.path.basename(os.readlink(master_link))
        if master == "ovs-system":
            continue
        devs.append(entry)
    return devs


def reconcile_isolation(want_isolated_devs):
    """Set isolated=on for desired devs, isolated=off for all other linux bridge ports.

    Idempotent: every linux bridge port ends up in the correct state.
    """
    want = set(want_isolated_devs)
    all_ports = set(list_bridge_ports())

    for dev in all_ports - want:
        set_isolated(dev, False)
    for dev in want:
        set_isolated(dev, True)


def apply_isolation(isolation_devs):
    """Backwards-compat alias: reconcile to the given list."""
    reconcile_isolation(isolation_devs)
