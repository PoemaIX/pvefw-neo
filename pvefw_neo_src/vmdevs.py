"""VM/CT device discovery: map VMID + netX to tap/veth device names and read MACs."""

import os
import glob
import re


def parse_vm_config(vmid):
    """Parse a VM (qemu) config file, return dict of netX -> {bridge, mac, ...}."""
    path = f"/etc/pve/qemu-server/{vmid}.conf"
    if not os.path.isfile(path):
        return {}
    return _parse_net_lines(path, "virtio|e1000|rtl8139|vmxnet3")


def parse_ct_config(vmid):
    """Parse a CT (lxc) config file, return dict of netX -> {bridge, mac, ...}."""
    path = f"/etc/pve/lxc/{vmid}.conf"
    if not os.path.isfile(path):
        return {}
    return _parse_net_lines(path, "veth")


def _parse_net_lines(path, model_pattern):
    """Parse netX lines from a PVE config file.

    Stops at the first [section] marker — PVE uses [special:...] and
    [snapshot:...] sections for pending state and snapshots, whose net
    entries must not overwrite the current config.
    """
    nets = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            # Section markers: [special:cloudinit], [PENDING], [snapshot:foo]
            if line.startswith("["):
                break
            if line.startswith("#") or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()

            m = re.match(r"^net(\d+)$", key)
            if not m:
                continue

            net_id = int(m.group(1))
            net_info = {"id": net_id}

            # Parse key=value pairs
            for part in value.split(","):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    k = k.strip()
                    v = v.strip()
                    if k == "bridge":
                        net_info["bridge"] = v
                    elif k == "hwaddr":
                        net_info["mac"] = v.upper()
                    elif k == "name":
                        net_info["guest_name"] = v
                    elif k == "tag":
                        net_info["tag"] = int(v)
                    elif k == "firewall":
                        net_info["firewall"] = int(v)
                    else:
                        # model=MAC format: "virtio=BC:24:11:F9:2B:47"
                        mm = re.match(
                            rf"(?:{model_pattern})$", k
                        )
                        if mm and re.match(r'^[\dA-Fa-f:]+$', v):
                            net_info["mac"] = v.upper()

            nets[f"net{net_id}"] = net_info

    return nets


def get_tap_name(vmid, net_id):
    """Get tap device name for a VM. net_id is integer."""
    return f"tap{vmid}i{net_id}"


def get_veth_name(vmid, net_id):
    """Get veth device name for a CT. net_id is integer."""
    return f"veth{vmid}i{net_id}"


def get_device_name(vmid, net_id, is_ct=False):
    """Get the host-side device name for a VM/CT port."""
    if is_ct:
        return get_veth_name(vmid, net_id)
    return get_tap_name(vmid, net_id)


def device_exists(devname):
    """Check if a network device exists on the host."""
    return os.path.exists(f"/sys/class/net/{devname}")


def discover_vms():
    """Discover all VM IDs that have .fw firewall config files."""
    vmids = []
    for fw_path in sorted(glob.glob("/etc/pve/firewall/*.fw")):
        basename = os.path.basename(fw_path)
        if basename == "cluster.fw":
            continue
        m = re.match(r"^(\d+)\.fw$", basename)
        if m:
            vmid = int(m.group(1))
            vmids.append(vmid)
    return vmids


def is_ct(vmid):
    """Check if a VMID is a container (LXC)."""
    return os.path.isfile(f"/etc/pve/lxc/{vmid}.conf")


def is_vm(vmid):
    """Check if a VMID is a virtual machine (QEMU)."""
    return os.path.isfile(f"/etc/pve/qemu-server/{vmid}.conf")


def get_vm_nets(vmid):
    """Get network config for a VMID (auto-detect VM vs CT)."""
    if is_ct(vmid):
        return parse_ct_config(vmid), True
    elif is_vm(vmid):
        return parse_vm_config(vmid), False
    return {}, False
