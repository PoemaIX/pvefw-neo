#!/usr/bin/env python3
"""pvefw-neo test suite — in-guest agent.

Runs INSIDE the test VM and CT (pushed to /tmp/pvefw-agent.py by setup.py).
Pure stdlib — `socket` + `struct`, no scapy — so it starts instantly and needs
nothing installed beyond python3. Runs as root.

It only ever forges *single, stateless* frames: a packet is a stack of small
composable layers (`eth [+ vlan] + (ip4|ip6) + (icmp|icmp6|udp) + payload`),
each a short struct.pack. Anything stateful (real TCP handshakes, established
flows) is left to the kernel — `connect` uses a normal socket, reachability
uses the `ping` binary on the host side. Capture/verification stays with
tcpdump (libpcap) on the host side; the agent only sends.

Subcommands:
  send    --kind {icmp,dhcp,ra,ns,na} --iface IF --eth-src MAC [...]
  connect --dst IP --dport N [--src IP] [--timeout S]   -> prints OPEN/CLOSED
  listen  --port N                                      -> self-daemonising echo server
"""

import argparse
import os
import socket
import struct
import sys

ETH_IP4 = 0x0800
ETH_IP6 = 0x86DD
ETH_VLAN = 0x8100
IPPROTO_ICMP = 1
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58


# ─────────────────────────── primitives ───────────────────────────
def _csum(data):
    """Internet one's-complement checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _mac(s):
    return bytes(int(b, 16) for b in s.split(":"))


def _ip4(s):
    return socket.inet_aton(s)


def _ip6(s):
    return socket.inet_pton(socket.AF_INET6, s)


# ─────────────────────────── layers ───────────────────────────
def _eth(dst, src, ethertype, vlan=None):
    hdr = _mac(dst) + _mac(src)
    if vlan is not None:
        # 802.1Q: TPID, TCI (pcp/dei 0 + 12-bit vid), then the real ethertype.
        return hdr + struct.pack("!HHH", ETH_VLAN, vlan & 0x0FFF, ethertype)
    return hdr + struct.pack("!H", ethertype)


def _ip4_hdr(src, dst, proto, payload_len):
    total = 20 + payload_len
    hdr = struct.pack("!BBHHHBBH4s4s",
                      0x45, 0, total, 0x1234, 0x4000, 64, proto, 0,
                      _ip4(src), _ip4(dst))
    return hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]


def _ip6_hdr(src, dst, nexthdr, payload_len, hlim=255):
    return struct.pack("!IHBB16s16s",
                       0x60000000, payload_len, nexthdr, hlim,
                       _ip6(src), _ip6(dst))


def _icmp4(type_, code, rest4, data):
    msg = struct.pack("!BBH", type_, code, 0) + rest4 + data
    return msg[:2] + struct.pack("!H", _csum(msg)) + msg[4:]


def _icmp6(type_, code, body, ip6_src, ip6_dst):
    msg = struct.pack("!BBH", type_, code, 0) + body
    pseudo = (_ip6(ip6_src) + _ip6(ip6_dst)
              + struct.pack("!I", len(msg)) + b"\x00\x00\x00"
              + struct.pack("!B", IPPROTO_ICMPV6))
    return msg[:2] + struct.pack("!H", _csum(pseudo + msg)) + msg[4:]


def _udp(sport, dport, payload):
    # UDP checksum 0 is legal (and ignored) for IPv4 — fine for a test frame.
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


# ─────────────────────────── frame builders ───────────────────────────
def _build_icmp(a):
    icmp = _icmp4(8, 0, struct.pack("!HH", 0x4242, 1), b"pvefw-neo-test")
    ip = _ip4_hdr(a.ip_src, a.ip_dst, IPPROTO_ICMP, len(icmp))
    return _eth(a.eth_dst, a.eth_src, ETH_IP4, a.vlan) + ip + icmp


def _build_dhcp(a):
    # BOOTP (op=BOOTREPLY) + magic cookie + a minimal DHCPOFFER option set.
    # The @neo:nodhcp rule only matches on UDP 67->68, so the payload just
    # needs to be plausibly DHCP-shaped.
    bootp = (b"\x02\x01\x06\x00" + b"\x00" * 232
             + bytes((99, 130, 83, 99)) + bytes((53, 1, 2, 255)))
    udp = _udp(67, 68, bootp)
    ip = _ip4_hdr(a.ip_src, a.ip_dst, IPPROTO_UDP, len(udp))
    return _eth(a.eth_dst, a.eth_src, ETH_IP4, a.vlan) + ip + udp


def _build_ra(a):
    # cur_hop_limit, flags, router_lifetime, reachable_time, retrans_timer
    body = struct.pack("!BBHII", 64, 0, 1800, 0, 0)
    msg = _icmp6(134, 0, body, a.ip6_src, a.ip6_dst)
    ip = _ip6_hdr(a.ip6_src, a.ip6_dst, IPPROTO_ICMPV6, len(msg))
    return _eth(a.eth_dst, a.eth_src, ETH_IP6, a.vlan) + ip + msg


def _build_ns(a):
    body = struct.pack("!I", 0) + _ip6(a.tgt)            # reserved + target
    msg = _icmp6(135, 0, body, a.ip6_src, a.ip6_dst)
    ip = _ip6_hdr(a.ip6_src, a.ip6_dst, IPPROTO_ICMPV6, len(msg))
    return _eth(a.eth_dst, a.eth_src, ETH_IP6, a.vlan) + ip + msg


def _build_na(a):
    body = struct.pack("!I", 0x60000000) + _ip6(a.tgt)   # solicited+override + target
    msg = _icmp6(136, 0, body, a.ip6_src, a.ip6_dst)
    ip = _ip6_hdr(a.ip6_src, a.ip6_dst, IPPROTO_ICMPV6, len(msg))
    return _eth(a.eth_dst, a.eth_src, ETH_IP6, a.vlan) + ip + msg


_BUILDERS = {
    "icmp": _build_icmp,
    "dhcp": _build_dhcp,
    "ra": _build_ra,
    "ns": _build_ns,
    "na": _build_na,
}


# ─────────────────────────── subcommands ───────────────────────────
def cmd_send(a):
    if a.kind in ("ra", "ns", "na") and not a.eth_dst:
        a.eth_dst = "33:33:00:00:00:01"          # IPv6 all-nodes multicast MAC
    if not a.eth_dst:
        sys.exit("--eth-dst is required for this kind")
    frame = _BUILDERS[a.kind](a)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    try:
        s.bind((a.iface, 0))
        for _ in range(a.count):
            s.send(frame)
    finally:
        s.close()


def cmd_connect(a):
    src = (a.src, 0) if a.src else None
    try:
        c = socket.create_connection((a.dst, a.dport), timeout=a.timeout,
                                     source_address=src)
        c.close()
        sys.stdout.write("OPEN\n")
    except OSError:
        sys.stdout.write("CLOSED\n")


def cmd_listen(a):
    # Double-fork into a detached daemon so the caller (and its SSH channel)
    # returns immediately. The grandchild redirects all std fds to /dev/null.
    if os.fork() > 0:
        return
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    dn = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(dn, fd)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", a.port))
    except OSError:
        os._exit(0)                              # someone already listening
    srv.listen(16)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            continue
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                conn.sendall(chunk)
        except OSError:
            pass
        finally:
            conn.close()


# ─────────────────────────── CLI ───────────────────────────
def main():
    p = argparse.ArgumentParser(description="pvefw-neo in-guest test agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("send", help="forge + send a single stateless frame")
    s.add_argument("--kind", required=True, choices=list(_BUILDERS))
    s.add_argument("--iface", required=True)
    s.add_argument("--eth-src", required=True)
    s.add_argument("--eth-dst")
    s.add_argument("--ip-src", default="0.0.0.0")
    s.add_argument("--ip-dst", default="0.0.0.0")
    s.add_argument("--ip6-src", default="fe80::1")
    s.add_argument("--ip6-dst", default="ff02::1")
    s.add_argument("--tgt", default="fe80::1")
    s.add_argument("--vlan", type=int)
    s.add_argument("--count", type=int, default=1)
    s.set_defaults(fn=cmd_send)

    c = sub.add_parser("connect", help="TCP connect probe -> OPEN/CLOSED")
    c.add_argument("--dst", required=True)
    c.add_argument("--dport", type=int, required=True)
    c.add_argument("--src")
    c.add_argument("--timeout", type=float, default=3.0)
    c.set_defaults(fn=cmd_connect)

    l = sub.add_parser("listen", help="background TCP echo listener")
    l.add_argument("--port", type=int, required=True)
    l.set_defaults(fn=cmd_listen)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
