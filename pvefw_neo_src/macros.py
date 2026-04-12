"""Parse PVE firewall macros from Firewall.pm with hardcoded fallback."""

import re
import os

# Hardcoded fallback for common macros
FALLBACK_MACROS = {
    "SSH": [{"action": "PARAM", "proto": "tcp", "dport": "22"}],
    "HTTP": [{"action": "PARAM", "proto": "tcp", "dport": "80"}],
    "HTTPS": [{"action": "PARAM", "proto": "tcp", "dport": "443"}],
    "DNS": [
        {"action": "PARAM", "proto": "udp", "dport": "53"},
        {"action": "PARAM", "proto": "tcp", "dport": "53"},
    ],
    "BGP": [{"action": "PARAM", "proto": "tcp", "dport": "179"}],
    "Ping": [{"action": "PARAM", "proto": "icmp"}],
    "DHCPfwd": [
        {"action": "PARAM", "proto": "udp", "dport": "67:68", "sport": "67:68"},
    ],
    "FTP": [{"action": "PARAM", "proto": "tcp", "dport": "21"}],
    "NTP": [{"action": "PARAM", "proto": "udp", "dport": "123"}],
    "SMTP": [{"action": "PARAM", "proto": "tcp", "dport": "25"}],
    "SMTPS": [{"action": "PARAM", "proto": "tcp", "dport": "465"}],
    "Submission": [{"action": "PARAM", "proto": "tcp", "dport": "587"}],
    "IMAP": [{"action": "PARAM", "proto": "tcp", "dport": "143"}],
    "IMAPS": [{"action": "PARAM", "proto": "tcp", "dport": "993"}],
    "POP3": [{"action": "PARAM", "proto": "tcp", "dport": "110"}],
    "POP3S": [{"action": "PARAM", "proto": "tcp", "dport": "995"}],
    "Telnet": [{"action": "PARAM", "proto": "tcp", "dport": "23"}],
    "SNMP": [
        {"action": "PARAM", "proto": "udp", "dport": "161:162"},
        {"action": "PARAM", "proto": "tcp", "dport": "161"},
    ],
    "MySQL": [{"action": "PARAM", "proto": "tcp", "dport": "3306"}],
    "PostgreSQL": [{"action": "PARAM", "proto": "tcp", "dport": "5432"}],
    "RDP": [{"action": "PARAM", "proto": "tcp", "dport": "3389"}],
    "VNC": [
        {"action": "PARAM", "proto": "tcp", "dport": "5900:5999"},
    ],
    "Syslog": [{"action": "PARAM", "proto": "udp", "dport": "514"}],
    "LDAP": [
        {"action": "PARAM", "proto": "tcp", "dport": "389"},
    ],
    "LDAPS": [
        {"action": "PARAM", "proto": "tcp", "dport": "636"},
    ],
    "Finger": [{"action": "PARAM", "proto": "tcp", "dport": "79"}],
    "Web": [
        {"action": "PARAM", "proto": "tcp", "dport": "80"},
        {"action": "PARAM", "proto": "tcp", "dport": "443"},
    ],
    "BitTorrent": [
        {"action": "PARAM", "proto": "tcp", "dport": "6881:6889"},
        {"action": "PARAM", "proto": "udp", "dport": "6881"},
    ],
    "BitTorrent32": [
        {"action": "PARAM", "proto": "tcp", "dport": "6881:6999"},
        {"action": "PARAM", "proto": "udp", "dport": "6881"},
    ],
    "Ceph": [
        {"action": "PARAM", "proto": "tcp", "dport": "6789"},
        {"action": "PARAM", "proto": "tcp", "dport": "3300"},
        {"action": "PARAM", "proto": "tcp", "dport": "6800:7300"},
    ],
    "GRE": [{"action": "PARAM", "proto": "47"}],
    "IPsec": [
        {"action": "PARAM", "proto": "udp", "dport": "500", "sport": "500"},
        {"action": "PARAM", "proto": "50"},
    ],
}


def parse_firewall_pm(path="/usr/share/perl5/PVE/Firewall.pm"):
    """Parse $pve_fw_macros from Firewall.pm. Returns dict of macro_name -> entries."""
    if not os.path.isfile(path):
        return {}

    content = open(path).read()
    m = re.search(r'\$pve_fw_macros\s*=\s*\{(.+?)\n\};', content, re.DOTALL)
    if not m:
        return {}

    block = m.group(1)
    macros = {}

    for mm in re.finditer(r"'(\w+)'\s*=>\s*\[(.*?)\]", block, re.DOTALL):
        name = mm.group(1)
        entries_block = mm.group(2)
        entries = []

        for em in re.finditer(
            r"\{\s*action\s*=>\s*'(\w+)'"
            r"(?:,\s*proto\s*=>\s*'([\w]+)')?"
            r"(?:,\s*dport\s*=>\s*'([\d:,]+)')?"
            r"(?:,\s*sport\s*=>\s*'([\d:,]+)')?"
            r"\s*\}",
            entries_block,
        ):
            entry = {"action": em.group(1)}
            if em.group(2):
                entry["proto"] = em.group(2)
            if em.group(3):
                entry["dport"] = em.group(3)
            if em.group(4):
                entry["sport"] = em.group(4)
            entries.append(entry)

        if entries:
            macros[name] = entries

    return macros


_cached_macros = None


def get_macros():
    """Get macros, using parsed Firewall.pm with fallback."""
    global _cached_macros
    if _cached_macros is not None:
        return _cached_macros

    macros = dict(FALLBACK_MACROS)
    try:
        parsed = parse_firewall_pm()
        if parsed:
            macros.update(parsed)
    except Exception:
        pass

    _cached_macros = macros
    return macros


def reset_cache():
    """Reset macro cache (for testing/reload)."""
    global _cached_macros
    _cached_macros = None
