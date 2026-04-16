"""PVE WebUI ICMP type name → (type, code) mapping.

Source: pvemanagerlib.js ICMP_TYPE_NAMES_STORE / ICMPV6_TYPE_NAMES_STORE.
Used by nftgen + ovsgen to render PVE-named ICMP types into backend syntax.
"""

# ICMPv4: PVE name → (type, code_or_None)
# code=None means match any code (type-level match only).
ICMPV4 = {
    "any":                       (None, None),
    "echo-reply":                (0, None),
    "destination-unreachable":   (3, None),
    "network-unreachable":       (3, 0),
    "host-unreachable":          (3, 1),
    "protocol-unreachable":      (3, 2),
    "port-unreachable":          (3, 3),
    "fragmentation-needed":      (3, 4),
    "source-route-failed":       (3, 5),
    "network-unknown":           (3, 6),
    "host-unknown":              (3, 7),
    "network-prohibited":        (3, 9),
    "host-prohibited":           (3, 10),
    "TOS-network-unreachable":   (3, 11),
    "TOS-host-unreachable":      (3, 12),
    "communication-prohibited":  (3, 13),
    "host-precedence-violation": (3, 14),
    "precedence-cutoff":         (3, 15),
    "source-quench":             (4, None),
    "redirect":                  (5, None),
    "network-redirect":          (5, 0),
    "host-redirect":             (5, 1),
    "TOS-network-redirect":      (5, 2),
    "TOS-host-redirect":         (5, 3),
    "echo-request":              (8, None),
    "router-advertisement":      (9, None),
    "router-solicitation":       (10, None),
    "time-exceeded":             (11, None),
    "ttl-zero-during-transit":   (11, 0),
    "ttl-zero-during-reassembly":(11, 1),
    "parameter-problem":         (12, None),
    "ip-header-bad":             (12, 0),
    "required-option-missing":   (12, 1),
    "timestamp-request":         (13, None),
    "timestamp-reply":           (14, None),
    "address-mask-request":      (17, None),
    "address-mask-reply":        (18, None),
}

# ICMPv6: PVE name → (type, code_or_None)
ICMPV6 = {
    "destination-unreachable":   (1, None),
    "no-route":                  (1, 0),
    "communication-prohibited":  (1, 1),
    "beyond-scope":              (1, 2),
    "address-unreachable":       (1, 3),
    "port-unreachable":          (1, 4),
    "failed-policy":             (1, 5),
    "reject-route":              (1, 6),
    "packet-too-big":            (2, None),
    "time-exceeded":             (3, None),
    "ttl-zero-during-transit":   (3, 0),
    "ttl-zero-during-reassembly":(3, 1),
    "parameter-problem":         (4, None),
    "bad-header":                (4, 0),
    "unknown-header-type":       (4, 1),
    "unknown-option":            (4, 2),
    "echo-request":              (128, None),
    "echo-reply":                (129, None),
    "router-solicitation":       (133, None),
    "router-advertisement":      (134, None),
    "neighbour-solicitation":    (135, None),
    "neighbor-solicitation":     (135, None),
    "neighbour-advertisement":   (136, None),
    "neighbor-advertisement":    (136, None),
    "redirect":                  (137, None),
}

# nft name mapping: PVE ICMPv6 names → nft-accepted names.
# nft uses "nd-*" prefix for NDP types. Other names match between PVE and nft.
NFT_ICMPV6_NAME = {
    "router-solicitation":       "nd-router-solicit",
    "router-advertisement":      "nd-router-advert",
    "neighbour-solicitation":    "nd-neighbor-solicit",
    "neighbor-solicitation":     "nd-neighbor-solicit",
    "neighbour-advertisement":   "nd-neighbor-advert",
    "neighbor-advertisement":    "nd-neighbor-advert",
    "redirect":                  "nd-redirect",
}

# Reverse: nft name → (type, code) for backends that receive nft-named
# ICMPv6 types from sugar handlers (which emit nft names directly).
NFT_ICMPV6_NUM = {nft: ICMPV6[pve]
                   for pve, nft in NFT_ICMPV6_NAME.items()
                   if pve in ICMPV6}
