"""
REVENANT :: arp_analysis.py
================================================================
ARP investigation module.

The classic ARP spoofing / cache-poisoning fingerprint is
simple and reliable: in a healthy network, one IP address maps
to exactly one MAC address. The moment REVENANT sees a single
IP claimed by two or more *different* MAC addresses via ARP
"is-at" replies, that's either a legitimate DHCP/NIC change —
or an active man-in-the-middle attack redirecting traffic.
================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class ARPBinding:
    ip: str
    mac_addresses: list = field(default_factory=list)   # chronological list of (mac, first_seen_ts, count)


@dataclass
class ARPAnomalyResult:
    total_arp_frames: int = 0
    unique_ip_mac_pairs: int = 0
    conflicting_ips: list = field(default_factory=list)   # list of dicts: ip, macs=[(mac,count)], flag
    gratuitous_arp_count: int = 0
    request_count: int = 0
    reply_count: int = 0


def analyze_arp(frames) -> ARPAnomalyResult:
    result = ARPAnomalyResult()
    ip_to_macs = defaultdict(lambda: defaultdict(int))
    ip_to_first_seen = {}

    for f in frames:
        if not f.is_arp:
            continue
        result.total_arp_frames += 1

        if f.arp_op == 1:
            result.request_count += 1
        elif f.arp_op == 2:
            result.reply_count += 1

        if f.arp_op == 2 and f.src_ip and f.arp_hwsrc:
            ip_to_macs[f.src_ip][f.arp_hwsrc] += 1
            ip_to_first_seen.setdefault((f.src_ip, f.arp_hwsrc), f.timestamp)

        if f.arp_op == 1 and f.src_ip == f.dst_ip and f.arp_hwsrc:
            result.gratuitous_arp_count += 1

    result.unique_ip_mac_pairs = sum(len(macs) for macs in ip_to_macs.values())

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            mac_list = sorted(macs.items(), key=lambda x: x[1], reverse=True)
            result.conflicting_ips.append({
                "ip": ip,
                "macs": mac_list,
                "mac_count": len(mac_list),
                "severity": "HIGH" if len(mac_list) >= 3 else "MEDIUM",
            })

    result.conflicting_ips.sort(key=lambda x: x["mac_count"], reverse=True)
    return result
