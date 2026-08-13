"""
REVENANT :: ioc_extraction.py
================================================================
IOC (Indicator of Compromise) aggregation module.

Pulls together everything every other module already found
into one consolidated, exportable indicator list — the artifact
an analyst actually copies into a ticket, a blocklist, or a
threat-intel platform at the end of an investigation.
================================================================
"""

from __future__ import annotations
import ipaddress
from dataclasses import dataclass, field


@dataclass
class IOCSet:
    all_ips: list = field(default_factory=list)
    external_ips: list = field(default_factory=list)
    internal_ips: list = field(default_factory=list)
    all_domains: list = field(default_factory=list)
    suspicious_domains: list = field(default_factory=list)
    ja3_hashes: list = field(default_factory=list)
    carved_file_hashes: list = field(default_factory=list)
    scanner_ips: list = field(default_factory=list)
    beacon_pairs: list = field(default_factory=list)
    arp_conflict_ips: list = field(default_factory=list)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def extract_iocs(proto_stats, dns_result, tls_result, http_result,
                  scan_result, beacon_result, arp_result) -> IOCSet:
    ioc = IOCSet()

    all_ips = set()
    for ip, *_ in proto_stats.top_talkers:
        all_ips.add(ip)
    for a, b, *_ in proto_stats.top_pairs:
        all_ips.add(a)
        all_ips.add(b)

    ioc.all_ips = sorted(all_ips)
    ioc.internal_ips = sorted(ip for ip in all_ips if _is_private(ip))
    ioc.external_ips = sorted(ip for ip in all_ips if not _is_private(ip))

    ioc.all_domains = sorted(set(d for d, _ in dns_result.top_domains))
    ioc.suspicious_domains = sorted(set(
        [q.query_name for q in dns_result.suspected_dga_domains] +
        [t.get("suffix", "") for t in dns_result.suspected_tunneling]
    ))
    ioc.suspicious_domains = [d for d in ioc.suspicious_domains if d]

    ioc.ja3_hashes = [h for h, _, _ in tls_result.unique_ja3_hashes]
    ioc.carved_file_hashes = [
        {"sha256": obj.sha256, "content_type": obj.content_type, "size_bytes": obj.size_bytes,
         "filename": obj.filename_guess}
        for obj in http_result.carved_objects
    ]

    ioc.scanner_ips = list(scan_result.likely_scanner_ips)
    ioc.beacon_pairs = [f"{c.src_ip} -> {c.dst_ip}:{c.dst_port}" for c in beacon_result.candidates]
    ioc.arp_conflict_ips = [c["ip"] for c in arp_result.conflicting_ips]

    return ioc
