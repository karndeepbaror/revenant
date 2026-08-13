"""
REVENANT :: scan_detection.py
================================================================
Port / host scan detection module.

Operates on reconstructed Flow objects (see flows.py) rather
than raw frames, and looks for the two canonical scan shapes:

  Vertical scan   — one source IP touching many distinct
                     destination PORTS on a single destination
                     host in a short window (e.g. `nmap -p-`).

  Horizontal scan — one source IP touching the same
                     destination PORT across many distinct
                     destination HOSTS (e.g. sweeping a subnet
                     for one open service).

Both are scored using SYN-heavy, low-completion-rate flows —
the fingerprint of a scanner that sends a SYN and immediately
moves on, rather than completing a real connection.
================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class ScanEvent:
    scanner_ip: str
    scan_type: str          # "vertical" or "horizontal"
    target: str              # dst_ip for vertical, dst_port for horizontal
    distinct_count: int
    total_attempts: int
    syn_only_ratio: float
    first_seen: float
    last_seen: float
    ports_or_hosts_sample: list = field(default_factory=list)
    severity: str = "MEDIUM"


@dataclass
class ScanDetectionResult:
    vertical_scans: list = field(default_factory=list)
    horizontal_scans: list = field(default_factory=list)
    total_syn_only_flows: int = 0
    likely_scanner_ips: list = field(default_factory=list)


VERTICAL_PORT_THRESHOLD = 15
HORIZONTAL_HOST_THRESHOLD = 10
SYN_ONLY_RATIO_THRESHOLD = 0.6


def analyze_scans(flows) -> ScanDetectionResult:
    result = ScanDetectionResult()

    scanner_to_host_ports = defaultdict(lambda: defaultdict(set))
    scanner_to_port_hosts = defaultdict(lambda: defaultdict(set))
    scanner_flow_counts = defaultdict(int)
    scanner_syn_only_counts = defaultdict(int)
    scanner_time_range = {}

    for fl in flows:
        if fl.proto != "TCP":
            continue

        initiator, target_ip, target_port = fl.ip_a, fl.ip_b, fl.port_b
        if fl.bytes_b_to_a > fl.bytes_a_to_b:
            initiator, target_ip, target_port = fl.ip_b, fl.ip_a, fl.port_a

        if target_port is None:
            continue

        scanner_flow_counts[initiator] += 1
        if fl.syn_only:
            scanner_syn_only_counts[initiator] += 1
            result.total_syn_only_flows += 1

        scanner_to_host_ports[initiator][target_ip].add(target_port)
        scanner_to_port_hosts[initiator][target_port].add(target_ip)

        lo, hi = scanner_time_range.get(initiator, (fl.first_seen, fl.last_seen))
        scanner_time_range[initiator] = (min(lo, fl.first_seen), max(hi, fl.last_seen))

    flagged_scanners = set()

    for scanner, host_ports in scanner_to_host_ports.items():
        for target_ip, ports in host_ports.items():
            if len(ports) >= VERTICAL_PORT_THRESHOLD:
                total = scanner_flow_counts[scanner]
                syn_ratio = scanner_syn_only_counts[scanner] / total if total else 0
                lo, hi = scanner_time_range.get(scanner, (0, 0))
                severity = "HIGH" if len(ports) >= 100 or syn_ratio >= SYN_ONLY_RATIO_THRESHOLD else "MEDIUM"
                result.vertical_scans.append(ScanEvent(
                    scanner_ip=scanner, scan_type="vertical", target=target_ip,
                    distinct_count=len(ports), total_attempts=total, syn_only_ratio=round(syn_ratio, 2),
                    first_seen=lo, last_seen=hi, ports_or_hosts_sample=sorted(ports)[:25],
                    severity=severity,
                ))
                flagged_scanners.add(scanner)

    for scanner, port_hosts in scanner_to_port_hosts.items():
        for target_port, hosts in port_hosts.items():
            if len(hosts) >= HORIZONTAL_HOST_THRESHOLD:
                total = scanner_flow_counts[scanner]
                syn_ratio = scanner_syn_only_counts[scanner] / total if total else 0
                lo, hi = scanner_time_range.get(scanner, (0, 0))
                severity = "HIGH" if len(hosts) >= 50 or syn_ratio >= SYN_ONLY_RATIO_THRESHOLD else "MEDIUM"
                result.horizontal_scans.append(ScanEvent(
                    scanner_ip=scanner, scan_type="horizontal", target=str(target_port),
                    distinct_count=len(hosts), total_attempts=total, syn_only_ratio=round(syn_ratio, 2),
                    first_seen=lo, last_seen=hi, ports_or_hosts_sample=sorted(hosts)[:25],
                    severity=severity,
                ))
                flagged_scanners.add(scanner)

    result.vertical_scans.sort(key=lambda x: x.distinct_count, reverse=True)
    result.horizontal_scans.sort(key=lambda x: x.distinct_count, reverse=True)
    result.likely_scanner_ips = sorted(flagged_scanners)

    return result
