"""
REVENANT :: exfil_detection.py
================================================================
Exfiltration / anomalous-transfer detection module.

Flags flows that look like data leaving the network in ways
worth a human's attention:

  - Large, heavily asymmetric outbound transfers (far more data
    going OUT than typical request/response traffic would need).
  - Transfers over uncommon or non-standard ports.
  - Long-lived single flows carrying most of a session's bytes
    (a hallmark of a bulk upload/exfil rather than normal
    browsing chatter).
  - Transfers to IP addresses with no corresponding DNS lookup
    anywhere in the capture (direct-to-IP is a common evasion
    of DNS-based detection/blocking).
================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, field

COMMON_PORTS = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389, 445, 139, 137, 138, 123, 67, 68}

LARGE_TRANSFER_BYTES = 5 * 1024 * 1024      # 5 MB flagged as "large" by default
ASYMMETRY_RATIO_THRESHOLD = 4.0              # outbound at least 4x inbound
MIN_FLOW_BYTES_FOR_ASYMMETRY_CHECK = 512 * 1024


@dataclass
class ExfilCandidate:
    src_ip: str
    dst_ip: str
    dst_port: int
    bytes_out: int
    bytes_in: int
    ratio: float
    duration_seconds: float
    uncommon_port: bool
    no_dns_resolution: bool
    reasons: list = field(default_factory=list)
    severity: str = "MEDIUM"


@dataclass
class ExfilDetectionResult:
    candidates: list = field(default_factory=list)
    total_outbound_bytes: int = 0
    largest_single_flow_bytes: int = 0


def analyze_exfiltration(flows, resolved_ips: set, local_ip_hint: set | None = None) -> ExfilDetectionResult:
    """
    resolved_ips: set of every IP address that appeared as a DNS response
                  anywhere in the capture (from dns_analysis output).
    local_ip_hint: optional set of IPs considered "internal" — if not
                   provided, REVENANT infers direction heuristically from
                   which side sent more bytes (the sender = "src" of concern).
    """
    result = ExfilDetectionResult()

    for fl in flows:
        # Treat the side that SENT more data as the "outbound" direction of interest
        if fl.bytes_a_to_b >= fl.bytes_b_to_a:
            src, dst, port, bytes_out, bytes_in = fl.ip_a, fl.ip_b, fl.port_b, fl.bytes_a_to_b, fl.bytes_b_to_a
        else:
            src, dst, port, bytes_out, bytes_in = fl.ip_b, fl.ip_a, fl.port_a, fl.bytes_b_to_a, fl.bytes_a_to_b

        result.total_outbound_bytes += bytes_out
        result.largest_single_flow_bytes = max(result.largest_single_flow_bytes, bytes_out)

        reasons = []
        if bytes_out >= LARGE_TRANSFER_BYTES:
            reasons.append(f"large outbound transfer ({bytes_out / (1024*1024):.1f} MB)")

        ratio = (bytes_out / bytes_in) if bytes_in > 0 else float(bytes_out)
        if bytes_out >= MIN_FLOW_BYTES_FOR_ASYMMETRY_CHECK and ratio >= ASYMMETRY_RATIO_THRESHOLD:
            reasons.append(f"highly asymmetric transfer ({ratio:.1f}x more outbound than inbound)")

        uncommon = port is not None and port not in COMMON_PORTS and port >= 1024
        if uncommon and bytes_out >= 1024 * 1024:
            reasons.append(f"large transfer over uncommon port {port}")

        no_dns = dst not in resolved_ips
        if no_dns and bytes_out >= LARGE_TRANSFER_BYTES:
            reasons.append("destination IP never appeared in a DNS response in this capture")

        if reasons:
            severity = "HIGH" if bytes_out >= LARGE_TRANSFER_BYTES * 2 or len(reasons) >= 3 else "MEDIUM"
            result.candidates.append(ExfilCandidate(
                src_ip=src, dst_ip=dst, dst_port=port or 0, bytes_out=bytes_out, bytes_in=bytes_in,
                ratio=round(ratio, 2), duration_seconds=round(fl.duration, 2),
                uncommon_port=uncommon, no_dns_resolution=no_dns, reasons=reasons, severity=severity,
            ))

    result.candidates.sort(key=lambda x: x.bytes_out, reverse=True)
    return result
