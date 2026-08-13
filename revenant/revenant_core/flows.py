"""
REVENANT :: flows.py
================================================================
Conversation / flow reconstruction engine.

Groups raw frames into bidirectional 5-tuple flows (src_ip,
src_port, dst_ip, dst_port, proto) — the same fundamental unit
NetFlow, Zeek "conn.log" and every commercial NDR tool builds
everything else on top of. Every correlation module downstream
(scans, beaconing, exfiltration) consumes Flow objects rather
than raw frames.
================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional


@dataclass
class Flow:
    key: tuple
    proto: str
    ip_a: str
    port_a: Optional[int]
    ip_b: str
    port_b: Optional[int]

    first_seen: float = 0.0
    last_seen: float = 0.0
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0

    tcp_flags_seen: set = field(default_factory=set)
    syn_only: bool = False          # SYN sent, no SYN-ACK observed (possible scan)
    handshake_completed: bool = False
    reset_seen: bool = False

    frame_indices: list = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def total_bytes(self) -> int:
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def total_packets(self) -> int:
        return self.packets_a_to_b + self.packets_b_to_a


def _flow_key(f) -> tuple:
    """Canonical, direction-independent 5-tuple key."""
    sp = f.src_port or 0
    dp = f.dst_port or 0
    endpoint_a = (f.src_ip, sp)
    endpoint_b = (f.dst_ip, dp)
    if endpoint_a <= endpoint_b:
        return (f.proto, endpoint_a, endpoint_b)
    return (f.proto, endpoint_b, endpoint_a)


def build_flows(frames) -> list[Flow]:
    table: dict[tuple, Flow] = {}

    for f in frames:
        if not f.src_ip or not f.dst_ip:
            continue
        if f.proto not in ("TCP", "UDP"):
            continue

        key = _flow_key(f)
        if key not in table:
            proto, (ip_a, port_a), (ip_b, port_b) = key
            table[key] = Flow(
                key=key, proto=proto,
                ip_a=ip_a, port_a=port_a or None,
                ip_b=ip_b, port_b=port_b or None,
                first_seen=f.timestamp, last_seen=f.timestamp,
            )

        flow = table[key]
        flow.last_seen = max(flow.last_seen, f.timestamp)
        flow.first_seen = min(flow.first_seen, f.timestamp)
        flow.frame_indices.append(f.index)

        forward = (f.src_ip == flow.ip_a and (f.src_port or 0) == (flow.port_a or 0))
        if forward:
            flow.packets_a_to_b += 1
            flow.bytes_a_to_b += f.length
        else:
            flow.packets_b_to_a += 1
            flow.bytes_b_to_a += f.length

        if f.tcp_flags:
            for part in f.tcp_flags.split(","):
                flow.tcp_flags_seen.add(part)
            if "RST" in f.tcp_flags:
                flow.reset_seen = True

    for flow in table.values():
        if flow.proto == "TCP":
            has_syn = "SYN" in flow.tcp_flags_seen
            has_ack_from_both_sides = flow.packets_a_to_b > 0 and flow.packets_b_to_a > 0
            flow.handshake_completed = has_syn and has_ack_from_both_sides and flow.total_packets >= 2
            flow.syn_only = has_syn and flow.total_packets <= 1

    return sorted(table.values(), key=lambda x: x.first_seen)


def flows_by_source(flows: list[Flow]) -> dict:
    """Group flows by the endpoint that initiated first (ip_a as a proxy)."""
    grouped = defaultdict(list)
    for fl in flows:
        grouped[fl.ip_a].append(fl)
    return dict(grouped)
