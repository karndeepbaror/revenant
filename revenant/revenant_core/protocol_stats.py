"""
REVENANT :: protocol_stats.py
================================================================
Protocol distribution and top-talkers engine.

Answers the first questions any analyst asks about a capture:
  - What protocols are actually present, and how much of the
    capture (by packet count AND by byte volume) does each one
    represent?
  - Which hosts are talking the most (top talkers)?
  - Which host pairs are exchanging the most data (top pairs)?
  - What does the traffic-volume-over-time curve look like?
================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict, Counter


@dataclass
class ProtoStatsResult:
    packet_count: int = 0
    total_bytes: int = 0
    by_protocol_packets: dict = field(default_factory=dict)
    by_protocol_bytes: dict = field(default_factory=dict)
    by_protocol_pct: dict = field(default_factory=dict)

    top_talkers: list = field(default_factory=list)     # [(ip, bytes, packets)]
    top_pairs: list = field(default_factory=list)        # [(ip_a, ip_b, bytes, packets)]
    top_dst_ports: list = field(default_factory=list)    # [(port, packets)]

    timeline_buckets: list = field(default_factory=list)  # [(bucket_start_offset_sec, bytes)]
    bucket_width_seconds: float = 1.0

    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_ips_total: int = 0


def analyze_protocol_stats(frames, first_ts: float, duration: float, bucket_count: int = 60) -> ProtoStatsResult:
    result = ProtoStatsResult()
    result.packet_count = len(frames)

    proto_pkts = Counter()
    proto_bytes = Counter()
    talker_bytes = Counter()
    talker_pkts = Counter()
    pair_bytes = Counter()
    pair_pkts = Counter()
    dst_port_pkts = Counter()
    src_ips, dst_ips = set(), set()

    bucket_width = max(duration / bucket_count, 0.001) if duration > 0 else 1.0
    buckets = Counter()

    for f in frames:
        proto_pkts[f.proto] += 1
        proto_bytes[f.proto] += f.length
        result.total_bytes += f.length

        if f.src_ip:
            talker_bytes[f.src_ip] += f.length
            talker_pkts[f.src_ip] += 1
            src_ips.add(f.src_ip)
        if f.dst_ip:
            talker_bytes[f.dst_ip] += f.length
            talker_pkts[f.dst_ip] += 1
            dst_ips.add(f.dst_ip)

        if f.src_ip and f.dst_ip:
            pair = tuple(sorted([f.src_ip, f.dst_ip]))
            pair_bytes[pair] += f.length
            pair_pkts[pair] += 1

        if f.dst_port:
            dst_port_pkts[f.dst_port] += 1

        offset = f.timestamp - first_ts
        bucket_idx = int(offset / bucket_width) if bucket_width else 0
        buckets[bucket_idx] += f.length

    result.by_protocol_packets = dict(proto_pkts)
    result.by_protocol_bytes = dict(proto_bytes)
    if result.total_bytes:
        result.by_protocol_pct = {
            k: round((v / result.total_bytes) * 100, 2) for k, v in proto_bytes.items()
        }

    result.top_talkers = [
        (ip, talker_bytes[ip], talker_pkts[ip])
        for ip, _ in talker_bytes.most_common(15)
    ]
    result.top_pairs = [
        (a, b, pair_bytes[(a, b)], pair_pkts[(a, b)])
        for (a, b), _ in pair_bytes.most_common(15)
    ]
    result.top_dst_ports = dst_port_pkts.most_common(15)

    result.bucket_width_seconds = round(bucket_width, 3)
    max_bucket = max(buckets.keys()) if buckets else 0
    result.timeline_buckets = [
        (round(i * bucket_width, 2), buckets.get(i, 0)) for i in range(max_bucket + 1)
    ]

    result.unique_src_ips = len(src_ips)
    result.unique_dst_ips = len(dst_ips)
    result.unique_ips_total = len(src_ips | dst_ips)

    return result
