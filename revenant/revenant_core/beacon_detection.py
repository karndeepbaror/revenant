"""
REVENANT :: beacon_detection.py
================================================================
Beaconing detection module.

Command-and-control malware almost universally "checks in" to
its controller on a regular interval — every 30 seconds, every
5 minutes, etc. — because that's operationally simpler to build
and manage than fully event-driven communication.

For every host pair with enough repeated connections, REVENANT
computes the inter-arrival times between connections and scores
how *regular* that rhythm is (low coefficient of variation =
highly regular = beacon-like). This is the same core statistical
technique used by RITA, Zeek's beacon detection, and most
commercial NDR "C2 beacon" detectors.
================================================================
"""

from __future__ import annotations
import statistics
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class BeaconCandidate:
    src_ip: str
    dst_ip: str
    dst_port: int
    connection_count: int
    mean_interval_seconds: float
    stdev_interval_seconds: float
    coefficient_of_variation: float
    span_seconds: float
    regularity_score: float          # 0-100, higher = more clock-like
    jitter_percent: float
    sample_intervals: list = field(default_factory=list)


@dataclass
class BeaconDetectionResult:
    candidates: list = field(default_factory=list)
    total_pairs_evaluated: int = 0


MIN_CONNECTIONS = 6
MIN_SPAN_SECONDS = 30.0


def analyze_beaconing(flows) -> BeaconDetectionResult:
    result = BeaconDetectionResult()

    pair_events = defaultdict(list)   # (src, dst, port) -> [start_times]
    for fl in flows:
        if fl.proto != "TCP":
            continue
        key = (fl.ip_a, fl.ip_b, fl.port_b if fl.port_b else fl.port_a)
        pair_events[key].append(fl.first_seen)

    result.total_pairs_evaluated = len(pair_events)

    for (ip_a, ip_b, port), times in pair_events.items():
        if len(times) < MIN_CONNECTIONS:
            continue
        times = sorted(times)
        span = times[-1] - times[0]
        if span < MIN_SPAN_SECONDS:
            continue

        intervals = [t2 - t1 for t1, t2 in zip(times, times[1:])]
        intervals = [i for i in intervals if i > 0.001]
        if len(intervals) < MIN_CONNECTIONS - 1:
            continue

        mean_i = statistics.mean(intervals)
        stdev_i = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        cv = (stdev_i / mean_i) if mean_i > 0 else 999

        # Regularity score: CV of 0 => perfectly clock-like => 100.
        # CV of >= 1.0 (as noisy as the mean itself) => 0.
        regularity = max(0.0, round((1 - min(cv, 1.0)) * 100, 2))
        jitter_pct = round(min(cv, 1.0) * 100, 2)

        if regularity >= 55:
            result.candidates.append(BeaconCandidate(
                src_ip=ip_a, dst_ip=ip_b, dst_port=port or 0,
                connection_count=len(times), mean_interval_seconds=round(mean_i, 2),
                stdev_interval_seconds=round(stdev_i, 2), coefficient_of_variation=round(cv, 3),
                span_seconds=round(span, 1), regularity_score=regularity, jitter_percent=jitter_pct,
                sample_intervals=[round(i, 2) for i in intervals[:20]],
            ))

    result.candidates.sort(key=lambda x: x.regularity_score, reverse=True)
    return result
