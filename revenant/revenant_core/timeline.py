"""
REVENANT :: timeline.py
================================================================
Timeline correlation module.

This is where "correlate" actually happens: every module above
found isolated facts (a DNS query here, a scan there, a beacon
somewhere else). This module merges all of them into a single,
chronologically sorted investigation timeline — so an analyst
can literally read the story of what happened, in order, instead
of cross-referencing seven separate tables by hand.
================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class TimelineEvent:
    timestamp: float
    relative_seconds: float
    category: str          # DNS / SCAN / BEACON / EXFIL / TLS / HTTP / ARP
    severity: str           # INFO / LOW / MEDIUM / HIGH
    summary: str
    detail: dict = field(default_factory=dict)


def build_timeline(first_ts: float, dns_result, scan_result, beacon_result,
                    exfil_result, tls_result, http_result, arp_result) -> list:
    events = []

    for q in dns_result.suspected_dga_domains[:15]:
        events.append(TimelineEvent(
            timestamp=q.timestamp, relative_seconds=round(q.timestamp - first_ts, 3),
            category="DNS", severity="MEDIUM",
            summary=f"Suspicious DGA-style domain queried: {q.query_name} (score {q.dga_score})",
            detail={"src_ip": q.src_ip, "domain": q.query_name, "dga_score": q.dga_score},
        ))

    for t in dns_result.suspected_tunneling[:10]:
        events.append(TimelineEvent(
            timestamp=first_ts, relative_seconds=0.0,
            category="DNS", severity="HIGH",
            summary=f"Possible DNS tunneling indicator on suffix '{t.get('suffix','')}' — {t.get('reason','')}",
            detail=t,
        ))

    for s in scan_result.vertical_scans[:15]:
        events.append(TimelineEvent(
            timestamp=s.first_seen, relative_seconds=round(s.first_seen - first_ts, 3),
            category="SCAN", severity=s.severity,
            summary=f"{s.scanner_ip} probed {s.distinct_count} distinct ports on {s.target} (vertical scan)",
            detail={"scanner": s.scanner_ip, "target": s.target, "ports": s.distinct_count},
        ))
    for s in scan_result.horizontal_scans[:15]:
        events.append(TimelineEvent(
            timestamp=s.first_seen, relative_seconds=round(s.first_seen - first_ts, 3),
            category="SCAN", severity=s.severity,
            summary=f"{s.scanner_ip} probed port {s.target} across {s.distinct_count} distinct hosts (horizontal scan)",
            detail={"scanner": s.scanner_ip, "port": s.target, "hosts": s.distinct_count},
        ))

    for b in beacon_result.candidates[:15]:
        events.append(TimelineEvent(
            timestamp=first_ts, relative_seconds=0.0,
            category="BEACON", severity="HIGH" if b.regularity_score >= 80 else "MEDIUM",
            summary=(f"{b.src_ip} -> {b.dst_ip}:{b.dst_port} shows clock-like beaconing "
                      f"({b.connection_count} conns, every ~{b.mean_interval_seconds}s, "
                      f"regularity {b.regularity_score}%)"),
            detail={"src": b.src_ip, "dst": b.dst_ip, "port": b.dst_port,
                    "regularity": b.regularity_score, "interval": b.mean_interval_seconds},
        ))

    for e in exfil_result.candidates[:15]:
        events.append(TimelineEvent(
            timestamp=first_ts, relative_seconds=0.0,
            category="EXFIL", severity=e.severity,
            summary=(f"{e.src_ip} -> {e.dst_ip}:{e.dst_port} sent {e.bytes_out/1024:.0f} KB "
                      f"({'; '.join(e.reasons)})"),
            detail={"src": e.src_ip, "dst": e.dst_ip, "port": e.dst_port, "bytes_out": e.bytes_out},
        ))

    for c in arp_result.conflicting_ips[:10]:
        events.append(TimelineEvent(
            timestamp=first_ts, relative_seconds=0.0,
            category="ARP", severity=c["severity"],
            summary=f"IP {c['ip']} claimed by {c['mac_count']} different MAC addresses — possible ARP spoofing",
            detail=c,
        ))

    for hello in tls_result.client_hellos:
        if hello.sni and any(x in hello.sni.lower() for x in (".xyz", ".top", ".club", ".tk", ".gq")):
            events.append(TimelineEvent(
                timestamp=hello.timestamp, relative_seconds=round(hello.timestamp - first_ts, 3),
                category="TLS", severity="LOW",
                summary=f"TLS connection to uncommon-TLD SNI '{hello.sni}' (JA3 {hello.ja3_hash[:12]}…)",
                detail={"sni": hello.sni, "ja3": hello.ja3_hash, "dst_ip": hello.dst_ip},
            ))

    for cred in http_result.plaintext_credentials_found[:10]:
        events.append(TimelineEvent(
            timestamp=first_ts, relative_seconds=0.0,
            category="HTTP", severity="HIGH",
            summary=f"Plaintext credential-like data observed from {cred['src_ip']} -> {cred['dst_ip']}",
            detail=cred,
        ))

    events.sort(key=lambda e: e.relative_seconds)
    return events
