"""
REVENANT :: risk_score.py
================================================================
Composite investigation risk scoring engine.

Rolls up every module's independent findings into a single
transparent 0-100 score for the ENTIRE capture, with a full
breakdown of exactly which findings contributed how many points.
Mirrors how a SOC analyst would triage a case: no single alert
is "the verdict" — the accumulated weight of evidence is.
================================================================
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class RiskFactor:
    label: str
    points: int
    detail: str
    category: str


@dataclass
class InvestigationRiskResult:
    score: int = 0
    verdict: str = "MINIMAL"
    verdict_color: str = "green"
    factors: list = field(default_factory=list)


def compute_investigation_risk(dns_result, scan_result, beacon_result, exfil_result,
                                tls_result, arp_result, http_result) -> InvestigationRiskResult:
    factors = []
    score = 0

    if scan_result.vertical_scans:
        top = scan_result.vertical_scans[0]
        pts = 20 if top.severity == "HIGH" else 12
        score += pts
        factors.append(RiskFactor(
            "Vertical Port Scan Detected", pts,
            f"{top.scanner_ip} probed {top.distinct_count} ports on {top.target}.", "Reconnaissance",
        ))
    if scan_result.horizontal_scans:
        top = scan_result.horizontal_scans[0]
        pts = 20 if top.severity == "HIGH" else 12
        score += pts
        factors.append(RiskFactor(
            "Horizontal Host Scan Detected", pts,
            f"{top.scanner_ip} probed port {top.target} across {top.distinct_count} hosts.", "Reconnaissance",
        ))

    if beacon_result.candidates:
        top = beacon_result.candidates[0]
        pts = 25 if top.regularity_score >= 85 else 15
        score += pts
        factors.append(RiskFactor(
            "Clock-Like C2 Beaconing Pattern", pts,
            f"{top.src_ip} -> {top.dst_ip}:{top.dst_port} — {top.connection_count} connections, "
            f"{top.regularity_score}% regularity, ~{top.mean_interval_seconds}s interval.", "Command & Control",
        ))
        if len(beacon_result.candidates) > 1:
            pts2 = min(10, (len(beacon_result.candidates) - 1) * 3)
            score += pts2
            factors.append(RiskFactor(
                "Multiple Beacon Candidates", pts2,
                f"{len(beacon_result.candidates)} distinct host pairs show beacon-like regularity.",
                "Command & Control",
            ))

    if exfil_result.candidates:
        high = [c for c in exfil_result.candidates if c.severity == "HIGH"]
        pts = 25 if high else 12
        score += pts
        top = exfil_result.candidates[0]
        factors.append(RiskFactor(
            "Anomalous Outbound Data Transfer", pts,
            f"{top.src_ip} -> {top.dst_ip}:{top.dst_port} sent {top.bytes_out/1024:.0f} KB "
            f"({'; '.join(top.reasons)}).", "Exfiltration",
        ))

    if dns_result.suspected_dga_domains:
        pts = min(18, len(dns_result.suspected_dga_domains) * 2)
        score += pts
        factors.append(RiskFactor(
            "DGA-Style Domain(s) Queried", pts,
            f"{len(dns_result.suspected_dga_domains)} domain(s) show algorithmically-generated "
            f"lexical patterns.", "Command & Control",
        ))
    if dns_result.suspected_tunneling:
        pts = 18
        score += pts
        factors.append(RiskFactor(
            "Possible DNS Tunneling", pts,
            f"{len(dns_result.suspected_tunneling)} suffix/domain pattern(s) consistent with "
            f"DNS-based data smuggling.", "Exfiltration",
        ))

    if arp_result.conflicting_ips:
        high = [c for c in arp_result.conflicting_ips if c["severity"] == "HIGH"]
        pts = 22 if high else 14
        score += pts
        factors.append(RiskFactor(
            "ARP Spoofing / Cache Poisoning Indicators", pts,
            f"{len(arp_result.conflicting_ips)} IP address(es) claimed by multiple MAC addresses.",
            "Man-in-the-Middle",
        ))

    if tls_result.ja3_reused_across_hosts:
        pts = 10
        score += pts
        factors.append(RiskFactor(
            "Single TLS Client Fingerprint Reused Across Many Hosts", pts,
            f"{len(tls_result.ja3_reused_across_hosts)} JA3 fingerprint(s) each connecting to 3+ "
            f"distinct destinations — consistent with automated/malware TLS stacks.", "Command & Control",
        ))

    if http_result.plaintext_credentials_found:
        pts = min(15, len(http_result.plaintext_credentials_found) * 5)
        score += pts
        factors.append(RiskFactor(
            "Plaintext Credentials Observed Over HTTP", pts,
            f"{len(http_result.plaintext_credentials_found)} instance(s) of credential-like data "
            f"sent in cleartext.", "Data Exposure",
        ))
    if http_result.suspicious_user_agents:
        pts = min(8, len(http_result.suspicious_user_agents) * 2)
        score += pts
        factors.append(RiskFactor(
            "Non-Browser User-Agent Strings Observed", pts,
            f"{len(http_result.suspicious_user_agents)} distinct non-browser User-Agent value(s) "
            f"(scripts/tools making HTTP requests).", "Reconnaissance",
        ))

    score = max(0, min(100, score))

    if score >= 70:
        verdict, color = "CRITICAL", "bold red"
    elif score >= 45:
        verdict, color = "HIGH", "red"
    elif score >= 22:
        verdict, color = "MODERATE", "yellow"
    elif score >= 8:
        verdict, color = "LOW", "cyan"
    else:
        verdict, color = "MINIMAL", "green"

    factors.sort(key=lambda f: f.points, reverse=True)
    return InvestigationRiskResult(score=score, verdict=verdict, verdict_color=color, factors=factors)
