"""
REVENANT :: report.py
================================================================
Rendering layer. Turns every module's structured results into
the final terminal investigation report, plus optional JSON/HTML
case-file export.
================================================================
"""

from __future__ import annotations
import json
import time
import dataclasses
import html as html_escape
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule


def _section(console: Console, icon: str, title: str, color: str = "cyan"):
    console.print()
    console.print(Rule(f"[bold {color}]{icon}  {title}[/bold {color}]", style=color, align="left"))


def _human_bytes(n: int) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n} B"


def _ts_human(ts: float) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)


# ---------------------------------------------------------------- overview

def render_overview(console: Console, meta):
    _section(console, "◆", "CASE FILE — CAPTURE OVERVIEW", "bright_cyan")
    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_column(style="dim white", justify="right")
    table.add_column(style="bold white")
    table.add_row("Evidence File", meta.filepath)
    table.add_row("File Size", _human_bytes(meta.file_size_bytes))
    table.add_row("Total Packets", f"{meta.packet_count:,}")
    table.add_row("Capture Start", _ts_human(meta.first_ts))
    table.add_row("Capture End", _ts_human(meta.last_ts))
    table.add_row("Duration", f"{meta.duration_seconds:.2f} seconds")
    table.add_row("Load Time", f"{meta.load_seconds:.2f}s")
    if meta.truncated:
        table.add_row("[yellow]Truncated[/yellow]", f"analysis limited to first {meta.truncation_limit:,} packets")
    console.print(table)


# ---------------------------------------------------------------- protocol stats

def render_protocol_stats(console: Console, stats):
    _section(console, "▓", "PROTOCOL DISTRIBUTION & TOP TALKERS", "magenta")

    table = Table(show_header=True, box=None, padding=(0, 2, 0, 0))
    table.add_column("protocol", style="bold white")
    table.add_column("packets", justify="right", style="white")
    table.add_column("bytes", justify="right", style="white")
    table.add_column("% of traffic", justify="right", style="magenta")
    for proto, pkt_count in sorted(stats.by_protocol_packets.items(), key=lambda x: -x[1]):
        byte_count = stats.by_protocol_bytes.get(proto, 0)
        pct = stats.by_protocol_pct.get(proto, 0)
        table.add_row(proto, f"{pkt_count:,}", _human_bytes(byte_count), f"{pct}%")
    console.print(table)

    console.print()
    console.print(f"  [dim]unique src IPs: {stats.unique_src_ips}   unique dst IPs: {stats.unique_dst_ips}"
                   f"   unique IPs total: {stats.unique_ips_total}[/dim]")

    console.print()
    console.print("  [bold]Top talkers (by bytes)[/bold]")
    tt = Table(show_header=True, box=None, padding=(0, 2, 0, 2))
    tt.add_column("ip", style="cyan")
    tt.add_column("bytes", justify="right", style="white")
    tt.add_column("packets", justify="right", style="dim white")
    for ip, b, p in stats.top_talkers[:10]:
        tt.add_row(ip, _human_bytes(b), f"{p:,}")
    console.print(tt)


def render_traffic_sparkline(console: Console, stats):
    if not stats.timeline_buckets:
        return
    max_bytes = max(b for _, b in stats.timeline_buckets) or 1
    chars = " ▁▂▃▄▅▆▇█"
    line = "".join(chars[min(int((b / max_bytes) * (len(chars) - 1)), len(chars) - 1)] for _, b in stats.timeline_buckets)
    console.print()
    console.print(f"  [dim]traffic volume over time (bucket ≈ {stats.bucket_width_seconds}s)[/dim]")
    console.print(f"  [bold bright_cyan]{line}[/bold bright_cyan]")


# ---------------------------------------------------------------- flows

def render_flow_summary(console: Console, flows):
    _section(console, "⟁", "CONVERSATIONS (FLOWS)", "blue")
    console.print(f"  Total reconstructed flows: [bold]{len(flows):,}[/bold]")
    tcp_flows = [f for f in flows if f.proto == "TCP"]
    udp_flows = [f for f in flows if f.proto == "UDP"]
    completed = [f for f in tcp_flows if f.handshake_completed]
    syn_only = [f for f in tcp_flows if f.syn_only]
    console.print(f"  TCP flows: {len(tcp_flows):,}  (completed handshake: {len(completed):,}, "
                  f"SYN-only/no response: {len(syn_only):,})")
    console.print(f"  UDP flows: {len(udp_flows):,}")

    console.print()
    console.print("  [bold]Longest-lived flows[/bold]")
    top = sorted(flows, key=lambda f: f.total_bytes, reverse=True)[:10]
    table = Table(show_header=True, box=None, padding=(0, 2, 0, 2))
    table.add_column("proto", style="dim white")
    table.add_column("endpoint A", style="cyan")
    table.add_column("endpoint B", style="cyan")
    table.add_column("bytes", justify="right", style="white")
    table.add_column("packets", justify="right", style="white")
    table.add_column("duration", justify="right", style="dim white")
    for fl in top:
        a = f"{fl.ip_a}:{fl.port_a}" if fl.port_a else fl.ip_a
        b = f"{fl.ip_b}:{fl.port_b}" if fl.port_b else fl.ip_b
        table.add_row(fl.proto, a, b, _human_bytes(fl.total_bytes), str(fl.total_packets), f"{fl.duration:.1f}s")
    console.print(table)


# ---------------------------------------------------------------- DNS

def render_dns(console: Console, dns):
    _section(console, "◈", "DNS INVESTIGATION", "green")
    console.print(f"  Total DNS messages: {dns.total_queries:,}   Unique domains: {dns.unique_domains:,}"
                  f"   NXDOMAIN responses: {dns.nxdomain_count}")

    if dns.top_domains:
        console.print()
        console.print("  [bold]Most queried domains[/bold]")
        t = Table(show_header=False, box=None, padding=(0, 2, 0, 2))
        t.add_column(style="cyan")
        t.add_column(justify="right", style="dim white")
        for d, c in dns.top_domains[:10]:
            t.add_row(d, str(c))
        console.print(t)

    if dns.suspected_dga_domains:
        console.print()
        console.print("  [bold red]⚠ Suspected DGA-style domains[/bold red]")
        t = Table(show_header=True, box=None, padding=(0, 2, 0, 2))
        t.add_column("domain", style="red")
        t.add_column("score", justify="right", style="bold red")
        t.add_column("src ip", style="dim white")
        for q in dns.suspected_dga_domains[:10]:
            t.add_row(q.query_name, str(q.dga_score), q.src_ip)
        console.print(t)

    if dns.suspected_tunneling:
        console.print()
        console.print("  [bold red]⚠ Possible DNS tunneling indicators[/bold red]")
        for t in dns.suspected_tunneling[:10]:
            console.print(f"    ▸ {t.get('suffix','')} — {t.get('reason','')} "
                           f"({t.get('query_count','?')} queries)")


# ---------------------------------------------------------------- HTTP

def render_http(console: Console, http):
    _section(console, "◇", "HTTP INVESTIGATION", "yellow")
    console.print(f"  Requests observed: {len(http.requests):,}   Responses observed: {len(http.responses):,}"
                   f"   Objects carved: {len(http.carved_objects):,}")

    if http.top_hosts:
        console.print()
        console.print("  [bold]Most contacted HTTP hosts[/bold]")
        t = Table(show_header=False, box=None, padding=(0, 2, 0, 2))
        t.add_column(style="cyan")
        t.add_column(justify="right", style="dim white")
        for h, c in http.top_hosts[:10]:
            t.add_row(h, str(c))
        console.print(t)

    if http.carved_objects:
        console.print()
        console.print("  [bold]Carved objects (transferred file-like bodies)[/bold]")
        t = Table(show_header=True, box=None, padding=(0, 2, 0, 2))
        t.add_column("content-type", style="white")
        t.add_column("size", justify="right", style="white")
        t.add_column("sha256", style="dim white")
        t.add_column("filename", style="cyan")
        for obj in http.carved_objects[:10]:
            t.add_row(obj.content_type, _human_bytes(obj.size_bytes), obj.sha256[:20] + "…", obj.filename_guess or "-")
        console.print(t)

    if http.suspicious_user_agents:
        console.print()
        console.print("  [bold yellow]⚠ Non-browser User-Agent strings[/bold yellow]")
        for ua in http.suspicious_user_agents[:10]:
            console.print(f"    ▸ {ua}")

    if http.plaintext_credentials_found:
        console.print()
        console.print("  [bold red]⚠ Plaintext credential-like data observed[/bold red]")
        for c in http.plaintext_credentials_found[:10]:
            console.print(f"    ▸ {c['src_ip']} -> {c['dst_ip']}  ({', '.join(c['indicators'])})")


# ---------------------------------------------------------------- TLS

def render_tls(console: Console, tls):
    _section(console, "⌬", "TLS INVESTIGATION", "bright_magenta")
    console.print(f"  ClientHellos observed: {len(tls.client_hellos):,}   Unique SNI: {tls.unique_sni_count:,}"
                   f"   No-SNI connections: {tls.connections_without_sni}")

    if tls.top_sni:
        console.print()
        console.print("  [bold]Most contacted TLS destinations (SNI)[/bold]")
        t = Table(show_header=False, box=None, padding=(0, 2, 0, 2))
        t.add_column(style="cyan")
        t.add_column(justify="right", style="dim white")
        for s, c in tls.top_sni[:10]:
            t.add_row(s, str(c))
        console.print(t)

    if tls.unique_ja3_hashes:
        console.print()
        console.print("  [bold]JA3 client fingerprints observed[/bold]")
        t = Table(show_header=True, box=None, padding=(0, 2, 0, 2))
        t.add_column("ja3 hash", style="white")
        t.add_column("count", justify="right", style="dim white")
        t.add_column("example sni", style="cyan")
        for h, c, sni in tls.unique_ja3_hashes[:10]:
            t.add_row(h, str(c), sni or "-")
        console.print(t)

    if tls.ja3_reused_across_hosts:
        console.print()
        console.print("  [bold yellow]⚠ JA3 fingerprint reused across many destinations[/bold yellow]")
        for r in tls.ja3_reused_across_hosts[:10]:
            console.print(f"    ▸ {r['ja3_hash']} → {r['distinct_dst_ips']} distinct hosts "
                           f"(e.g. {r['example_sni']})")


# ---------------------------------------------------------------- ARP

def render_arp(console: Console, arp):
    _section(console, "▚", "ARP INTEGRITY", "orange3")
    console.print(f"  ARP frames: {arp.total_arp_frames:,}   requests: {arp.request_count:,}"
                   f"   replies: {arp.reply_count:,}   gratuitous: {arp.gratuitous_arp_count:,}")
    if arp.conflicting_ips:
        console.print()
        console.print("  [bold red]⚠ IP addresses claimed by multiple MAC addresses[/bold red]")
        t = Table(show_header=True, box=None, padding=(0, 2, 0, 2))
        t.add_column("ip", style="red")
        t.add_column("mac count", justify="right", style="bold red")
        t.add_column("macs", style="dim white")
        t.add_column("severity", style="yellow")
        for c in arp.conflicting_ips[:10]:
            macs_str = ", ".join(f"{m}({n})" for m, n in c["macs"][:4])
            t.add_row(c["ip"], str(c["mac_count"]), macs_str, c["severity"])
        console.print(t)
    else:
        console.print("  [green]No IP/MAC conflicts detected.[/green]")


# ---------------------------------------------------------------- scans

def render_scans(console: Console, scan):
    _section(console, "☠", "SCAN DETECTION", "red")
    if not scan.vertical_scans and not scan.horizontal_scans:
        console.print("  [green]No port or host scanning patterns detected.[/green]")
        return

    if scan.vertical_scans:
        console.print("  [bold]Vertical scans (many ports, one host)[/bold]")
        t = Table(show_header=True, box=None, padding=(0, 2, 0, 2))
        t.add_column("scanner", style="red")
        t.add_column("target host", style="white")
        t.add_column("ports hit", justify="right", style="bold red")
        t.add_column("syn-only %", justify="right", style="dim white")
        t.add_column("severity", style="yellow")
        for s in scan.vertical_scans[:10]:
            t.add_row(s.scanner_ip, s.target, str(s.distinct_count), f"{s.syn_only_ratio*100:.0f}%", s.severity)
        console.print(t)

    if scan.horizontal_scans:
        console.print()
        console.print("  [bold]Horizontal scans (one port, many hosts)[/bold]")
        t = Table(show_header=True, box=None, padding=(0, 2, 0, 2))
        t.add_column("scanner", style="red")
        t.add_column("target port", style="white")
        t.add_column("hosts hit", justify="right", style="bold red")
        t.add_column("syn-only %", justify="right", style="dim white")
        t.add_column("severity", style="yellow")
        for s in scan.horizontal_scans[:10]:
            t.add_row(s.scanner_ip, s.target, str(s.distinct_count), f"{s.syn_only_ratio*100:.0f}%", s.severity)
        console.print(t)


# ---------------------------------------------------------------- beaconing

def render_beacons(console: Console, beacon):
    _section(console, "◉", "BEACONING DETECTION", "bright_red")
    if not beacon.candidates:
        console.print("  [green]No clock-like periodic connection patterns detected.[/green]")
        return
    t = Table(show_header=True, box=None, padding=(0, 2, 0, 0))
    t.add_column("src", style="cyan")
    t.add_column("dst", style="cyan")
    t.add_column("port", justify="right", style="white")
    t.add_column("conns", justify="right", style="white")
    t.add_column("avg interval", justify="right", style="white")
    t.add_column("regularity", justify="right", style="bold red")
    for b in beacon.candidates[:10]:
        t.add_row(b.src_ip, b.dst_ip, str(b.dst_port), str(b.connection_count),
                   f"{b.mean_interval_seconds}s", f"{b.regularity_score}%")
    console.print(t)


# ---------------------------------------------------------------- exfil

def render_exfil(console: Console, exfil):
    _section(console, "▲", "EXFILTRATION / ANOMALOUS TRANSFER DETECTION", "dark_orange")
    console.print(f"  Total outbound-classified bytes: {_human_bytes(exfil.total_outbound_bytes)}   "
                   f"largest single flow: {_human_bytes(exfil.largest_single_flow_bytes)}")
    if not exfil.candidates:
        console.print("  [green]No anomalous transfer patterns detected.[/green]")
        return
    console.print()
    t = Table(show_header=True, box=None, padding=(0, 2, 0, 0))
    t.add_column("src", style="cyan")
    t.add_column("dst", style="cyan")
    t.add_column("port", justify="right", style="white")
    t.add_column("out", justify="right", style="bold white")
    t.add_column("in", justify="right", style="dim white")
    t.add_column("severity", style="yellow")
    t.add_column("reasons", style="dim white")
    for c in exfil.candidates[:10]:
        t.add_row(c.src_ip, c.dst_ip, str(c.dst_port), _human_bytes(c.bytes_out), _human_bytes(c.bytes_in),
                   c.severity, "; ".join(c.reasons)[:60])
    console.print(t)


# ---------------------------------------------------------------- IOCs

def render_iocs(console: Console, ioc):
    _section(console, "⟐", "INDICATORS OF COMPROMISE (IOC SUMMARY)", "bright_yellow")
    console.print(f"  External IPs: {len(ioc.external_ips)}   Internal IPs: {len(ioc.internal_ips)}   "
                   f"Suspicious domains: {len(ioc.suspicious_domains)}   "
                   f"JA3 hashes: {len(ioc.ja3_hashes)}   Carved files: {len(ioc.carved_file_hashes)}   "
                   f"Scanner IPs: {len(ioc.scanner_ips)}   Beacon pairs: {len(ioc.beacon_pairs)}")

    if ioc.suspicious_domains:
        console.print()
        console.print("  [bold]Suspicious domains[/bold]")
        for d in ioc.suspicious_domains[:15]:
            console.print(f"    ▸ {d}")

    if ioc.scanner_ips:
        console.print()
        console.print("  [bold]Scanner IPs[/bold]")
        console.print("    " + ", ".join(ioc.scanner_ips[:15]))

    if ioc.beacon_pairs:
        console.print()
        console.print("  [bold]Beacon pairs[/bold]")
        for p in ioc.beacon_pairs[:15]:
            console.print(f"    ▸ {p}")


# ---------------------------------------------------------------- timeline

def render_timeline(console: Console, events):
    _section(console, "⏱", "INVESTIGATION TIMELINE", "white")
    if not events:
        console.print("  [dim]No notable correlated events to display on the timeline.[/dim]")
        return
    t = Table(show_header=True, box=None, padding=(0, 2, 0, 0))
    t.add_column("t+", justify="right", style="dim white")
    t.add_column("category", style="cyan")
    t.add_column("severity", style="yellow")
    t.add_column("event", style="white")
    sev_color = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim white"}
    for e in events[:40]:
        t.add_row(f"{e.relative_seconds:.1f}s", e.category,
                   f"[{sev_color.get(e.severity,'white')}]{e.severity}[/{sev_color.get(e.severity,'white')}]",
                   e.summary)
    console.print(t)
    if len(events) > 40:
        console.print(f"  [dim]…and {len(events) - 40} more event(s) in the exported report.[/dim]")


# ---------------------------------------------------------------- risk / verdict

def _risk_bar(score: int, width: int = 40) -> str:
    filled = int((score / 100) * width)
    if score >= 70:
        color = "bold red"
    elif score >= 45:
        color = "red"
    elif score >= 22:
        color = "yellow"
    elif score >= 8:
        color = "cyan"
    else:
        color = "green"
    bar = "█" * filled + "░" * (width - filled)
    return f"[{color}]{bar}[/{color}]"


def render_risk_score(console: Console, risk):
    _section(console, "☣", "COMPOSITE INVESTIGATION RISK SCORE", "red")
    console.print(f"  {_risk_bar(risk.score)}  [bold]{risk.score}/100[/bold]  →  "
                  f"[{risk.verdict_color}]{risk.verdict}[/{risk.verdict_color}]")
    console.print()
    if risk.factors:
        t = Table(show_header=True, box=None, padding=(0, 2, 0, 0))
        t.add_column("pts", style="bold red", width=5, justify="right")
        t.add_column("category", style="dim cyan")
        t.add_column("factor", style="bold white")
        t.add_column("detail", style="dim white")
        for f in risk.factors:
            t.add_row(f"+{f.points}", f.category, f.label, f.detail)
        console.print(t)
    else:
        console.print("  [green]No significant risk factors identified across this capture.[/green]")


def render_final_verdict(console: Console, risk, filename: str):
    console.print()
    if risk.score >= 70:
        style, label, glyph = "bold white on red", "CRITICAL — ACTIVE COMPROMISE INDICATORS PRESENT", "☠"
    elif risk.score >= 45:
        style, label, glyph = "bold red", "HIGH RISK — MULTIPLE CORRELATED FINDINGS", "⚠"
    elif risk.score >= 22:
        style, label, glyph = "bold yellow", "MODERATE — ANOMALIES WARRANT REVIEW", "◈"
    elif risk.score >= 8:
        style, label, glyph = "bold cyan", "LOW — MINOR ANOMALIES ONLY", "◇"
    else:
        style, label, glyph = "bold green", "MINIMAL — NO SIGNIFICANT FINDINGS", "✓"

    text = Text(f"\n {glyph}  {label}  {glyph}\n", justify="center", style=style)
    console.print(Panel(text, border_style="red" if "on" in style else style.split()[-1],
                         title=f"[bold]VERDICT — {filename}[/bold]", title_align="left"))
    console.print()


# ---------------------------------------------------------------- export

def build_export_dict(meta, stats, flows, dns, http, tls, arp, scan, beacon,
                       exfil, ioc, timeline_events, risk, elapsed_seconds: float) -> dict:
    def d(obj):
        return dataclasses.asdict(obj) if dataclasses.is_dataclass(obj) else obj

    return {
        "revenant_report_version": 1,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration_seconds": round(elapsed_seconds, 3),
        "capture_meta": d(meta),
        "protocol_stats": d(stats),
        "flow_count": len(flows),
        "flows_sample": [
            {"proto": f.proto, "ip_a": f.ip_a, "port_a": f.port_a, "ip_b": f.ip_b, "port_b": f.port_b,
             "bytes_total": f.total_bytes, "packets_total": f.total_packets, "duration": round(f.duration, 2)}
            for f in sorted(flows, key=lambda x: x.total_bytes, reverse=True)[:200]
        ],
        "dns": d(dns),
        "http": d(http),
        "tls": d(tls),
        "arp": d(arp),
        "scan_detection": d(scan),
        "beacon_detection": d(beacon),
        "exfil_detection": d(exfil),
        "iocs": d(ioc),
        "timeline": [d(e) for e in timeline_events],
        "risk_score": {
            "score": risk.score, "verdict": risk.verdict,
            "factors": [dataclasses.asdict(f) for f in risk.factors],
        },
    }


def export_json(data: dict, path: str):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def export_html(data: dict, path: str):
    meta = data["capture_meta"]
    risk = data["risk_score"]

    def esc(x):
        return html_escape.escape(str(x))

    verdict_color = {"CRITICAL": "#ff1744", "HIGH": "#ff3552", "MODERATE": "#f5a623",
                      "LOW": "#22d3ee", "MINIMAL": "#22c55e"}.get(risk["verdict"], "#999")

    rows_risk = "".join(
        f"<tr><td>+{esc(f['points'])}</td><td>{esc(f['category'])}</td><td>{esc(f['label'])}</td><td>{esc(f['detail'])}</td></tr>"
        for f in risk["factors"]
    )
    rows_timeline = "".join(
        f"<tr><td>{esc(e['relative_seconds'])}s</td><td>{esc(e['category'])}</td>"
        f"<td>{esc(e['severity'])}</td><td>{esc(e['summary'])}</td></tr>"
        for e in data["timeline"][:200]
    )
    rows_iocs_domains = "".join(f"<li>{esc(d)}</li>" for d in data["iocs"].get("suspicious_domains", []))
    rows_iocs_scanners = "".join(f"<li>{esc(d)}</li>" for d in data["iocs"].get("scanner_ips", []))

    html_doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>REVENANT Report — {esc(meta.get('filepath'))}</title>
<style>
body{{background:#0b0e14;color:#e2e8f0;font-family:'Courier New',monospace;padding:2rem;max-width:1100px;margin:auto;}}
h1{{color:#22d3ee;letter-spacing:.08em;}}
h2{{color:#ff3552;border-bottom:1px solid #333;padding-bottom:.3rem;margin-top:2rem;}}
table{{width:100%;border-collapse:collapse;margin-top:.5rem;}}
td{{padding:.4rem .6rem;border-bottom:1px solid #1e293b;font-size:.82rem;vertical-align:top;}}
.verdict{{display:inline-block;padding:.6rem 1.2rem;border-radius:8px;font-weight:bold;background:{verdict_color}22;border:1px solid {verdict_color};color:{verdict_color};}}
.score{{font-size:2rem;font-weight:bold;color:{verdict_color};}}
ul{{columns:2;font-size:.85rem;}}
</style></head><body>
<h1>REVENANT :: NETWORK INVESTIGATION REPORT</h1>
<p>Evidence: {esc(meta.get('filepath'))}<br>Generated {esc(data['generated_at'])} — analysis took {esc(data['scan_duration_seconds'])}s</p>
<div class="score">{esc(risk['score'])}/100</div>
<span class="verdict">{esc(risk['verdict'])} RISK</span>

<h2>Risk Factors</h2><table>{rows_risk if rows_risk else '<tr><td colspan=4>No risk factors triggered.</td></tr>'}</table>
<h2>Investigation Timeline</h2><table>{rows_timeline if rows_timeline else '<tr><td colspan=4>No correlated events.</td></tr>'}</table>
<h2>Suspicious Domains</h2><ul>{rows_iocs_domains or '<li>none</li>'}</ul>
<h2>Scanner IPs</h2><ul>{rows_iocs_scanners or '<li>none</li>'}</ul>

<p style="margin-top:3rem;color:#475569;font-size:.75rem;">Generated by REVENANT — developed by Cryptonic Area — github.com/cryptonicarea</p>
</body></html>"""

    with open(path, "w") as f:
        f.write(html_doc)


def export_ioc_txt(ioc, path: str):
    lines = ["# REVENANT IOC EXPORT", ""]
    lines.append("## External IPs")
    lines.extend(ioc.external_ips)
    lines.append("")
    lines.append("## Suspicious Domains")
    lines.extend(ioc.suspicious_domains)
    lines.append("")
    lines.append("## JA3 Hashes")
    lines.extend(ioc.ja3_hashes)
    lines.append("")
    lines.append("## Scanner IPs")
    lines.extend(ioc.scanner_ips)
    lines.append("")
    lines.append("## Beacon Pairs")
    lines.extend(ioc.beacon_pairs)
    with open(path, "w") as f:
        f.write("\n".join(lines))
