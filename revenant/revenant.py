#!/usr/bin/env python3
"""
================================================================
  REVENANT — Network Traffic Investigation Engine
================================================================
  PCAP/evidence file -> analyze -> correlate -> investigate -> report

  Developed by Cryptonic Area
  GitHub: https://github.com/cryptonicarea
  License: MIT

  Usage:
      python3 revenant.py investigate <capture.pcap> [options]
      python3 revenant.py <capture.pcap>                (shortcut)
      python3 revenant.py                                (interactive mode)

  Options:
      --export json|html|both|ioc     Save report artifact(s)
      --out DIR                       Output directory (default ./revenant_reports)
      --no-anim                       Disable animations (fast/CI mode)
      --limit N                       Only analyze the first N packets (large captures)
      --entropy-buckets N             Timeline buckets for the traffic sparkline (default 60)
      --min-similarity N              (reserved for future cross-capture correlation)
      --version                       Print version and exit
================================================================
"""

from __future__ import annotations
import os
import sys
import time
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from revenant_core import banner, pcap_loader, protocol_stats, flows as flows_mod
from revenant_core import dns_analysis, http_analysis, tls_analysis, arp_analysis
from revenant_core import scan_detection, beacon_detection, exfil_detection
from revenant_core import ioc_extraction, timeline as timeline_mod, risk_score, report


console = Console(highlight=False)

PHASES = [
    "Ingesting evidence file (pcap/pcapng)",
    "Building protocol distribution & top-talkers",
    "Reconstructing TCP/UDP conversations (flows)",
    "Investigating DNS traffic",
    "Investigating HTTP traffic",
    "Investigating TLS handshakes",
    "Checking ARP integrity",
    "Correlating scan patterns",
    "Correlating beaconing patterns",
    "Correlating exfiltration patterns",
    "Aggregating indicators of compromise",
    "Building investigation timeline",
    "Scoring composite investigation risk",
]


def run_pipeline(filepath: str, args) -> dict:
    if not os.path.isfile(filepath):
        console.print(f"\n  [bold red]✗ ERROR[/bold red] — evidence file not found:")
        console.print(f"    [dim]{filepath}[/dim]\n")
        sys.exit(1)

    start = time.time()
    r = {}

    with Progress(
        SpinnerColumn(spinner_name="dots12", style="cyan"),
        TextColumn("[bold red]{task.fields[phase]}[/bold red]"),
        BarColumn(bar_width=30, style="grey30", complete_style="cyan", finished_style="green"),
        TextColumn("[dim]{task.percentage:>3.0f}%[/dim]"),
        TimeElapsedColumn(),
        console=console,
        disable=args.no_anim,
    ) as progress:
        task = progress.add_task("scan", total=len(PHASES), phase="starting…")

        def step(label):
            progress.update(task, phase=label)

        step(PHASES[0])
        r["frames"], r["meta"] = pcap_loader.load_capture(filepath, packet_limit=args.limit)
        progress.advance(task)

        step(PHASES[1])
        r["stats"] = protocol_stats.analyze_protocol_stats(
            r["frames"], r["meta"].first_ts, r["meta"].duration_seconds, bucket_count=args.entropy_buckets)
        progress.advance(task)

        step(PHASES[2])
        r["flows"] = flows_mod.build_flows(r["frames"])
        progress.advance(task)

        step(PHASES[3])
        r["dns"] = dns_analysis.analyze_dns(r["frames"])
        progress.advance(task)

        step(PHASES[4])
        r["http"] = http_analysis.analyze_http(r["frames"])
        progress.advance(task)

        step(PHASES[5])
        r["tls"] = tls_analysis.analyze_tls(r["frames"])
        progress.advance(task)

        step(PHASES[6])
        r["arp"] = arp_analysis.analyze_arp(r["frames"])
        progress.advance(task)

        step(PHASES[7])
        r["scan"] = scan_detection.analyze_scans(r["flows"])
        progress.advance(task)

        step(PHASES[8])
        r["beacon"] = beacon_detection.analyze_beaconing(r["flows"])
        progress.advance(task)

        step(PHASES[9])
        resolved_ips = set()
        for q in r["dns"].queries:
            resolved_ips.update(q.response_ips)
        r["exfil"] = exfil_detection.analyze_exfiltration(r["flows"], resolved_ips)
        progress.advance(task)

        step(PHASES[10])
        r["ioc"] = ioc_extraction.extract_iocs(
            r["stats"], r["dns"], r["tls"], r["http"], r["scan"], r["beacon"], r["arp"])
        progress.advance(task)

        step(PHASES[11])
        r["timeline"] = timeline_mod.build_timeline(
            r["meta"].first_ts, r["dns"], r["scan"], r["beacon"], r["exfil"], r["tls"], r["http"], r["arp"])
        progress.advance(task)

        step(PHASES[12])
        r["risk"] = risk_score.compute_investigation_risk(
            r["dns"], r["scan"], r["beacon"], r["exfil"], r["tls"], r["arp"], r["http"])
        progress.advance(task)
        progress.update(task, phase="[bold green]investigation complete[/bold green]")

    r["elapsed"] = time.time() - start
    return r


def render_full_report(filepath: str, r: dict):
    report.render_overview(console, r["meta"])
    report.render_protocol_stats(console, r["stats"])
    report.render_traffic_sparkline(console, r["stats"])
    report.render_flow_summary(console, r["flows"])
    report.render_dns(console, r["dns"])
    report.render_http(console, r["http"])
    report.render_tls(console, r["tls"])
    report.render_arp(console, r["arp"])
    report.render_scans(console, r["scan"])
    report.render_beacons(console, r["beacon"])
    report.render_exfil(console, r["exfil"])
    report.render_iocs(console, r["ioc"])
    report.render_timeline(console, r["timeline"])
    report.render_risk_score(console, r["risk"])
    report.render_final_verdict(console, r["risk"], os.path.basename(filepath))


def handle_export(filepath: str, r: dict, args):
    if not args.export:
        return
    out_dir = args.out or "./revenant_reports"
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(filepath))[0]
    stamp = time.strftime("%Y%m%d_%H%M%S")

    data = report.build_export_dict(
        r["meta"], r["stats"], r["flows"], r["dns"], r["http"], r["tls"], r["arp"],
        r["scan"], r["beacon"], r["exfil"], r["ioc"], r["timeline"], r["risk"], r["elapsed"],
    )

    written = []
    if args.export in ("json", "both"):
        p = os.path.join(out_dir, f"revenant_{base}_{stamp}.json")
        report.export_json(data, p)
        written.append(p)
    if args.export in ("html", "both"):
        p = os.path.join(out_dir, f"revenant_{base}_{stamp}.html")
        report.export_html(data, p)
        written.append(p)
    if args.export == "ioc":
        p = os.path.join(out_dir, f"revenant_{base}_{stamp}_iocs.txt")
        report.export_ioc_txt(r["ioc"], p)
        written.append(p)

    console.print()
    for p in written:
        console.print(f"  [bold green]✓ report saved[/bold green] → {p}")
    console.print()


def interactive_prompt() -> str:
    console.print()
    console.print("  [bold cyan]No evidence file supplied — entering interactive mode.[/bold cyan]")
    while True:
        path = console.input("  [bold red]revenant[/bold red][dim]›[/dim] enter path to .pcap/.pcapng evidence file: ").strip().strip('"').strip("'")
        if not path:
            continue
        if os.path.isfile(path):
            return path
        console.print(f"  [red]not found:[/red] {path}\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="revenant", description="REVENANT — Network Traffic Investigation Engine")
    parser.add_argument("path", nargs="?", help="Path to the .pcap/.pcapng evidence file")
    parser.add_argument("--export", choices=["json", "html", "both", "ioc"], default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--no-anim", action="store_true")
    parser.add_argument("--limit", type=int, default=None, help="Only analyze the first N packets")
    parser.add_argument("--entropy-buckets", type=int, default=60, help="Traffic timeline bucket count")
    parser.add_argument("--min-similarity", type=float, default=35.0)
    parser.add_argument("--version", action="store_true")
    return parser


def main():
    raw_argv = sys.argv[1:]
    if raw_argv and raw_argv[0] == "investigate":
        raw_argv = raw_argv[1:]

    parser = build_arg_parser()
    args = parser.parse_args(raw_argv)

    if args.version:
        console.print(f"{banner.TOOL_NAME} {banner.VERSION}")
        sys.exit(0)

    animate = not args.no_anim
    banner.boot_sequence(console, animate=animate)
    banner.render_banner(console, animate=animate)

    filepath = args.path
    if not filepath:
        filepath = interactive_prompt()

    r = run_pipeline(filepath, args)
    render_full_report(filepath, r)
    handle_export(filepath, r, args)

    banner.render_credits_panel(console)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n  [bold red]✗ investigation aborted by user[/bold red]\n")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n  [bold red]✗ REVENANT encountered a fatal error:[/bold red] {exc}\n")
        raise
