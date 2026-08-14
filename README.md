<div align="center">

```
██████╗ ███████╗██╗   ██╗███████╗███╗   ██╗ █████╗ ███╗   ██╗████████╗
██╔══██╗██╔════╝██║   ██║██╔════╝████╗  ██║██╔══██╗████╗  ██║╚══██╔══╝
██████╔╝█████╗  ██║   ██║█████╗  ██╔██╗ ██║███████║██╔██╗ ██║   ██║
██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██╔══██║██║╚██╗██║   ██║
██║  ██║███████╗ ╚████╔╝ ███████╗██║ ╚████║██║  ██║██║ ╚████║   ██║
╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝
```

### Network Traffic Investigation Engine
**PCAP / Evidence File → Analyze → Correlate → Investigate → Report**

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Built with Scapy](https://img.shields.io/badge/Built%20with-Scapy-red)](https://scapy.net/)
[![Status: Active](https://img.shields.io/badge/Status-Active-22d3ee.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-ff3552.svg)](CONTRIBUTING.md)
[![Made by Karndeep Baror](https://img.shields.io/badge/Made%20by-Karndeep%20Baror-0891b2)](https://github.com/cryptonicarea)

**[Quick Start](#-quick-start)** ·
**[Features](#-what-revenant-actually-does)** ·
**[Architecture](docs/ARCHITECTURE.md)** ·
**[Detection Methodology](docs/DETECTION_METHODOLOGY.md)** ·
**[CLI Reference](docs/CLI_REFERENCE.md)** ·
**[FAQ](docs/FAQ.md)** ·
**[Contributing](CONTRIBUTING.md)**

</div>

---

## What is REVENANT?

**REVENANT** is a command-line network forensics engine that takes a single
`.pcap` / `.pcapng` evidence file and runs it through a complete investigation
pipeline — the same conceptual workflow a SOC analyst, incident responder, or
DFIR practitioner runs by hand across five or six different tools (Wireshark,
tshark filters, a spreadsheet, a Python one-off script, and a threat-intel
lookup) — except REVENANT does all of it in one pass, correlates the findings
against each other, and hands back a single, structured investigation report.

Nothing in REVENANT is a demo, a stub, or a hard-coded example. Every number
in the output — every hash, every entropy score, every JA3 fingerprint, every
"regularity: 91%" beacon score — is computed live from the actual bytes of
whatever capture file you point it at.

> **REVENANT never executes, injects, replays, or transmits a single packet.**
> It is a strictly **passive, read-only** analysis engine. It only ever reads
> the evidence file you give it.

---

## Why REVENANT exists

Most free PCAP tools stop at "here is a table of every packet." That's a
*viewer*, not an *investigator*. REVENANT was built to answer the questions an
analyst actually has:

- Who talked to whom, how much, and for how long?
- Which of these domains looks machine-generated rather than typed by a human?
- Is any host on this network being scanned right now?
- Is any host on this network quietly checking in with something external on
  a fixed clock — the way malware beacons to its command-and-control server?
- Did any data leave this network in a way that doesn't look like normal
  browsing traffic?
- Is anyone on this LAN pretending to be the gateway?
- If I had to hand a five-minute summary to my manager in the next ten
  minutes, what would it say?

REVENANT's whole design is built around answering those questions
automatically, then laying the answers out — correlated, timestamped, and
scored — in a single report.

---

## What REVENANT actually does

Every one of the sections below is a real, independent analysis module. Full
technical detail on each one lives in **[docs/MODULES.md](docs/MODULES.md)**
and **[docs/DETECTION_METHODOLOGY.md](docs/DETECTION_METHODOLOGY.md)** — this
is the short version.

| # | Module | What it computes |
|---|--------|-------------------|
| 1 | **Evidence Ingestion** | Streams the pcap/pcapng file frame-by-frame (constant memory, even on multi-GB captures) and normalizes every packet into a flat internal record. |
| 2 | **Protocol Distribution & Top Talkers** | Real packet/byte counts per protocol, top talking hosts, top conversation pairs, top destination ports, and a live traffic-volume-over-time sparkline. |
| 3 | **Flow Reconstruction** | Groups raw frames into bidirectional 5-tuple TCP/UDP conversations — the same foundational unit NetFlow and Zeek's `conn.log` are built on. |
| 4 | **DNS Investigation** | Extracts every query/response, then scores every queried domain for **DGA-style lexical randomness** (entropy, consonant runs, digit ratio, vowel ratio) and flags **DNS tunneling** indicators (abnormally long labels, sustained high-frequency queries against one suffix, oversized TXT/NULL records). |
| 5 | **HTTP Investigation** | Regex-based request/response parsing straight off raw TCP payloads, **plaintext-object carving** (SHA-256 hashes downloaded file-like bodies without needing full TCP stream reassembly), suspicious/non-browser User-Agent detection, and plaintext credential exposure detection. |
| 6 | **TLS Investigation** | A **hand-written TLS ClientHello parser** (no decryption — TLS handshake metadata is sent in plaintext by design) that extracts SNI (the real hostname being requested) and computes a **JA3-style client fingerprint** from the cipher suites / extensions / elliptic curves offered. |
| 7 | **ARP Integrity** | Detects the classic ARP-spoofing fingerprint: one IP address being claimed by more than one MAC address. |
| 8 | **Scan Detection** | Correlates reconstructed flows to find **vertical scans** (one source touching many ports on one host) and **horizontal scans** (one source touching one port across many hosts), weighted by SYN-only/no-response ratio. |
| 9 | **Beaconing Detection** | Computes inter-arrival intervals between every repeated host-pair connection and scores how *clock-like* the rhythm is — the statistical fingerprint of C2 check-in behaviour. |
| 10 | **Exfiltration Detection** | Flags large, asymmetric, uncommon-port, or DNS-unresolved outbound transfers. |
| 11 | **IOC Aggregation** | Rolls every finding above into one consolidated, exportable indicator list — IPs, domains, JA3 hashes, file hashes, scanner IPs, beacon pairs. |
| 12 | **Timeline Correlation** | Merges every module's findings into one chronologically sorted investigation timeline — the actual "story" of the capture. |
| 13 | **Composite Risk Scoring** | A transparent, weighted 0–100 score for the whole capture, with a full breakdown of exactly which findings contributed how many points and why. |

---

## Quick Start

```bash
# 1. clone the repository
git clone https://github.com/cryptonicarea/revenant.git
cd revenant/revenant

# 2. install dependencies
pip install -r requirements.txt

# 3. point REVENANT at any evidence file
python3 revenant.py investigate /path/to/capture.pcap

# ...or the shortcut form
python3 revenant.py /path/to/capture.pcap

# ...or just run it with no arguments for interactive mode
python3 revenant.py
```

> A ready-to-use test file, `sample_evidence.pcap`, ships at the repository
> root — it's a synthetic capture deliberately engineered to trigger every
> detection module (DGA domains, a carved file, plaintext credentials,
> beaconing, both scan types, an exfil-style transfer, ARP spoofing, and
> three TLS ClientHellos). Perfect for a first run:
>
> ```bash
> python3 revenant.py ../sample_evidence.pcap
> ```

Full installation notes (including platform-specific tips for scapy) live in
**[docs/INSTALLATION.md](docs/INSTALLATION.md)**.

---

## Repository layout

This repository intentionally nests the tool one level deep so that the
**documentation, license, and GitHub metadata live at the repo root**, while
the **runnable tool stays self-contained** in its own folder — this keeps
`revenant/` copy-pasteable as a standalone unit (into a Docker image, a
different repo, a USB stick during an IR engagement) without dragging
documentation along with it.

```
revenant/                          ← repository root (what you clone)
│
├── README.md                      ← you are here
├── LICENSE                        ← MIT
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── CHANGELOG.md
├── sample_evidence.pcap           ← ready-to-use test capture
│
├── docs/                          ← full documentation suite
│   ├── ARCHITECTURE.md            ← how the pipeline is wired together
│   ├── MODULES.md                 ← deep dive on every module, file-by-file
│   ├── DETECTION_METHODOLOGY.md   ← the actual math/heuristics behind every score
│   ├── CLI_REFERENCE.md           ← every flag, every option, with examples
│   ├── INSTALLATION.md            ← setup for Linux / macOS / Windows
│   ├── FAQ.md
│   └── ROADMAP.md
│
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── feature_request.md
│   │   ├── detection_false_positive.md
│   │   └── config.yml
│   └── PULL_REQUEST_TEMPLATE.md
│
└── revenant/                      ← the tool itself (self-contained)
    ├── revenant.py                ← CLI entrypoint
    ├── requirements.txt
    └── revenant_core/
        ├── pcap_loader.py         ← evidence ingestion & frame normalization
        ├── protocol_stats.py      ← protocol distribution / top talkers
        ├── flows.py               ← conversation reconstruction
        ├── dns_analysis.py        ← DNS + DGA + tunneling
        ├── http_analysis.py       ← HTTP + object carving + credential exposure
        ├── tls_analysis.py        ← TLS ClientHello + SNI + JA3
        ├── arp_analysis.py        ← ARP spoofing detection
        ├── scan_detection.py      ← vertical / horizontal scan correlation
        ├── beacon_detection.py    ← C2 beaconing periodicity analysis
        ├── exfil_detection.py     ← anomalous transfer detection
        ├── ioc_extraction.py      ← IOC aggregation
        ├── timeline.py            ← cross-module event correlation
        ├── risk_score.py          ← composite risk model
        ├── banner.py              ← terminal UI presentation layer
        └── report.py              ← rendering + JSON/HTML/IOC export
```

Because of this layout, **after cloning you `cd` in twice**:

```bash
git clone https://github.com/cryptonicarea/revenant.git
cd revenant/revenant
python3 revenant.py --version
```

---

## Sample output

Running REVENANT against a capture produces a full-color terminal report.
A condensed excerpt (colors and animation obviously don't render in
Markdown, but the structure is exact):

```
◆  CASE FILE — CAPTURE OVERVIEW ─────────────────────────────────
  Evidence File     /evidence/incident-4471.pcap
  Total Packets     18,402
  Duration          612.44 seconds

▓  PROTOCOL DISTRIBUTION & TOP TALKERS ──────────────────────────
  protocol   packets    bytes      % of traffic
  TCP        14,220     11.4 MB    82.1%
  UDP        3,910      1.8 MB     13.0%
  ARP        272        16.3 KB    0.1%

◈  DNS INVESTIGATION ─────────────────────────────────────────────
  ⚠ Suspected DGA-style domains
    qxkvbzpfjhgqrx.biz     score 78.4     src 10.0.0.5

◉  BEACONING DETECTION ───────────────────────────────────────────
  10.0.0.5  →  203.0.113.77:8443   10 conns   every ~5.0s   regularity 98.6%

☣  COMPOSITE INVESTIGATION RISK SCORE ────────────────────────────
  ████████████████████████████████████░░░░░░░░░░  81/100  →  CRITICAL

  ╭─ VERDICT — incident-4471.pcap ─────────────────────────────╮
  │         ☠  CRITICAL — ACTIVE COMPROMISE INDICATORS PRESENT  ☠      │
  ╰──────────────────────────────────────────────────────────────╯
```

---

## Exporting a report

```bash
# JSON — the full structured findings, for feeding into other tooling
python3 revenant.py capture.pcap --export json

# a self-contained HTML case file, styled for sharing
python3 revenant.py capture.pcap --export html

# both at once
python3 revenant.py capture.pcap --export both

# a flat plaintext IOC list (IPs, domains, JA3, hashes, scanner IPs)
python3 revenant.py capture.pcap --export ioc
```

Everything lands in `./revenant_reports/` by default (override with `--out`).
The full flag reference is in **[docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)**.

---

## Design principles

- **Passive only.** REVENANT reads bytes. It never crafts, injects, replays,
  or transmits a packet, and never touches the network interface.
- **No black boxes.** Every score REVENANT produces — DGA score, JA3 hash,
  beacon regularity, risk score — comes with a written, human-readable
  explanation of exactly how it was computed. See
  [docs/DETECTION_METHODOLOGY.md](docs/DETECTION_METHODOLOGY.md).
- **Offline-first.** No cloud upload, no external API calls, no telemetry.
  The only file REVENANT touches is the one you give it.
- **Signal over noise.** Every heuristic is written to focus a human's
  attention, not to hand down an automated verdict. REVENANT is built to
  make a skilled analyst faster — not to replace their judgment.

---

## Contributing

Bug reports, detection-accuracy feedback, and pull requests are genuinely
welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)** for the workflow, and
use the issue templates under `.github/ISSUE_TEMPLATE/` for bug reports,
feature requests, and false-positive reports on any detection module.

## Security

For responsible disclosure of a security issue in REVENANT itself, see
**[SECURITY.md](SECURITY.md)**.

## License

Released under the **MIT License** — see [LICENSE](LICENSE). Free to use,
modify, and redistribute, including commercially.

---

<div align="center">

**Developed by [Karndeep Baror](https://linkedin.com/in/karndeepbaror)**

*REVENANT — because the traffic remembers, even after the attacker is gone.*

</div>
