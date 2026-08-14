# Changelog

All notable changes to REVENANT are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses a `MAJOR.MINOR.PATCH :: CORE-BUILD NNN` versioning
scheme.

---

## [1.0.0] :: CORE-BUILD 001 — Initial Release

### Added

- **Evidence ingestion pipeline** (`pcap_loader.py`) — streaming pcap/pcapng
  parsing with a normalized, memory-flat `Frame` record per packet.
- **Protocol distribution & top-talkers analysis** (`protocol_stats.py`) —
  per-protocol packet/byte counts, top talkers, top conversation pairs,
  top destination ports, and a bucketed traffic-volume timeline.
- **Flow reconstruction** (`flows.py`) — bidirectional 5-tuple TCP/UDP
  conversation grouping with handshake-completion tracking.
- **DNS investigation module** (`dns_analysis.py`) — query/response
  extraction, DGA-style lexical domain scoring, and DNS tunneling
  indicator detection.
- **HTTP investigation module** (`http_analysis.py`) — request/response
  parsing, plaintext object carving with SHA-256 hashing, suspicious
  User-Agent detection, and plaintext credential exposure detection.
- **TLS investigation module** (`tls_analysis.py`) — a hand-written
  ClientHello parser extracting SNI and computing JA3-style client
  fingerprints, including GREASE-value filtering.
- **ARP integrity module** (`arp_analysis.py`) — IP/MAC conflict detection
  for ARP spoofing / cache poisoning indicators.
- **Scan detection module** (`scan_detection.py`) — vertical and
  horizontal port/host scan correlation with SYN-only-ratio severity
  weighting.
- **Beacon detection module** (`beacon_detection.py`) — coefficient-of-
  variation-based periodicity scoring for C2-style beaconing behaviour.
- **Exfiltration detection module** (`exfil_detection.py`) — combined
  large-transfer, asymmetric-ratio, uncommon-port, and no-DNS-resolution
  heuristics.
- **IOC aggregation module** (`ioc_extraction.py`) — consolidated,
  exportable indicator list across every detection module.
- **Timeline correlation module** (`timeline.py`) — chronological merge of
  every module's findings into a single investigation narrative.
- **Composite risk scoring module** (`risk_score.py`) — transparent,
  additive 0–100 investigation risk score with full factor breakdown.
- **Premium animated terminal UI** (`banner.py`, `report.py`) — ASCII
  banner, animated boot sequence, colorized `rich`-based report rendering.
- **Export formats** — JSON, self-contained HTML case file, and flat IOC
  text list, via `--export {json,html,both,ioc}`.
- **CLI** (`revenant.py`) — `investigate` subcommand, bare-path shortcut,
  interactive prompt mode, `--limit`, `--no-anim`, `--out`,
  `--entropy-buckets`, `--version`.
- **Sample evidence file** (`sample_evidence.pcap`) — synthetic capture
  engineered to exercise every detection module for first-run testing.
- **Full documentation suite** — architecture, module reference, detection
  methodology, CLI reference, installation guide, FAQ, and roadmap.

---

## [Unreleased]

See [docs/ROADMAP.md](docs/ROADMAP.md) for planned work.
