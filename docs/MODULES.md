# REVENANT — Module Reference

A file-by-file deep dive into every module in `revenant/revenant_core/`.
For the *math and heuristics* behind the detections, see
[DETECTION_METHODOLOGY.md](DETECTION_METHODOLOGY.md). This document is about
*what each file is responsible for and how it's structured*.

---

## `pcap_loader.py`

**Responsibility:** Evidence ingestion. The only module that touches scapy's
packet-parsing internals directly.

**Key exports:**
- `Frame` — the flat, normalized per-packet record every other module consumes.
- `CaptureMeta` — file-level metadata (size, packet count, duration, load time).
- `load_capture(filepath, packet_limit=None) -> (list[Frame], CaptureMeta)`

**Notable design choices:**
- Uses `scapy.all.PcapReader` (streaming) instead of `rdpcap` (loads
  everything into RAM at once) — critical for multi-gigabyte captures.
- TCP flags are decoded from scapy's terse single-letter representation
  (`"PA"`) into a readable comma-joined form (`"PSH,ACK"`) once, at load
  time, so no downstream module needs to re-decode them.
- DNS and ARP fields are parsed **at ingestion time** and attached directly
  to the `Frame`, rather than requiring downstream modules to re-open the
  scapy packet. This trades a small amount of ingestion-time work for a
  much simpler, faster downstream pipeline.

---

## `protocol_stats.py`

**Responsibility:** The "what does this capture even contain" pass —
protocol breakdown, top talkers, top conversation pairs, top destination
ports, and a bucketed traffic-volume timeline (used to render the terminal
sparkline).

**Key export:** `analyze_protocol_stats(frames, first_ts, duration,
bucket_count=60) -> ProtoStatsResult`

Bucket width is computed adaptively from the capture's actual duration
(`duration / bucket_count`), so a 10-second capture and a 10-hour capture
both render a proportionate, readable sparkline.

---

## `flows.py`

**Responsibility:** Conversation reconstruction — the single most important
data structure in REVENANT, since three other modules (`scan_detection.py`,
`beacon_detection.py`, `exfil_detection.py`) depend entirely on it.

**Key exports:**
- `Flow` — a bidirectional 5-tuple conversation record with byte/packet
  counts in each direction, TCP flag history, and handshake-completion state.
- `build_flows(frames) -> list[Flow]`

**Notable design choices:**
- The flow key is **direction-independent**: `(A, portA)` talking to
  `(B, portB)` produces the same key regardless of which side sent the
  first packet REVENANT happened to see. This matters because pcaps don't
  guarantee you see the true first packet of a conversation (e.g. if the
  capture started mid-session).
- `Flow.handshake_completed` and `Flow.syn_only` are computed per-flow
  after all frames are processed — these two flags are what
  `scan_detection.py` uses to distinguish a real connection attempt from a
  scanner's SYN-and-move-on behaviour.

---

## `dns_analysis.py`

**Responsibility:** Everything DNS — query/response extraction, most-queried
domains, and two heuristic detectors layered on top (DGA scoring, tunneling
indicators). See [DETECTION_METHODOLOGY.md](DETECTION_METHODOLOGY.md#dga-scoring)
for the actual scoring formula.

**Key exports:**
- `DNSQuery` — one parsed DNS message.
- `DNSAnalysisResult` — aggregate findings (top domains, suspected DGA
  domains, suspected tunneling, qtype distribution, NXDOMAIN count).
- `analyze_dns(frames) -> DNSAnalysisResult`

---

## `http_analysis.py`

**Responsibility:** Cleartext HTTP investigation. Operates entirely on the
`payload` bytes already captured per-`Frame` — no separate re-read of the
pcap.

**Key exports:**
- `HTTPRequest`, `HTTPResponse`, `CarvedObject`
- `HTTPAnalysisResult`
- `analyze_http(frames) -> HTTPAnalysisResult`

**How object carving works:** when a response's `Content-Type` isn't
`text/html`, REVENANT treats the bytes after the blank line following the
headers as a candidate file body, hashes it with SHA-256, and records the
content type, size, and any filename found in a `Content-Disposition`
header. This mirrors (in a lighter-weight form) what tools like
NetworkMiner's "Files" tab do — without needing full TCP stream reassembly,
which is enough for the common case of a response body landing in one
captured segment.

**How credential detection works:** a small set of regex patterns look for
`username=`/`password=` form fields and `Authorization: Basic` headers in
request payloads. This is intentionally narrow and pattern-based (not a
generic secret scanner) to keep false positives low.

---

## `tls_analysis.py`

**Responsibility:** TLS handshake investigation *without decryption* — SNI
extraction and JA3-style client fingerprinting.

**Key exports:**
- `TLSClientHello`
- `TLSAnalysisResult`
- `analyze_tls(frames) -> TLSAnalysisResult`

**Why this doesn't need decryption:** the TLS `ClientHello` message — the
very first message a client sends — is never encrypted. It's sent in the
clear specifically so the server can select a certificate before any keys
are negotiated. REVENANT's parser (`_parse_client_hello`) walks this
message's binary structure by hand: TLS record header → handshake header →
protocol version → random → session ID → cipher suite list → compression
methods → extensions. The `server_name` extension (type `0x0000`) contains
the SNI hostname; `supported_groups` (`0x000a`) and `ec_point_formats`
(`0x000b`) feed into the JA3 fingerprint.

See [DETECTION_METHODOLOGY.md](DETECTION_METHODOLOGY.md#ja3-fingerprinting)
for exactly how the JA3 hash is constructed and why GREASE values are
excluded.

---

## `arp_analysis.py`

**Responsibility:** ARP integrity — the simplest and most reliable detector
in REVENANT. One IP should map to one MAC. When it doesn't, that's either a
legitimate device/NIC change or an active MITM attack.

**Key exports:**
- `ARPBinding`, `ARPAnomalyResult`
- `analyze_arp(frames) -> ARPAnomalyResult`

Also tracks gratuitous ARP (a host announcing its own IP→MAC binding
unprompted — normal on boot/IP change, but also a mechanism spoofing tools
abuse) and raw request/reply counts.

---

## `scan_detection.py`

**Responsibility:** Correlates `Flow` objects (not raw frames) to detect two
canonical scan shapes. See
[DETECTION_METHODOLOGY.md](DETECTION_METHODOLOGY.md#scan-detection) for the
exact thresholds and scoring.

**Key exports:**
- `ScanEvent`, `ScanDetectionResult`
- `analyze_scans(flows) -> ScanDetectionResult`

Builds two indexes simultaneously — `scanner → target_host → {ports}` for
vertical scans, and `scanner → target_port → {hosts}` for horizontal scans —
in a single pass over the flow list, then flags any index entry that
crosses its respective threshold.

---

## `beacon_detection.py`

**Responsibility:** Statistical periodicity analysis on repeated host-pair
connections — the fingerprint of C2 check-in behaviour. See
[DETECTION_METHODOLOGY.md](DETECTION_METHODOLOGY.md#beacon-detection) for the
regularity-score formula.

**Key exports:**
- `BeaconCandidate`, `BeaconDetectionResult`
- `analyze_beaconing(flows) -> BeaconDetectionResult`

Groups flows by `(src, dst, dst_port)`, requires a minimum connection count
and time span before even considering a pair (short bursts of legitimate
polling shouldn't trigger this), then computes the coefficient of variation
of inter-arrival times to score how "clock-like" the rhythm is.

---

## `exfil_detection.py`

**Responsibility:** Flags flows that look like meaningful data leaving the
network. Combines four independent signals (large transfer, asymmetric
ratio, uncommon port, no corresponding DNS resolution) — a flow can trigger
on any subset of these, and the more that fire together, the higher its
assigned severity.

**Key exports:**
- `ExfilCandidate`, `ExfilDetectionResult`
- `analyze_exfiltration(flows, resolved_ips, local_ip_hint=None) ->
  ExfilDetectionResult`

`resolved_ips` is built by the pipeline from every IP address that appeared
in a DNS *response* anywhere in the capture — a destination IP that never
shows up there was reached without a logged DNS lookup, which is a common
detection-evasion pattern.

---

## `ioc_extraction.py`

**Responsibility:** Pure aggregation — no new analysis happens here. Pulls
together the IPs, domains, JA3 hashes, carved-file hashes, scanner IPs, and
beacon pairs that every other module already found, classifies IPs as
internal/external using `ipaddress.ip_address(...).is_private`, and returns
one consolidated `IOCSet`.

**Key export:** `extract_iocs(proto_stats, dns_result, tls_result,
http_result, scan_result, beacon_result, arp_result) -> IOCSet`

This is what powers `--export ioc`.

---

## `timeline.py`

**Responsibility:** Cross-module correlation into one chronological story.
Reads the already-computed results from `dns_analysis`, `scan_detection`,
`beacon_detection`, `exfil_detection`, `tls_analysis`, `http_analysis`, and
`arp_analysis`, and emits a flat, time-sorted list of `TimelineEvent`
objects.

**Key export:** `build_timeline(first_ts, dns_result, scan_result,
beacon_result, exfil_result, tls_result, http_result, arp_result) ->
list[TimelineEvent]`

---

## `risk_score.py`

**Responsibility:** The composite 0–100 score for the whole investigation.
Purely additive and fully transparent — see
[DETECTION_METHODOLOGY.md](DETECTION_METHODOLOGY.md#composite-risk-score)
for the complete point table.

**Key exports:**
- `RiskFactor`, `InvestigationRiskResult`
- `compute_investigation_risk(dns_result, scan_result, beacon_result,
  exfil_result, tls_result, arp_result, http_result) ->
  InvestigationRiskResult`

---

## `banner.py`

**Responsibility:** Pure presentation — the ASCII banner, animated boot
sequence, and credits panel. Contains zero analysis logic and has no effect
on any finding REVENANT produces; it can be entirely disabled with
`--no-anim`.

---

## `report.py`

**Responsibility:** Turns every module's structured dataclass results into
the terminal report (via `rich`), and builds the JSON / HTML / IOC-text
export artifacts. Also pure presentation — every `render_x()` function
takes an already-computed result object and only formats it.

**Key exports:** one `render_x(console, result)` function per module
(`render_overview`, `render_protocol_stats`, `render_dns`, …), plus
`build_export_dict(...)`, `export_json(...)`, `export_html(...)`, and
`export_ioc_txt(...)`.
