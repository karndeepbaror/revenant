# REVENANT — Architecture

This document explains how REVENANT is actually wired together internally:
the data flow from raw evidence file to final report, why the pipeline is
shaped the way it is, and the design decisions behind the core abstractions.

---

## 1. High-level pipeline

REVENANT's entire execution is a single linear pipeline, orchestrated by
`revenant.py::run_pipeline()`. Every stage consumes the output of the stage(s)
before it — nothing is re-parsed from the raw pcap after the ingestion stage.

```
                        ┌─────────────────────┐
                        │   evidence.pcap       │
                        └──────────┬───────────┘
                                   ▼
                     ┌──────────────────────────┐
                     │  1. pcap_loader.py         │
                     │  stream-parse every frame  │
                     │  → normalized Frame list    │
                     └──────────┬───────────────┘
                                   ▼
              ┌────────────────────┴─────────────────────┐
              ▼                                            ▼
  ┌───────────────────────┐                  ┌───────────────────────────┐
  │ 2. protocol_stats.py    │                  │ 3. flows.py                 │
  │ per-protocol counts,     │                  │ 5-tuple conversation        │
  │ top talkers, timeline    │                  │ reconstruction                │
  └───────────────────────┘                  └──────────────┬────────────┘
              │                                                 │
              │            ┌────────────────────────────────────┤
              │            ▼                    ▼                ▼
              │  ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐
              │  │ 8. scan_detection │  │ 9. beacon_detection│  │ 10. exfil_detection│
              │  │  (needs flows)     │  │  (needs flows)      │  │  (needs flows +    │
              │  │                    │  │                      │  │   DNS resolved IPs)│
              │  └─────────────────┘  └──────────────────┘  └──────────────────┘
              │
              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  4. dns_analysis.py    5. http_analysis.py    6. tls_analysis.py │
  │  7. arp_analysis.py                                                │
  │  (all four run directly off the normalized Frame list)             │
  └──────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  11. ioc_extraction.py   — aggregates every module's findings   │
  └──────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  12. timeline.py         — merges every finding chronologically  │
  └──────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  13. risk_score.py       — composite 0-100 investigation score  │
  └──────────────────────────────────────────────────────────────┘
              │
              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  report.py                — renders the terminal report,          │
  │                              optionally exports JSON/HTML/IOC     │
  └──────────────────────────────────────────────────────────────┘
```

---

## 2. The `Frame` abstraction

Everything downstream of ingestion operates on a flat, dependency-free
dataclass called `Frame` (defined in `pcap_loader.py`), **not** on raw scapy
packet objects. This is a deliberate architectural choice:

- **Memory.** A raw scapy `Packet` object retains its full layered structure
  and back-references. Holding tens of thousands of them in memory at once
  (which every correlation module needs to do) is expensive. A `Frame` is a
  small, flat object with only the fields any module actually needs.
- **Decoupling.** No module past `pcap_loader.py` needs to know anything
  about scapy's API. If REVENANT ever swaps its packet-parsing backend
  (e.g. to `dpkt` or a Rust extension for speed), only `pcap_loader.py`
  needs to change — every other module is untouched.
- **Streaming.** `pcap_loader.py` uses scapy's `PcapReader` (a streaming
  reader) rather than `rdpcap` (which loads the entire file into memory
  before returning). Frames are yielded and converted one at a time.

A `Frame` carries:

- Layer 2: `eth_src`, `eth_dst`
- Layer 3: `ip_version`, `src_ip`, `dst_ip`, `ttl`
- Layer 4: `proto`, `src_port`, `dst_port`, TCP flags/seq/ack/window
- Raw payload bytes (`payload`) — used directly by `http_analysis.py` and
  `tls_analysis.py`, which parse cleartext protocol structure straight out
  of these bytes without needing scapy's own (optional, often-missing) HTTP
  or TLS dissectors.
- Pre-parsed DNS fields (`dns_qname`, `dns_qtype`, `dns_response_ips`, …) —
  parsed once at ingestion time, since DNS's wire format is annoying to
  re-parse and every module that cares about DNS wants the same fields.
- Pre-parsed ARP fields (`arp_op`, `arp_hwsrc`, `arp_hwdst`).

## 3. The `Flow` abstraction

`flows.py` groups `Frame`s into bidirectional 5-tuple conversations. This is
the same fundamental unit NetFlow, IPFIX, and Zeek's `conn.log` are built on.
A `Flow` key is **direction-independent** — `(proto, (ip_a, port_a), (ip_b,
port_b))` sorted canonically — so packets flowing in either direction of the
same conversation land in the same `Flow` object.

Every correlation module (`scan_detection.py`, `beacon_detection.py`,
`exfil_detection.py`) operates on `Flow` objects rather than raw `Frame`s,
because scanning, beaconing, and exfiltration are fundamentally
*conversation-level* patterns, not single-packet patterns.

## 4. Why some modules read `Frame`s directly and others read `Flow`s

| Module | Reads | Why |
|---|---|---|
| `protocol_stats.py` | `Frame`s | Byte/packet counting doesn't need conversation grouping. |
| `dns_analysis.py` | `Frame`s | Each DNS message is a complete, independent unit. |
| `http_analysis.py` | `Frame`s | HTTP request/response lines usually land in a single TCP segment's payload; no reassembly needed for the common case. |
| `tls_analysis.py` | `Frame`s | A ClientHello is (almost always) a single TCP segment. |
| `arp_analysis.py` | `Frame`s | ARP has no concept of a "flow" — it's request/reply broadcast traffic. |
| `scan_detection.py` | `Flow`s | Scanning is defined by the *shape* of many conversations from one source. |
| `beacon_detection.py` | `Flow`s | Beaconing is defined by the *timing pattern between* repeated conversations. |
| `exfil_detection.py` | `Flow`s | "How much data moved" only makes sense at the conversation level. |

## 5. Correlation & the timeline

`timeline.py` is the "correlate" step named explicitly in REVENANT's design
brief (*analyze → correlate → investigate → report*). Every other module
produces isolated findings — a DGA domain here, a beacon there, a scan
somewhere else. `timeline.py` doesn't re-analyze anything; it simply reads
the already-computed results from every module and merges them into one
chronologically sorted list of `TimelineEvent` objects, each tagged with a
category, severity, and a human-readable summary.

This is deliberately the *last* analytical step before scoring and
rendering — everything before it is independent, parallelizable analysis;
everything from here on is synthesis.

## 6. Risk scoring philosophy

`risk_score.py` never re-derives raw signals — it only reads the *already
computed* results from every other module and assigns point values to
specific findings (see
[DETECTION_METHODOLOGY.md](DETECTION_METHODOLOGY.md#composite-risk-score)
for the full point table). This keeps the scoring model auditable: anyone
can read `risk_score.py` top to bottom and see exactly why a capture scored
what it scored, with no hidden ML model or opaque aggregation step.

## 7. Presentation layer

`banner.py` and `report.py` contain **zero analysis logic** — they are pure
presentation. This separation means the entire analysis pipeline can be
driven headlessly (e.g. imported as a library, called from a test suite, or
wrapped in a different UI) without importing `rich` or touching a terminal
at all — every `revenant_core` analysis module has no dependency on the
presentation layer.

## 8. Extensibility

Adding a new detection module means:

1. Write a new file in `revenant_core/` that exports a single
   `analyze_x(frames_or_flows) -> XResult` function returning a dataclass.
2. Call it from `run_pipeline()` in `revenant.py`.
3. Add a `render_x()` function to `report.py`.
4. Optionally feed its findings into `ioc_extraction.py`,
   `timeline.py`, and `risk_score.py`.

No existing module needs to change — this is why the pipeline is built as a
flat sequence of independent functions rather than a class hierarchy or
plugin framework with inheritance.
