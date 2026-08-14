# REVENANT — Detection Methodology

This document is the "show your work" page. Every score, threshold, and
formula REVENANT uses is documented here in full — nothing in REVENANT's
detection logic is a black box. If you disagree with a threshold, this is
also the map you need to go change it in the source.

---

## Table of contents

1. [DGA domain scoring](#dga-scoring)
2. [DNS tunneling indicators](#dns-tunneling)
3. [JA3 fingerprinting](#ja3-fingerprinting)
4. [ARP spoofing detection](#arp-spoofing-detection)
5. [Scan detection](#scan-detection)
6. [Beacon detection](#beacon-detection)
7. [Exfiltration detection](#exfiltration-detection)
8. [HTTP object carving & credential detection](#http-object-carving)
9. [Composite risk score](#composite-risk-score)
10. [Known limitations](#known-limitations)

---

<a name="dga-scoring"></a>
## 1. DGA domain scoring

**File:** `dns_analysis.py::_dga_score()`

Domain Generation Algorithms (used by malware families to generate large
numbers of candidate C2 domains, defeating static blocklists) tend to
produce domain labels that are lexically "random" in ways real, human-typed
words are not. REVENANT scores every queried domain's registrable label
(the part before the first dot) on four independent axes, each contributing
up to a fixed number of points to a 0–100 score:

| Signal | Max points | Formula |
|---|---|---|
| **Character entropy** | 40 | Shannon entropy of the label, normalized: `min(entropy / 4.0, 1.0) * 40` |
| **Longest consonant run** | 25 | `min(max_consonant_run / 6.0, 1.0) * 25` — real words rarely stack 6+ consonants |
| **Digit ratio** | 15 | `min(digit_ratio / 0.4, 1.0) * 15` |
| **Low vowel ratio** | 20 | `(1.0 - min(vowel_ratio / 0.25, 1.0)) * 20` — real words are rarely this vowel-sparse |

Labels shorter than 6 characters are skipped entirely (score = 0) — short
labels don't carry enough signal to score reliably, and scoring them
produces noisy false positives.

A domain is flagged **suspected DGA** at a score **≥ 55**.

**Why this approach instead of a blocklist:** blocklists only catch domains
someone has already seen and catalogued. Lexical scoring catches domains
REVENANT has never seen before, which is the entire point of a DGA in the
first place. This is explicitly a *heuristic signal to focus human
attention on*, not an automated verdict — real DGA classifiers in
production systems combine exactly this kind of lexical scoring with
additional signals (registration recency, NXDOMAIN rate, etc.) before
acting automatically.

---

<a name="dns-tunneling"></a>
## 2. DNS tunneling indicators

**File:** `dns_analysis.py::analyze_dns()`

DNS tunneling smuggles arbitrary data through DNS queries/responses — a
technique that works because DNS is almost never blocked outbound. REVENANT
flags two independent patterns:

1. **Per-query flags** — a query is flagged if its full name exceeds 60
   characters, or if its query type is `TXT` or `NULL` (record types with
   room for arbitrary payload data, and commonly abused by tunneling tools
   like `iodine` and `dnscat2`).

2. **Sustained high-frequency queries against one suffix** — REVENANT
   groups queries by their last two labels (the "suffix", e.g.
   `tunnel.evil.com` → `evil.com`) and computes the query rate against
   that suffix. A suffix is flagged if it receives **≥ 20 queries** with a
   sustained rate of **> 0.5 queries/second** — normal DNS resolution for a
   domain doesn't look like this; a steady drip of high-frequency queries
   against a single suffix does.

---

<a name="ja3-fingerprinting"></a>
## 3. JA3 fingerprinting

**File:** `tls_analysis.py::_build_ja3()`

JA3 is a well-established, publicly documented fingerprinting technique
(originally published by Salesforce's security team) for identifying the
*client library/application* making a TLS connection — not the destination,
the *client*. It works because different TLS implementations (OpenSSL,
BoringSSL, a specific malware family's custom TLS stack, a specific version
of a browser) construct their ClientHello messages with distinctive,
consistent choices of cipher suites, extensions, and elliptic curves.

**Construction (exactly as REVENANT implements it):**

```
JA3_string = "{TLSVersion},{Ciphers},{Extensions},{EllipticCurves},{EllipticCurvePointFormats}"
JA3_hash   = MD5(JA3_string)
```

Where each of `Ciphers`, `Extensions`, and `EllipticCurves` is a
hyphen-joined list of the integer values offered, in the order the client
sent them.

**GREASE exclusion:** TLS 1.3 clients (per
[RFC 8701](https://datatracker.ietf.org/doc/html/rfc8701)) insert random
"GREASE" values into cipher suites and extensions specifically to prevent
servers from assuming a fixed set of values will ever appear — these values
follow the pattern `0x?A?A` (e.g. `0x0A0A`, `0x1A1A`, …). If left in, GREASE
values would make every single ClientHello's JA3 hash unique, defeating the
entire point of fingerprinting. REVENANT's `_grease()` check
(`(val & 0x0F0F) == 0x0A0A`) filters these out before hashing, matching the
reference JA3 implementation's behaviour.

**Why this matters for an investigation:** a legitimate browser's JA3 hash
changes with each browser version and varies across browsers, but a
specific piece of malware's custom or embedded TLS stack tends to produce
the *same* JA3 hash across every infected host and every C2 connection,
regardless of which domain or IP it's talking to that day. REVENANT
specifically flags any JA3 hash that appears across **3 or more distinct
destination IPs** (`ja3_reused_across_hosts`) as worth attention — a single
client fingerprint fanning out to many destinations is unusual for normal
browsing (where JA3 is a property of the *browser*, shared across all its
connections, so this alone isn't damning — but combined with other
findings in the risk model, it adds weight).

---

<a name="arp-spoofing-detection"></a>
## 4. ARP spoofing detection

**File:** `arp_analysis.py::analyze_arp()`

The detection logic is intentionally simple because the underlying network
invariant is simple: **in a healthy network, one IP address is claimed by
exactly one MAC address.** REVENANT builds a table of every `IP → {MAC:
count}` binding observed in ARP *replies* (`arp_op == 2`, i.e. "is-at"
messages, which is what actually updates a real ARP cache — REVENANT
intentionally does not use ARP *requests* for this, since requests only
state who's asking, not who owns an address).

Any IP with more than one distinct MAC in that table is flagged as
conflicting, with severity:

- **MEDIUM** — exactly 2 MAC addresses claimed the IP
- **HIGH** — 3 or more MAC addresses claimed the IP

Gratuitous ARP (a host announcing its own IP↔MAC binding unprompted,
`arp_op == 1` with `src_ip == dst_ip`) is tracked separately as contextual
information — it's normal on boot/DHCP renewal, but it's also the mechanism
ARP spoofing tools use to push a poisoned binding into every host's cache
at once, so REVENANT surfaces the count without scoring it independently.

---

<a name="scan-detection"></a>
## 5. Scan detection

**File:** `scan_detection.py::analyze_scans()`

Operates on reconstructed `Flow` objects. For every flow, REVENANT
determines the "initiator" (the side that sent *less* data — the side doing
the probing, not the side responding) and builds two indexes in one pass:

```
scanner_to_host_ports[initiator][target_ip]   = { every distinct target_port touched }
scanner_to_port_hosts[initiator][target_port] = { every distinct target_ip touched }
```

**Vertical scan** (one source, many ports, one host) is flagged when
`len(scanner_to_host_ports[scanner][host]) >= 15` distinct ports.

**Horizontal scan** (one source, one port, many hosts) is flagged when
`len(scanner_to_port_hosts[scanner][port]) >= 10` distinct hosts.

**Severity** is escalated to **HIGH** when either the scale is large
(≥ 100 ports for vertical, ≥ 50 hosts for horizontal) or the scanner's
overall SYN-only ratio (flows with a SYN and no completed handshake) is
**≥ 60%** — a scanner sending a SYN and immediately moving to the next
target, rather than completing real connections, is the textbook signature
of tools like `nmap`'s SYN scan (`-sS`) or a fast internal reconnaissance
sweep.

---

<a name="beacon-detection"></a>
## 6. Beacon detection

**File:** `beacon_detection.py::analyze_beaconing()`

For every `(src, dst, dst_port)` pair with **at least 6 connections**
spanning **at least 30 seconds**, REVENANT computes the list of
inter-arrival intervals between consecutive connection start times, then
scores how *regular* that rhythm is using the **coefficient of variation
(CV)**:

```
mean_interval  = mean(intervals)
stdev_interval = population_stdev(intervals)
CV             = stdev_interval / mean_interval
```

CV is a scale-independent measure of relative spread — a CV near 0 means
the intervals are almost identical to each other (a metronome); a CV near 1
means the spread is as large as the mean itself (essentially random
timing).

```
regularity_score = max(0, (1 - min(CV, 1.0)) * 100)
jitter_percent    = min(CV, 1.0) * 100
```

A pair is reported as a beacon candidate at **regularity ≥ 55%**. This is
the same core statistical approach used by Zeek's beacon-detection scripts
and tools like [RITA](https://github.com/activecm/rita) — real C2
frameworks (Cobalt Strike, Metasploit, most custom implants) check in on a
fixed interval, often with a small randomized "jitter" added specifically
to evade naive regularity detection — which is exactly why REVENANT scores
regularity on a spectrum rather than requiring a perfectly identical
interval every time.

**Why the minimum connection/span thresholds exist:** a burst of 3 quick
requests 200ms apart is a browser prefetching resources, not a beacon.
Requiring both a minimum count *and* a minimum time span filters out
short-lived legitimate bursts before they're ever scored.

---

<a name="exfiltration-detection"></a>
## 7. Exfiltration detection

**File:** `exfil_detection.py::analyze_exfiltration()`

For every flow, REVENANT identifies the "outbound" direction as whichever
side sent more bytes, then evaluates four independent, additive signals:

| Signal | Threshold | Rationale |
|---|---|---|
| **Large transfer** | ≥ 5 MB outbound | Default threshold for "worth a look" — tune via source if your environment's baseline differs |
| **Asymmetric ratio** | outbound ≥ 512 KB *and* outbound/inbound ≥ 4.0× | Normal request/response traffic (web browsing, API calls) is response-heavy, not request-heavy; a flow sending far more than it receives inverts that pattern |
| **Uncommon port** | destination port not in the common-services set (80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389, 445, 139, 137, 138, 123, 67, 68) *and* ≥ 1 MB transferred | Bulk transfers over non-standard ports are unusual for normal application traffic |
| **No DNS resolution** | destination IP never appeared in any DNS *response* in the capture, *and* ≥ 5 MB transferred | Direct-to-IP traffic bypasses DNS-based monitoring/blocking — a common evasion pattern |

A flow triggers a finding if **any** signal fires; severity is escalated to
**HIGH** when the transfer is ≥ 2× the large-transfer threshold, or when
**3 or more** signals fire together on the same flow.

---

<a name="http-object-carving"></a>
## 8. HTTP object carving & credential detection

**File:** `http_analysis.py`

**Object carving:** REVENANT looks for the HTTP header/body boundary
(`\r\n\r\n`) in a response's raw payload. If the response's `Content-Type`
is present and is not `text/html`, everything after that boundary is
treated as a candidate file body, hashed with SHA-256, and recorded
alongside its declared content type, size, and any filename found in a
`Content-Disposition` header. This is intentionally lightweight (no TCP
stream reassembly across multiple packets) — it catches the common case of
a response body landing within a single captured payload, which covers a
large share of real HTTP file transfers in practice.

**Credential detection** uses three narrow, specific regex patterns rather
than a general-purpose secret scanner (to keep the false-positive rate
low):

1. `(username|user|login|email)=<value>` in a request body — form-encoded
   login field.
2. `(password|passwd|pwd)=<value>` in a request body — form-encoded
   password field.
3. `Authorization: Basic <base64>` header — HTTP Basic Authentication,
   which is base64-encoded (**not encrypted**) and trivially reversible.

---

<a name="composite-risk-score"></a>
## 9. Composite risk score

**File:** `risk_score.py::compute_investigation_risk()`

A single, transparent, **additive** 0–100 score computed purely from the
already-produced results of every other module — there is no separate
"risk analysis" pass over raw packets. Every possible contribution is
listed below; the final score is the sum of every factor that fired,
capped at 100.

| Finding | Points | Category |
|---|---|---|
| Vertical port scan detected (HIGH severity scan) | 20 | Reconnaissance |
| Vertical port scan detected (MEDIUM severity scan) | 12 | Reconnaissance |
| Horizontal host scan detected (HIGH severity scan) | 20 | Reconnaissance |
| Horizontal host scan detected (MEDIUM severity scan) | 12 | Reconnaissance |
| Beaconing pattern, regularity ≥ 85% | 25 | Command & Control |
| Beaconing pattern, regularity 55–85% | 15 | Command & Control |
| Additional beacon candidates beyond the first | up to +10 (3 pts each) | Command & Control |
| Anomalous outbound transfer, any HIGH-severity candidate present | 25 | Exfiltration |
| Anomalous outbound transfer, only MEDIUM-severity candidates | 12 | Exfiltration |
| DGA-style domain(s) queried | up to 18 (2 pts per domain) | Command & Control |
| Possible DNS tunneling indicators | 18 | Exfiltration |
| ARP conflicts including a HIGH-severity conflict (3+ MACs on one IP) | 22 | Man-in-the-Middle |
| ARP conflicts, only MEDIUM-severity (exactly 2 MACs) | 14 | Man-in-the-Middle |
| Single JA3 fingerprint reused across 3+ distinct destinations | 10 | Command & Control |
| Plaintext credentials observed over HTTP | up to 15 (5 pts each) | Data Exposure |
| Non-browser User-Agent strings observed | up to 8 (2 pts each) | Reconnaissance |

**Verdict bands:**

| Score | Verdict |
|---|---|
| ≥ 70 | **CRITICAL** |
| 45–69 | **HIGH** |
| 22–44 | **MODERATE** |
| 8–21 | **LOW** |
| 0–7 | **MINIMAL** |

Every factor that fires is retained (not just summarized into the total) —
the full table is rendered in the terminal report and included in the JSON
export under `risk_score.factors`, so the score is always auditable back to
its individual contributing findings.

---

<a name="known-limitations"></a>
## 10. Known limitations

Documenting these honestly is part of not being a black box:

- **No TCP stream reassembly across many segments.** HTTP/TLS parsing
  operates on individual captured payloads. A response body split across
  many small TCP segments (rather than landing in one or two captures)
  may not be fully carved.
- **Heuristic, not signature-based.** DGA scoring, beacon regularity, and
  exfiltration flagging are statistical heuristics meant to focus a human
  analyst's attention — they are not a substitute for signature/IOC-based
  detection against known-bad indicators, and they will occasionally flag
  legitimate-but-unusual traffic (a legitimate SaaS product with an
  auto-generated subdomain, a backup tool with a regular sync interval, a
  CDN with a genuinely uncommon port).
- **NTFS Alternate Data Streams and file-system-level artifacts are out of
  scope** for a *network* forensics tool — REVENANT only ever looks at
  what's inside the pcap.
- **Encrypted payloads stay encrypted.** REVENANT never attempts to
  decrypt TLS traffic; JA3 and SNI extraction work specifically *because*
  they operate on the unencrypted handshake metadata, not the encrypted
  application data.
- **Thresholds are defaults, not universal truths.** A 5 MB "large
  transfer" threshold is sensible for a typical office LAN capture and may
  need tuning for environments with routinely large legitimate transfers
  (media production networks, backup infrastructure, etc.).
