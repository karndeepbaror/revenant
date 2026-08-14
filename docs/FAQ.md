# REVENANT — Frequently Asked Questions

### Does REVENANT capture live network traffic?

No. REVENANT is strictly a **post-capture analysis tool**. It reads an
existing `.pcap`/`.pcapng` file you already have — it never opens a network
interface, never sends a packet, and never runs live. If you need to
*produce* a capture, use `tcpdump`, `Wireshark`, or `dumpcap`, then hand the
resulting file to REVENANT.

### Does REVENANT send my capture file anywhere?

No. Every module runs entirely locally. REVENANT makes no network
requests, has no telemetry, and no cloud dependency of any kind. The only
file it reads is the one you point it at, and the only files it writes are
the optional export reports you explicitly request with `--export`.

### Is REVENANT a replacement for Wireshark?

No — they solve different problems. Wireshark is an interactive *packet
viewer/dissector* — you use it to manually inspect individual packets and
apply display filters. REVENANT is an *automated investigation engine* —
you point it at a file and it runs the full analyst workflow (protocol
stats, DNS/HTTP/TLS extraction, scan/beacon/exfil correlation, risk
scoring) without you writing a single filter. Many analysts use both:
REVENANT for the fast automated first pass and to know *where to look*,
Wireshark to manually drill into specific packets afterward.

### Will REVENANT tell me for certain that a file is malicious / that an attack happened?

No, and treat any tool that claims to with suspicion. REVENANT's detection
modules are **heuristic signal generators**, not verdicts. A high risk
score means "this capture contains multiple patterns that are strongly
associated with malicious activity and deserve human review" — not "this
is definitely an attack." See
[DETECTION_METHODOLOGY.md](DETECTION_METHODOLOGY.md#known-limitations) for
an honest accounting of false-positive scenarios for every module.

### Why did REVENANT flag [some legitimate service] as suspicious?

The most common causes, by module:

- **DGA domain flag on a real domain** — some legitimate services
  (CDN edge nodes, some SaaS auto-generated subdomains) genuinely use
  short, high-entropy subdomains. The DGA score is lexical only; it has no
  concept of domain reputation.
- **Beacon flag on a legitimate scheduled service** — backup software,
  monitoring agents, and license-check-in tools often *also* connect on a
  fixed interval. Regularity alone doesn't distinguish "malware" from
  "well-behaved scheduled software" — that's a judgment call for the
  analyst reviewing the finding.
- **Exfil flag on a large legitimate transfer** — file syncs, backups, and
  large legitimate downloads can trip the size/asymmetry thresholds. Tune
  `LARGE_TRANSFER_BYTES` and related constants in `exfil_detection.py` for
  your environment's normal baseline if this happens often.

If you believe a finding is a clear, reproducible false positive, please
open an issue using the **Detection False Positive** template — see
[../CONTRIBUTING.md](../CONTRIBUTING.md).

### Can REVENANT decrypt TLS traffic?

No, and it never attempts to. REVENANT's TLS module only reads the
`ClientHello` message, which is sent unencrypted *by design* in the TLS
protocol (the server needs to see it before any encryption keys exist).
Everything after the handshake stays encrypted and REVENANT never touches
it.

### Does REVENANT work with capture files from Wireshark / tcpdump / tshark?

Yes — any standard `.pcap` or `.pcapng` file works, since REVENANT parses
them with the same underlying library family (`scapy`) that these tools
use to write them.

### How large a capture file can REVENANT handle?

`pcap_loader.py` streams the file (via scapy's `PcapReader`) rather than
loading it entirely into memory, so file size on disk isn't the binding
constraint — total packet count and available RAM for the resulting
in-memory `Frame`/`Flow` objects are. For very large captures, use
`--limit N` for a fast first pass (see
[CLI_REFERENCE.md](CLI_REFERENCE.md#--limit-n)).

### Why does the repository have a nested `revenant/revenant/` folder?

This keeps the documentation, license, and GitHub metadata at the
repository root, while the runnable tool itself stays fully self-contained
in its own folder — so `revenant/revenant/` can be copied elsewhere (a
different repo, a Docker image, a USB drive during an IR engagement)
without dragging the documentation along. See the repository layout
diagram in the main [README](../README.md#repository-layout).

### Can I use REVENANT's findings in a legal/formal investigation?

REVENANT produces investigative leads and structured analysis — it is not
a chain-of-custody or evidence-integrity tool, and it makes no claims about
forensic soundness for legal proceedings. If your use case requires formal
chain-of-custody handling, follow your organization's or jurisdiction's
established forensic procedures for evidence handling *before and
alongside* using REVENANT for analysis.

### Is REVENANT free?

Yes — REVENANT is released under the MIT License (see
[../LICENSE](../LICENSE)), free to use, modify, and redistribute, including
commercially.

### How do I report a bug or request a feature?

See [../CONTRIBUTING.md](../CONTRIBUTING.md) — there are dedicated GitHub
issue templates for bug reports, feature requests, and detection
false-positive reports under `.github/ISSUE_TEMPLATE/`.
