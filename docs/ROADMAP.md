# REVENANT — Roadmap

A living list of where REVENANT is headed. Nothing here is a promise of a
delivery date — this is a direction, not a schedule. Community input via
GitHub issues (see [../CONTRIBUTING.md](../CONTRIBUTING.md)) directly
shapes this list.

---

## Near-term

- **Cross-capture correlation.** The `--min-similarity` flag is already
  reserved on the CLI for this: given multiple evidence files from the
  same incident (e.g. captures from several hosts), correlate shared IOCs
  (same JA3 hash, same beacon destination, same DGA-style domains) across
  all of them into one merged case file.
- **Configurable detection thresholds.** Move the constants currently
  hard-coded in each detection module (scan thresholds, beacon minimums,
  exfil size cutoffs, DGA score cutoff) into an optional config file, so
  an environment with different normal-traffic baselines can tune
  REVENANT without editing source.
- **PCAP-NG comment/annotation export.** Write REVENANT's findings back as
  packet comments in a `.pcapng` file, so opening the annotated capture in
  Wireshark shows REVENANT's findings inline against the actual packets.
- **Additional protocol coverage.** SMB/SMB2 session and file-share
  activity parsing; FTP command/data channel correlation; ICMP tunneling
  detection (payload-size and timing analysis on ICMP echo traffic).

## Medium-term

- **Streaming / incremental mode.** Accept a growing pcap file (e.g. one
  being actively written by `tcpdump -w` during a live incident) and
  re-run correlation incrementally rather than requiring a complete,
  closed file.
- **Baseline learning mode.** Given a known-clean reference capture from
  the same environment, compute a baseline for "normal" top talkers,
  common ports, and typical transfer sizes, then score anomalies in a
  target capture relative to that baseline instead of fixed global
  defaults.
- **Expanded TLS analysis.** JA3S (server-side fingerprint from
  ServerHello) and certificate chain inspection (self-signed detection,
  unusually short validity periods, mismatched CN/SAN vs. SNI).

## Exploratory / under consideration

- Optional GeoIP-style classification of external IPs using a
  locally-provided offline database (never a live lookup — keeping with
  REVENANT's offline-first design principle).
- A lightweight web-based report viewer for the JSON export, as an
  alternative to the static HTML export, for interactively filtering a
  large timeline.
- Plugin architecture for community-contributed detection modules,
  formalizing the extension pattern already documented in
  [ARCHITECTURE.md](ARCHITECTURE.md#8-extensibility).

---

## Explicitly out of scope

To keep REVENANT's design principles intact (see the main
[README](../README.md#design-principles)), the following will **not** be
added, regardless of how often requested:

- Any form of active scanning, packet injection, or traffic replay.
- Any built-in cloud upload, telemetry, or "phone home" behavior.
- Automated blocking/response actions (REVENANT investigates; it does not
  act on a network).

---

Have an idea that isn't listed here? Open a
[feature request](../.github/ISSUE_TEMPLATE/feature_request.md).
