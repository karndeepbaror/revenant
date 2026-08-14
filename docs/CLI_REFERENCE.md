# REVENANT — CLI Reference

Full reference for every command, flag, and invocation style REVENANT
supports.

---

## Invocation forms

All three of these are equivalent — REVENANT accepts the `investigate`
keyword as an optional, purely readable prefix:

```bash
python3 revenant.py investigate capture.pcap
python3 revenant.py capture.pcap
python3 revenant.py                       # interactive mode, prompts for a path
```

Interactive mode is useful when you don't remember the exact filename or
path — REVENANT will keep prompting until you give it a file that exists:

```
  No evidence file supplied — entering interactive mode.
  revenant› enter path to .pcap/.pcapng evidence file: _
```

---

## Flags

### `--export {json,html,both,ioc}`

Writes a report artifact to disk in addition to the terminal output.

| Value | Produces |
|---|---|
| `json` | Full structured findings as a single `.json` file — every module's complete dataclass output, suitable for feeding into other tooling, a SIEM, or a script. |
| `html` | A self-contained, styled `.html` case file (dark theme, no external assets) — suitable for sharing with someone who doesn't have REVENANT installed. |
| `both` | Both of the above in one run. |
| `ioc` | A flat, plaintext `.txt` file of indicators only (external IPs, suspicious domains, JA3 hashes, scanner IPs, beacon pairs) — the fastest artifact to paste into a ticket or a blocklist. |

```bash
python3 revenant.py capture.pcap --export json
python3 revenant.py capture.pcap --export html
python3 revenant.py capture.pcap --export both
python3 revenant.py capture.pcap --export ioc
```

### `--out DIR`

Overrides the output directory for exported reports. Defaults to
`./revenant_reports/` (created automatically if it doesn't exist).

```bash
python3 revenant.py capture.pcap --export both --out ~/cases/incident-4471/
```

Filenames are auto-generated as `revenant_<basename>_<timestamp>.<ext>`, so
running REVENANT against the same file twice never overwrites a previous
report.

### `--no-anim`

Disables the boot sequence, ASCII banner animation, and progress bar
animation — everything renders instantly instead. Useful for CI pipelines,
scripted batch analysis, or just a faster repeated-run workflow during
active investigation.

```bash
python3 revenant.py capture.pcap --no-anim
```

### `--limit N`

Only ingests and analyzes the **first N packets** of the capture. Useful
for a fast first look at a very large evidence file before committing to a
full analysis pass.

```bash
python3 revenant.py huge_capture.pcap --limit 50000
```

When truncation is active, the terminal report and JSON export both note it
explicitly (`capture_meta.truncated: true`, along with the limit applied)
so a truncated analysis is never mistaken for a complete one.

### `--entropy-buckets N`

Controls how many time buckets the traffic-volume sparkline (in the
Protocol Distribution section) is divided into. Default is `60`. Higher
values give a finer-grained timeline at the cost of a wider terminal
sparkline.

```bash
python3 revenant.py capture.pcap --entropy-buckets 120
```

### `--min-similarity N`

Reserved for future cross-capture correlation features (comparing findings
across multiple evidence files from the same incident). Currently accepted
but not yet used by any active module — see
[ROADMAP.md](ROADMAP.md).

### `--version`

Prints the tool name and version, then exits.

```bash
python3 revenant.py --version
# R E V E N A N T v1.0.0 :: CORE-BUILD 001
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Investigation completed successfully. |
| `1` | Evidence file not found, or another handled error occurred before analysis started. |
| `130` | Interrupted by the user (Ctrl+C). |

---

## Common recipes

**Quick triage of a large capture, animations off, JSON for later review:**
```bash
python3 revenant.py incident.pcap --no-anim --limit 100000 --export json
```

**Full investigation with a shareable HTML case file:**
```bash
python3 revenant.py incident.pcap --export html --out ~/cases/2026-08-14/
```

**Batch-processing multiple captures in a shell loop:**
```bash
for f in evidence/*.pcap; do
    python3 revenant.py "$f" --no-anim --export both --out "reports/$(basename "$f" .pcap)/"
done
```

**Fast IOC list for a blocklist / ticket, nothing else:**
```bash
python3 revenant.py incident.pcap --no-anim --export ioc
```
