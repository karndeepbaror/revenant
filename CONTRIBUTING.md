# Contributing to REVENANT

Thanks for considering a contribution — bug reports, detection-accuracy
feedback, documentation fixes, and pull requests are all genuinely welcome.

---

## Before you start

- Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
  [docs/MODULES.md](docs/MODULES.md) first — most contributions touch
  exactly one module, and understanding how the pipeline is wired together
  will save you time.
- Check [docs/ROADMAP.md](docs/ROADMAP.md) and existing open issues before
  starting significant new work, to avoid duplicate effort.
- REVENANT is a **strictly passive, read-only** analysis tool by design
  (see the [README's design principles](README.md#design-principles)).
  Contributions that add active scanning, packet injection/replay, cloud
  upload, or automated network response actions will not be accepted,
  regardless of how useful they might be elsewhere — that's simply not
  what this project is.

---

## Reporting a bug

Use the **Bug Report** issue template
(`.github/ISSUE_TEMPLATE/bug_report.md`). Please include:

- The exact command you ran.
- The full traceback, if there was one.
- `python3 --version` and `pip show scapy rich` output.
- If possible, a minimal `.pcap` that reproduces the issue (or a script
  that generates one — see `gen_test_pcap.py`-style synthetic generation
  patterns if you'd rather not share real traffic).

## Reporting a detection false positive

If a detection module flagged something you believe is clearly legitimate,
use the **Detection False Positive** issue template. This is genuinely
valuable — every detection module in REVENANT is a heuristic (see
[docs/DETECTION_METHODOLOGY.md](docs/DETECTION_METHODOLOGY.md)), and
real-world false-positive patterns directly inform threshold tuning.

## Requesting a feature

Use the **Feature Request** issue template. For a new detection module in
particular, it helps enormously to include:

- What network behavior/pattern you want detected.
- What signal(s) in a pcap actually indicate that behavior.
- Any reference to how existing tools (Zeek, Suricata, RITA, NetworkMiner,
  etc.) detect the same thing, if applicable.

---

## Submitting a pull request

1. **Fork** the repository and create a branch off `main`.
2. Keep the change focused — one logical change per PR is much easier to
   review than a large mixed changeset.
3. Follow the existing code style: dataclasses for structured results,
   one `analyze_x()` function per module, no analysis logic in
   `banner.py`/`report.py` (see
   [ARCHITECTURE.md](docs/ARCHITECTURE.md#7-presentation-layer)).
4. If you're adding a new detection module, follow the extension pattern
   documented in
   [ARCHITECTURE.md §8](docs/ARCHITECTURE.md#8-extensibility).
5. Compile-check every file you touch:
   ```bash
   python3 -m py_compile revenant/revenant_core/your_module.py
   ```
6. Test against the bundled `sample_evidence.pcap` (and ideally a synthetic
   pcap targeting your specific change) before opening the PR:
   ```bash
   cd revenant/revenant
   python3 revenant.py ../sample_evidence.pcap --no-anim
   ```
7. Update the relevant documentation — new modules should get an entry in
   [docs/MODULES.md](docs/MODULES.md), and new detection heuristics should
   be documented in
   [docs/DETECTION_METHODOLOGY.md](docs/DETECTION_METHODOLOGY.md) with the
   same level of "show your work" detail as the existing entries.
8. Open the PR using the pull request template — describe *what* changed
   and *why*, and link any related issue.

---

## Code style notes

- **Dataclasses, not dicts**, for any structured result passed between
  modules — see any existing `*Result` class for the pattern.
- **No hidden state.** Every `analyze_x()` function should be a pure
  function of its inputs — no module-level mutable globals, no reading
  files other than the one explicitly passed in.
- **Every heuristic needs a documented threshold and rationale.** If you
  add a magic number, add a comment (or a `DETECTION_METHODOLOGY.md`
  entry) explaining where it came from.
- **Type hints are expected** on function signatures for new code.

---

## Code of Conduct

Participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Security issues

Do **not** open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for the responsible disclosure process.
