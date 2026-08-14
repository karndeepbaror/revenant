# REVENANT — Installation

## Requirements

- **Python 3.9 or newer**
- Two Python packages: [`scapy`](https://scapy.net/) (packet parsing) and
  [`rich`](https://github.com/Textualize/rich) (terminal rendering)

REVENANT has no compiled/native dependencies — everything is pure Python,
so installation is the same three commands on every platform.

---

## Linux / macOS

```bash
git clone https://github.com/cryptonicarea/revenant.git
cd revenant/revenant

python3 -m venv .venv               # optional but recommended
source .venv/bin/activate

pip install -r requirements.txt

python3 revenant.py --version
```

## Windows (PowerShell)

```powershell
git clone https://github.com/cryptonicarea/revenant.git
cd revenant\revenant

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt

python revenant.py --version
```

> **Note on Npcap/WinPcap:** scapy's *packet capture* features need
> Npcap installed on Windows. REVENANT does **not** capture live traffic —
> it only *reads existing `.pcap`/`.pcapng` files* — so Npcap is **not
> required** to run REVENANT. If `pip install scapy` prints a warning
> about a missing capture backend, it's safe to ignore for REVENANT's
> use case.

---

## Verifying the install

Run REVENANT against the sample evidence file that ships in this
repository:

```bash
# from inside revenant/revenant/
python3 revenant.py ../sample_evidence.pcap
```

You should see the animated boot sequence, the ASCII banner, then a full
investigation report ending in a **CRITICAL** verdict (the sample file is
deliberately engineered to trigger every detection module).

---

## Installing without git

If you received this project as a `.zip` rather than cloning it, just
extract it and follow the same steps from inside the extracted
`revenant/revenant/` folder:

```bash
unzip revenant.zip
cd revenant/revenant
pip install -r requirements.txt
python3 revenant.py --version
```

---

## Dependency versions

`requirements.txt` pins minimum versions only:

```
scapy>=2.5.0
rich>=13.0.0
```

REVENANT is tested against current releases of both libraries. If you hit
an incompatibility with a very new or very old version of either, please
open an issue (see [../CONTRIBUTING.md](../CONTRIBUTING.md)) with the exact
version numbers (`pip show scapy rich`) and the full traceback.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'scapy'` (or `rich`)**
You're running `python3 revenant.py` without having installed
`requirements.txt` first, or you installed it into a different environment
than the one you're running with. Confirm with:
```bash
python3 -c "import scapy, rich; print('ok')"
```

**Garbled box-drawing characters / broken layout in the terminal**
Your terminal isn't rendering UTF-8/Unicode box-drawing characters
correctly. Try a different terminal emulator, or run with `--no-anim`
(the report tables still render, just without the animated boot sequence).

**Very large capture files take a long time or use a lot of memory**
Use `--limit N` to cap ingestion to the first N packets for a fast first
pass — see [CLI_REFERENCE.md](CLI_REFERENCE.md#--limit-n).
