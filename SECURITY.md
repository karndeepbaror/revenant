# Security Policy

## Supported Versions

REVENANT is currently pre-1.0-stable and actively developed on `main`.
Security fixes are applied to the latest release only.

| Version | Supported |
|---|---|
| 1.0.x (`main`) | ✅ |
| older / pre-release | ❌ |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a security issue in REVENANT — for example, a way a
maliciously crafted `.pcap` file could cause REVENANT to crash in an
unsafe way, consume unbounded resources, execute unintended code, or
otherwise behave outside its documented passive-analysis scope — please
report it privately:

- Open a [GitHub Security Advisory](https://github.com/cryptonicarea/revenant/security/advisories/new)
  on this repository (preferred), **or**
- Contact the maintainers directly through the Cryptonic Area GitHub
  organization: https://github.com/cryptonicarea

Please include:

- A clear description of the issue and its potential impact.
- Steps to reproduce, ideally including a minimal example file or script
  that triggers the behavior.
- Your assessment of severity, if you have one.

## What counts as in-scope

Since REVENANT's entire design principle is **passive, read-only analysis
of a file the user explicitly provides** (see the
[README's design principles](README.md#design-principles)), the security
model that matters most is: *can a malicious evidence file do something to
REVENANT (or the machine running it) beyond producing an incorrect
analysis result?* Examples of in-scope reports:

- Crashes, hangs, or unbounded memory/CPU consumption triggered by a
  crafted pcap.
- Any code path where REVENANT could be made to read or write files
  outside the evidence file and the explicitly-requested `--out` export
  directory.
- Any dependency (scapy, rich) vulnerability that's reachable through
  REVENANT's actual usage of that dependency.

**Out of scope:** REVENANT is not a network-facing service (it has no
listener, no API, no server component) — reports assuming a network attack
surface don't apply here.

## Response

We aim to acknowledge reports within a reasonable timeframe and will work
with you on a coordinated disclosure timeline appropriate to the severity
of the issue. Credit will be given in the release notes for confirmed
reports, unless you prefer to remain anonymous.
