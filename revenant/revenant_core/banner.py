"""
REVENANT :: banner.py
================================================================
Boot sequence, ASCII banner and credits screen.
Pure presentation layer — no analysis logic lives here.
================================================================
"""

from __future__ import annotations
import sys
import time
import random
from rich.console import Console
from rich.text import Text
from rich.align import Align
from rich.panel import Panel

TOOL_NAME = "R E V E N A N T"
TOOL_TAGLINE = "Network Traffic Investigation Engine — PCAP In, Case File Out"
VERSION = "v1.0.0 :: CORE-BUILD 001"
DEVELOPER_NAME = "Cryptonic Area"
DEVELOPER_GITHUB = "https://github.com/cryptonicarea"

REVENANT_ART = r"""
██████╗ ███████╗██╗   ██╗███████╗███╗   ██╗ █████╗ ███╗   ██╗████████╗
██╔══██╗██╔════╝██║   ██║██╔════╝████╗  ██║██╔══██╗████╗  ██║╚══██╔══╝
██████╔╝█████╗  ██║   ██║█████╗  ██╔██╗ ██║███████║██╔██╗ ██║   ██║
██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██╔══██║██║╚██╗██║   ██║
██║  ██║███████╗ ╚████╔╝ ███████╗██║ ╚████║██║  ██║██║ ╚████║   ██║
╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝
"""

BOOT_LINES = [
    "initializing revenant investigation core",
    "mounting packet ingestion subsystem",
    "loading protocol dissection tables",
    "arming DNS / TLS / HTTP correlation engines",
    "calibrating scan & beacon heuristic models",
    "priming ARP integrity monitor",
    "opening case file workspace",
    "investigation environment ready",
]

GLYPHS = "░▒▓█▚▞▟▙▛▜◈◇◆⟁⟐⌬❖✦"


def _glitch_line(width: int) -> str:
    return "".join(random.choice(GLYPHS) for _ in range(width))


def boot_sequence(console: Console, animate: bool = True):
    if not animate:
        return
    width = min(console.size.width, 74)
    console.print()
    for _ in range(3):
        console.print(Text(_glitch_line(width), style="dim cyan"), justify="center")
        time.sleep(0.04)
    console.print()

    for line in BOOT_LINES:
        console.print(f"  [dim red][[/dim red][bold green]•[/bold green][dim red]][/dim red] {line}...", end="")
        sys.stdout.flush()
        time.sleep(random.uniform(0.10, 0.20))
        console.print(" [bold green]OK[/bold green]")
    console.print()


def render_banner(console: Console, animate: bool = True):
    art_lines = REVENANT_ART.strip("\n").split("\n")
    console.print()
    for idx, line in enumerate(art_lines):
        style = "bold cyan" if idx % 2 == 0 else "bold dark_cyan"
        console.print(Align.center(Text(line, style=style)))
        if animate:
            time.sleep(0.025)

    console.print(Align.center(Text(TOOL_TAGLINE, style="bold red")))
    console.print(Align.center(Text(VERSION, style="dim white")))
    console.print(Align.center(Text(f"developed by {DEVELOPER_NAME}  ·  {DEVELOPER_GITHUB}", style="dim italic grey62")))
    console.print()
    console.print(Align.center(Text("─" * min(console.size.width - 4, 68), style="dim cyan")))
    console.print()


def render_credits_panel(console: Console):
    body = Text()
    body.append(f"{TOOL_NAME}\n", style="bold cyan")
    body.append(f"{TOOL_TAGLINE}\n\n", style="red")
    body.append(f"Version     : ", style="dim white"); body.append(f"{VERSION}\n", style="white")
    body.append(f"Developer   : ", style="dim white"); body.append(f"{DEVELOPER_NAME}\n", style="white")
    body.append(f"GitHub      : ", style="dim white"); body.append(f"{DEVELOPER_GITHUB}\n", style="underline cyan")
    body.append(f"License     : ", style="dim white"); body.append("MIT — free & open for the community\n", style="white")
    console.print(Panel(body, border_style="cyan", title="[bold]About REVENANT[/bold]", title_align="left", padding=(1, 2)))
