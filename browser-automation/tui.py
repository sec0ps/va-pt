"""
Three panel rich TUI for the MITM autopwn orchestrator.
Panel one shows Responder poisoning and captured NetNTLM hashes. Panel two shows
bettercap spoofing, DNS lure hits, and autopwn page delivery including failures
distinct from successes. Panel three shows confirmed Metasploit sessions. Reads
snapshots from shared state and never mutates it.
"""

import time

from rich.live import Live
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.console import Group


def run_tui(state, stop_event, refresh_hz=2):
    layout = _build_layout()
    with Live(layout, refresh_per_second=refresh_hz, screen=True) as live:
        while not stop_event.is_set():
            snap = state.snapshot()
            height = live.console.size.height
            rows = max(1, height - 9)
            mitm_rows = max(1, height - 10)
            layout["header"].update(_header(snap))
            layout["hashes"].update(_hashes_panel(snap, rows))
            layout["mitm"].update(_mitm_panel(snap, mitm_rows))
            layout["sessions"].update(_sessions_panel(snap, rows))
            layout["footer"].update(_footer(snap))
            time.sleep(1.0 / refresh_hz)


def _build_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="hashes"),
        Layout(name="mitm"),
        Layout(name="sessions"),
    )
    return layout


def _fmt_uptime(seconds):
    seconds = int(seconds)
    return "%02d:%02d:%02d" % (seconds // 3600, (seconds % 3600) // 60, seconds % 60)


def _header(snap):
    text = Text()
    text.append(" MITM Autopwn Orchestrator ", style="bold white on dark_blue")
    text.append("   phase ", style="bold")
    text.append(snap["phase"], style="cyan")
    text.append("   uptime ", style="bold")
    text.append(_fmt_uptime(snap["uptime"]), style="green")
    if snap["status"]:
        text.append("   " + snap["status"], style="yellow")
    return Panel(text, border_style="blue")


def _hashes_panel(snap, rows=14):
    table = Table(expand=True, show_edge=False, pad_edge=False)
    table.add_column("Client", style="cyan", no_wrap=True)
    table.add_column("User", style="white")
    table.add_column("Type", style="magenta", no_wrap=True)
    for h in snap["hashes"][-rows:]:
        user = h["domain"] + "\\" + h["user"] if h["domain"] not in ("", "?") else h["user"]
        table.add_row(h["client"], user, h["htype"])
    title = "Poisoning and Hashes   poison=%d   creds=%d" % (len(snap["poison_hits"]), len(snap["hashes"]))
    return Panel(table, title=title, border_style="green")


def _mitm_panel(snap, rows=12):
    victims = snap["victims"]

    vtable = Table(expand=True, show_edge=False, pad_edge=False)
    vtable.add_column("Victim", style="cyan", no_wrap=True)
    vtable.add_column("Browser/OS", style="white")
    vtable.add_column("State", no_wrap=True)
    ordered = sorted(victims.items(), key=lambda kv: kv[1]["ts"], reverse=True)
    for ip, v in ordered[:rows]:
        label, style = _victim_state(v)
        bo = " ".join(x for x in [v.get("browser"), v.get("os")] if x) or "-"
        vtable.add_row(ip, bo, Text(label, style=style))

    summary = Text()
    summary.append("spoofed=%d" % len(snap["spoofed_hosts"]), style="cyan")
    summary.append("   dns=%d" % len(snap["dns_hits"]), style="magenta")
    served = sum(1 for v in victims.values() if v["served"])
    failed = sum(1 for v in victims.values() if v["failed"] and not v["exploited"])
    summary.append("   served=%d" % served, style="green")
    summary.append("   failed=%d" % failed, style="red")

    return Panel(Group(summary, vtable), title="MITM and Delivery", border_style="magenta")


def _victim_state(v):
    if v["exploited"]:
        return "exploited", "bold green"
    if v["failed"] and not v["served"]:
        return "failed", "red"
    if v["failed"]:
        return "served/failed", "yellow"
    if v["served"]:
        return "served", "cyan"
    return v.get("last") or "seen", "white"


def _sessions_panel(snap, rows=14):
    table = Table(expand=True, show_edge=False, pad_edge=False)
    table.add_column("ID", style="yellow", no_wrap=True)
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Platform", style="white")
    table.add_column("Via", style="magenta")
    for sid, s in list(snap["sessions"].items())[-rows:]:
        via = s["via_exploit"].split("/")[-1] if s["via_exploit"] else "-"
        table.add_row(str(sid), s["host"], s.get("platform") or "-", via)
    return Panel(table, title="Sessions   count=%d" % len(snap["sessions"]), border_style="yellow")


def _footer(snap):
    recent = snap["events"][-1]["msg"] if snap["events"] else "running"
    text = Text()
    text.append(" ctrl-c to stop and tear down ", style="bold white on grey23")
    text.append("   " + recent, style="dim")
    return Panel(text, border_style="blue")
