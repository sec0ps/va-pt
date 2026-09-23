#!/usr/bin/env python3
# =============================================================================
# Location    automation/tui.py
# Author      Keith Pachulski
# Company     Red Cell Security LLC
# Email       keith@redcellsecurity.org
# Website     www.redcellsecurity.org
#
# License     MIT License
#
# Purpose     Rich terminal dashboard for the orchestrator: live host lifecycle,
#             attack progress, and a proven-impact results view of sessions,
#             unauthenticated access, and credentials.
#
# SECURITY NOTICE
#             This software is intended for authorized security assessment and
#             defensive operations only. Use it exclusively on systems you own or
#             are explicitly permitted to test. Unauthorized use may violate law.
#
# DISCLAIMER
#             This software is provided "as is" without warranty of any kind. The
#             author and Red Cell Security LLC accept no liability for damage or
#             misuse arising from its operation.
# =============================================================================

"""
tui.py - rich Live dashboard. Read-only view over RunState.

Three stacked regions: a fixed stat bar on top, an active-hosts pane in the
middle (hosts still moving through scan/analyze/check/fire), and a results pane
on the bottom (exploitable and exploited hosts with their winning module and any
opened sessions). The dashboard never mutates state; it pulls deep-copied
snapshots through RunState's locked accessors (stats, active_hosts, result_hosts)
so a repaint never blocks a pipeline worker and never races one.

Lifecycle is driven entirely by the orchestrator on the main thread: start()
once before the run, refresh() each poll from the main loop, stop() during
teardown. There is no internal refresh thread (auto_refresh is off), so paints
stay synchronized with the loop and nothing fights the terminal. screen mode is
used so the run owns the alternate buffer and the original terminal is restored
cleanly on stop; this pairs with the orchestrator sending logs to file (not
stderr) whenever the TUI is up. On a non-tty stdout start() raises so the
orchestrator falls back to headless.
"""

from __future__ import annotations

import logging
import sys
import time

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from state import HostState, Verdict, TOOL, VERSION

logger = logging.getLogger(__name__)

# Header is fixed height: title + progress + counts = 3 lines, plus the 2 panel
# border rows. The body below splits left (active over results) and right (feed).
_HEADER_SIZE = 5
_ACTIVE_RATIO = 3
_RESULTS_RATIO = 2
_BODY_LEFT_RATIO = 3        # left column (host tables) vs the command feed
_FEED_RATIO = 2

# Rows lost per pane to the panel border (2) and the table header (1).
_PANE_CHROME = 3

# Latchkey palette, matched to the console dark-ink theme (crimson accent, amber
# secondary). Severity ramp and status colors mirror the web UI so the engine TUI
# and the Latchkey console read as one product.
_LK_ACCENT = "#be1e2d"   # crimson, primary accent (attack / proven impact)
_LK_AMBER = "#d98a1e"    # amber, secondary accent (msf activity / credentials)
_LK_TEXT = "#ece9e8"
_LK_DIM = "#a5a1a0"
_LK_FAINT = "#6b6c6e"
_LK_OK = "#3ecf8e"       # green (compromised / session)
_LK_INFO = "#4aa8ff"     # blue (scanning / discovery)
_LK_CRIT = "#f0555f"     # critical / error
_LK_HIGH = "#f2853a"
_LK_MED = "#e8c14a"


_FEED_STYLE = {
    "nmap": _LK_INFO,
    "msf": _LK_AMBER,
    "fire": f"bold {_LK_ACCENT}",
    "phase": f"bold {_LK_TEXT}",
}

_STATE_STYLE = {
    HostState.QUEUED: _LK_DIM,
    HostState.DISCOVERED: _LK_INFO,
    HostState.DOWN: _LK_FAINT,
    HostState.SCANNING: _LK_INFO,
    HostState.ANALYZED: _LK_INFO,
    HostState.ATTACKING: f"bold {_LK_AMBER}",
    HostState.COMPROMISED: f"bold {_LK_OK}",
    HostState.CLEAN: _LK_FAINT,
    HostState.ERROR: f"bold {_LK_CRIT}",
}

_VERDICT_STYLE = {
    Verdict.VULNERABLE: f"bold {_LK_CRIT}",
    Verdict.LIKELY: _LK_AMBER,
    Verdict.SAFE: _LK_OK,
    Verdict.UNSUPPORTED: _LK_FAINT,
    Verdict.UNKNOWN: _LK_FAINT,
}

_VERDICT_RANK = {
    Verdict.VULNERABLE: 3,
    Verdict.LIKELY: 2,
    Verdict.SAFE: 1,
    Verdict.UNSUPPORTED: 0,
    Verdict.UNKNOWN: 0,
}


class Dashboard:
    def __init__(self, run):
        self.run = run
        self.console = Console()
        self._live = None
        self._done = False          # set when the run completes, shows the footer

    # -- lifecycle (main thread only) --

    def start(self):
        if not self.console.is_terminal:
            raise RuntimeError("stdout is not a terminal; use --no-tui")
        # Dashboard is its own renderable (see __rich__), and auto_refresh runs a
        # background paint at refresh_per_second. That keeps the screen live even
        # while the main thread is blocked in a long call (e.g. the discovery SYN
        # sweep), which the old main-loop-only refresh could not do.
        self._live = Live(
            self,
            console=self.console,
            screen=True,
            auto_refresh=True,
            refresh_per_second=4)
        self._live.start(refresh=True)

    def __rich__(self):
        return self._render()

    def refresh(self):
        # The background thread drives most paints; this is a responsiveness nudge
        # from the main loop. Safe to call concurrently (rich Live is locked).
        if self._live is not None:
            try:
                self._live.refresh()
            except Exception:
                pass

    def wait_for_exit(self):
        """Hold the completed dashboard open until the user presses Enter (or sends
        EOF / Ctrl-C). Reads the controlling terminal directly rather than fd 0:
        the venv re-exec (os.execv) and sudo's pty handling can leave sys.stdin as
        an EOF/non-blocking stream, so sys.stdin.readline() returns at once and the
        dashboard drops instead of holding. /dev/tty survives both. The background
        refresh keeps the screen live while we block. Callers must have already made
        the host safe (firewall restored) before this."""
        self._done = True
        self.refresh()
        try:
            with open("/dev/tty") as tty:
                tty.readline()
        except KeyboardInterrupt:
            pass
        except OSError:
            # No controlling terminal (piped/detached). Fall back to stdin so a
            # plain interactive pipe still works; if that is EOF too, just return.
            try:
                sys.stdin.readline()
            except Exception:
                pass

    def stop(self):
        if self._live is None:
            return
        try:
            self._live.stop()
        finally:
            self._live = None
        self._print_final_summary()

    # -- render --

    def _render(self):
        stats = self.run.stats()
        footer_rows = 1 if self._done else 0
        body_rows = max(0, self.console.size.height - _HEADER_SIZE - footer_rows)
        active_h, results_h = _split_heights(body_rows)
        active = self.run.active_hosts(limit=max(1, active_h - _PANE_CHROME))
        results = self.run.result_hosts(limit=max(1, results_h - _PANE_CHROME))
        feed = self.run.recent_activity(max(1, body_rows - 2))

        left = Layout(name="left", ratio=_BODY_LEFT_RATIO)
        left.split_column(
            Layout(self._active_panel(active, stats), name="active",
                   ratio=_ACTIVE_RATIO),
            Layout(self._results_panel(results, stats,
                                       max(1, results_h - _PANE_CHROME)),
                   name="results", ratio=_RESULTS_RATIO))

        body = Layout(name="body")
        body.split_row(
            left,
            Layout(self._feed_panel(feed), name="feed", ratio=_FEED_RATIO))

        children = [Layout(self._header(stats), name="header", size=_HEADER_SIZE),
                    body]
        if self._done:
            children.append(Layout(self._footer(), name="footer", size=1))
        layout = Layout()
        layout.split_column(*children)
        return layout

    def _footer(self):
        return Text("run complete   -   press Enter to exit",
                    style=f"bold #0d0b0c on {_LK_OK}", justify="center")

    def _feed_panel(self, feed):
        rows = []
        for ev in feed:
            t = Text(no_wrap=True, overflow="ellipsis")
            t.append(_clock(ev.ts) + " ", style=_LK_FAINT)
            t.append(ev.text, style=_FEED_STYLE.get(ev.source, ""))
            rows.append(t)
        body = Group(*rows) if rows else Text("(idle)", style=_LK_FAINT)
        return Panel(body, title="commands", title_align="left",
                     box=box.ROUNDED, border_style=_LK_OK, padding=(0, 1))

    def _header(self, stats):
        title = Text.assemble(
            (f"{TOOL} ", "bold"),
            (VERSION, _LK_DIM),
            ("   mode ", _LK_DIM), (stats.mode, f"bold {_LK_AMBER}"),
            ("   phase ", _LK_DIM), (stats.phase, "bold"),
            ("   elapsed ", _LK_DIM), (_fmt_elapsed(stats.elapsed), ""))
        title.no_wrap = True
        title.overflow = "ellipsis"

        total = stats.total
        pct = (stats.completed / total * 100.0) if total else 0.0
        bar = ProgressBar(total=max(total, 1), completed=stats.completed, width=34)
        prog = Table.grid(padding=(0, 1))
        prog.add_column(no_wrap=True)
        prog.add_column(no_wrap=True)
        prog.add_row(bar, Text(f"{stats.completed}/{total} hosts  ({pct:0.0f}%)"))

        counts = Text(no_wrap=True, overflow="ellipsis")
        _seg(counts, "live ", str(stats.live), _LK_OK)
        _seg(counts, "  down ", str(stats.down), _LK_FAINT)
        _seg(counts, "  scan ", str(stats.scanning), _LK_INFO)
        _seg(counts, "  atk ", str(stats.attacking), f"bold {_LK_AMBER}")
        _seg(counts, "  pwn ", str(stats.compromised), f"bold {_LK_OK}")
        _seg(counts, "  clean ", str(stats.clean), _LK_FAINT)
        _seg(counts, "  err ", str(stats.errored), f"bold {_LK_CRIT}")
        _seg(counts, "  sess ", str(stats.sessions), _LK_INFO)
        _seg(counts, "  cred ", str(stats.credentials), f"bold {_LK_AMBER}")
        _seg(counts, "  acc ", str(stats.access), f"bold {_LK_ACCENT}")
        _seg(counts, "  cve ", str(stats.cves), _LK_TEXT)
        counts.append("/", style=_LK_DIM)
        counts.append(str(stats.exploit_cves), style=f"bold {_LK_TEXT}")
        _seg(counts, "  wkr ", str(stats.active_workers), _LK_TEXT)

        return Panel(Group(title, prog, counts), box=box.ROUNDED,
                     border_style=_LK_INFO, padding=(0, 1))

    def _active_panel(self, hosts, stats):
        t = Table(box=box.SIMPLE_HEAD, expand=True, pad_edge=False,
                  show_edge=False)
        t.add_column("ip", no_wrap=True, overflow="ellipsis", width=15)
        t.add_column("host", no_wrap=True, overflow="ellipsis", ratio=4)
        t.add_column("state", no_wrap=True, width=15)
        t.add_column("prt", justify="right", width=4)
        t.add_column("cve", justify="right", width=6)
        t.add_column("cnd", justify="right", width=4)
        t.add_column("detail", no_wrap=True, overflow="ellipsis", ratio=6)
        for h in hosts:
            t.add_row(
                h.ip,
                Text(h.hostname or "-", style=_LK_DIM),
                _state_text(h.state),
                str(h.open_ports),
                _cve_cell(h),
                str(len(h.candidates)),
                _detail_cell(h))
        title = (f"active   scan {stats.scanning}   attack {stats.attacking}")
        return Panel(t, title=title, title_align="left", box=box.ROUNDED,
                     border_style=_LK_INFO, padding=(0, 1))

    def _results_panel(self, hosts, stats, max_rows):
        t = Table(box=box.SIMPLE_HEAD, expand=True, pad_edge=False,
                  show_edge=False)
        t.add_column("ip", no_wrap=True, overflow="ellipsis", width=15)
        t.add_column("host", no_wrap=True, overflow="ellipsis", ratio=3)
        t.add_column("state", no_wrap=True, width=13)
        t.add_column("kind", no_wrap=True, width=9)
        t.add_column("module", no_wrap=True, overflow="ellipsis", ratio=6)
        t.add_column("session", no_wrap=True, overflow="ellipsis", ratio=4)
        rows = 0
        for h in hosts:
            if rows >= max_rows:
                break
            # One row per session, then one row per credential that did not open a
            # session (session-bearing creds already show as their session row).
            entries = []
            for s in h.sessions:
                entries.append((
                    Text("session", style=f"bold {_LK_OK}"),
                    s.module or "-",
                    Text(f"{s.session_id} {s.payload}".strip(), style=f"bold {_LK_OK}")))
            for a in h.access:
                entries.append((
                    Text("access", style=f"bold {_LK_ACCENT}"),
                    a.module or "-",
                    Text(a.proof or "-", style=_LK_ACCENT)))
            for c in h.credentials:
                if c.session_id:
                    continue
                entries.append((
                    Text("cred", style=f"bold {_LK_AMBER}"),
                    c.module or "-",
                    Text(f"{c.username}:{c.password or '(blank)'}", style=_LK_INFO)))
            if entries:
                # ip/host/state repeat on every row so each session or credential
                # is self-contained, even when several land on the same host.
                for kind, module, last in entries:
                    if rows >= max_rows:
                        break
                    t.add_row(
                        h.ip,
                        Text(h.hostname or "-", style=_LK_DIM),
                        _state_text(h.state),
                        kind, module, last)
                    rows += 1
            else:
                t.add_row(
                    h.ip, Text(h.hostname or "-", style=_LK_DIM),
                    _state_text(h.state), Text("-", style=_LK_DIM), "-",
                    _session_cell(h))
                rows += 1
        title = (f"results   pwn {stats.compromised}   sessions {stats.sessions}"
                 f"   creds {stats.credentials}   access {stats.access}")
        return Panel(t, title=title, title_align="left", box=box.ROUNDED,
                     border_style=_LK_ACCENT, padding=(0, 1))

    # -- teardown summary (printed to the restored screen) --

    def _print_final_summary(self):
        try:
            stats = self.run.stats()
        except Exception:
            return
        head = Text.assemble(
            ("run complete   ", "bold"),
            (f"{_fmt_elapsed(stats.elapsed)}   ", ""),
            (f"{stats.live} live", _LK_OK), ("   ", ""),
            (f"{stats.compromised} compromised", f"bold {_LK_OK}"), ("   ", ""),
            (f"{stats.sessions} session(s)", _LK_INFO), ("   ", ""),
            (f"{stats.access} access", f"bold {_LK_ACCENT}"), ("   ", ""),
            (f"{stats.credentials} credential(s)", f"bold {_LK_AMBER}"))
        self.console.print(head)

        # Sessions across every host, so brute-opened shells on hosts that were
        # not exploited are listed too, not just the exploited ones.
        with_sessions = [h for h in self.run.snapshot_hosts() if h.sessions]
        if with_sessions:
            t = Table(box=box.SIMPLE_HEAD, title="sessions", title_justify="left")
            t.add_column("ip", no_wrap=True)
            t.add_column("host", overflow="ellipsis")
            t.add_column("module", overflow="ellipsis")
            t.add_column("session")
            t.add_column("payload", overflow="ellipsis")
            for h in with_sessions:
                for s in h.sessions:
                    t.add_row(h.ip, h.hostname or "-", s.module or "-",
                              str(s.session_id), s.payload or "-")
            self.console.print(t)

        with_creds = [h for h in self.run.snapshot_hosts() if h.credentials]
        if with_creds:
            t = Table(box=box.SIMPLE_HEAD, title="credentials",
                      title_justify="left")
            t.add_column("ip", no_wrap=True)
            t.add_column("host", overflow="ellipsis")
            t.add_column("service")
            t.add_column("port", no_wrap=True)
            t.add_column("username", overflow="ellipsis")
            t.add_column("password", overflow="ellipsis")
            t.add_column("session")
            for h in with_creds:
                for c in h.credentials:
                    t.add_row(h.ip, h.hostname or "-", c.service or "-",
                              str(c.port or "-"), c.username,
                              c.password or "(blank)", c.session_id or "-")
            self.console.print(t)


# --- cell + format helpers -------------------------------------------------

def _seg(text, label, value, value_style):
    text.append(label, style=_LK_DIM)
    text.append(value, style=value_style)


def _state_text(state):
    return Text(state.value, style=_STATE_STYLE.get(state, ""))


def _verdict_text(verdict):
    return Text(verdict.value, style=_VERDICT_STYLE.get(verdict, ""))


def _cve_cell(host):
    total = host.cve_count
    exploit = host.exploit_cve_count
    style = f"bold {_LK_TEXT}" if exploit else (_LK_TEXT if total else _LK_DIM)
    return Text(f"{total}/{exploit}", style=style)


def _detail_cell(host):
    if host.state == HostState.ERROR and host.error:
        return Text(host.error, style=_LK_CRIT)
    best = _best_candidate(host)
    if best is not None and host.state == HostState.ATTACKING:
        txt = Text(f"{_module_leaf(best.module)} ")
        txt.append(best.fire_status or "attacking", style=_LK_AMBER)
        return txt
    if host.notes:
        return Text(host.notes, style=_LK_DIM)
    return Text("")


def _session_cell(host):
    if not host.sessions:
        return Text("-", style=_LK_DIM)
    parts = [f"{s.session_id} {s.payload}".strip() for s in host.sessions]
    return Text(", ".join(parts), style=f"bold {_LK_OK}")


def _best_candidate(host):
    if not host.candidates:
        return None
    fired = [c for c in host.candidates if c.fire_status]
    pool = fired or host.candidates
    return max(pool, key=lambda c: 1 if c.source == "msf" else 0)


def _module_leaf(module):
    return module.rsplit("/", 1)[-1] if module else ""


def _split_heights(body_rows):
    denom = _ACTIVE_RATIO + _RESULTS_RATIO
    if body_rows <= 0 or denom <= 0:
        return 0, 0
    active_h = body_rows * _ACTIVE_RATIO // denom
    return active_h, body_rows - active_h


def _fmt_elapsed(seconds):
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{sec:02d}"


def _clock(ts):
    lt = time.localtime(ts)
    return f"{lt.tm_hour:02d}:{lt.tm_min:02d}:{lt.tm_sec:02d}"


__all__ = ["Dashboard"]
