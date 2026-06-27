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
# border rows. The body below splits between the two panes on this ratio.
_HEADER_SIZE = 5
_ACTIVE_RATIO = 3
_RESULTS_RATIO = 2

# Rows lost per pane to the panel border (2) and the table header (1).
_PANE_CHROME = 3

_STATE_STYLE = {
    HostState.QUEUED: "dim",
    HostState.DISCOVERED: "cyan",
    HostState.DOWN: "grey42",
    HostState.SCANNING: "blue",
    HostState.ANALYZED: "blue",
    HostState.CANDIDATES: "yellow",
    HostState.NO_CANDIDATES: "grey42",
    HostState.CHECKING: "yellow",
    HostState.EXPLOITABLE: "bold magenta",
    HostState.NOT_EXPLOITABLE: "grey42",
    HostState.EXPLOITING: "bold yellow",
    HostState.EXPLOITED: "bold green",
    HostState.FAILED: "red",
    HostState.ERROR: "bold red",
}

_VERDICT_STYLE = {
    Verdict.VULNERABLE: "bold red",
    Verdict.LIKELY: "yellow",
    Verdict.SAFE: "green",
    Verdict.UNSUPPORTED: "grey42",
    Verdict.UNKNOWN: "grey42",
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

    # -- lifecycle (main thread only) --

    def start(self):
        if not self.console.is_terminal:
            raise RuntimeError("stdout is not a terminal; use --no-tui")
        self._live = Live(
            self._render(),
            console=self.console,
            screen=True,
            auto_refresh=False)
        self._live.start(refresh=True)

    def refresh(self):
        if self._live is None:
            return
        self._live.update(self._render(), refresh=True)

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
        body_rows = self.console.size.height - _HEADER_SIZE
        active_h, results_h = _split_heights(body_rows)
        active = self.run.active_hosts(limit=max(1, active_h - _PANE_CHROME))
        results = self.run.result_hosts(limit=max(1, results_h - _PANE_CHROME))

        layout = Layout()
        layout.split_column(
            Layout(self._header(stats), name="header", size=_HEADER_SIZE),
            Layout(self._active_panel(active, stats), name="active",
                   ratio=_ACTIVE_RATIO),
            Layout(self._results_panel(results, stats), name="results",
                   ratio=_RESULTS_RATIO))
        return layout

    def _header(self, stats):
        title = Text.assemble(
            (f"{TOOL} ", "bold"),
            (VERSION, "dim"),
            ("   mode ", "dim"), (stats.mode, "bold cyan"),
            ("   phase ", "dim"), (stats.phase, "bold"),
            ("   elapsed ", "dim"), (_fmt_elapsed(stats.elapsed), ""))
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
        _seg(counts, "live ", str(stats.live), "green")
        _seg(counts, "  down ", str(stats.down), "grey42")
        _seg(counts, "  scan ", str(stats.scanning), "blue")
        _seg(counts, "  cand ", str(stats.candidates), "yellow")
        _seg(counts, "  chk ", str(stats.checking), "yellow")
        _seg(counts, "  vuln ", str(stats.exploitable), "magenta")
        _seg(counts, "  fire ", str(stats.exploiting), "bold yellow")
        _seg(counts, "  pwn ", str(stats.exploited), "bold green")
        _seg(counts, "  fail ", str(stats.failed), "red")
        _seg(counts, "  err ", str(stats.errored), "bold red")
        _seg(counts, "  sess ", str(stats.sessions), "cyan")
        _seg(counts, "  cve ", str(stats.cves), "white")
        counts.append("/", style="dim")
        counts.append(str(stats.exploit_cves), style="bold white")
        _seg(counts, "  wkr ", str(stats.active_workers), "white")

        return Panel(Group(title, prog, counts), box=box.ROUNDED,
                     border_style="blue", padding=(0, 1))

    def _active_panel(self, hosts, stats):
        t = Table(box=box.SIMPLE_HEAD, expand=True, pad_edge=False,
                  show_edge=False)
        t.add_column("ip", no_wrap=True, overflow="ellipsis", ratio=3,
                     min_width=12)
        t.add_column("host", no_wrap=True, overflow="ellipsis", ratio=4)
        t.add_column("state", no_wrap=True, width=15)
        t.add_column("prt", justify="right", width=4)
        t.add_column("cve", justify="right", width=6)
        t.add_column("cnd", justify="right", width=4)
        t.add_column("detail", no_wrap=True, overflow="ellipsis", ratio=6)
        for h in hosts:
            t.add_row(
                h.ip,
                Text(h.hostname or "-", style="dim"),
                _state_text(h.state),
                str(h.open_ports),
                _cve_cell(h),
                str(len(h.candidates)),
                _detail_cell(h))
        title = (f"active   scan {stats.scanning}   check {stats.checking}"
                 f"   fire {stats.exploiting}")
        return Panel(t, title=title, title_align="left", box=box.ROUNDED,
                     border_style="cyan", padding=(0, 1))

    def _results_panel(self, hosts, stats):
        t = Table(box=box.SIMPLE_HEAD, expand=True, pad_edge=False,
                  show_edge=False)
        t.add_column("ip", no_wrap=True, overflow="ellipsis", ratio=3,
                     min_width=12)
        t.add_column("host", no_wrap=True, overflow="ellipsis", ratio=3)
        t.add_column("state", no_wrap=True, width=13)
        t.add_column("verdict", no_wrap=True, width=11)
        t.add_column("module", no_wrap=True, overflow="ellipsis", ratio=6)
        t.add_column("session", no_wrap=True, overflow="ellipsis", ratio=4)
        for h in hosts:
            best = _best_candidate(h)
            verdict = best.check_result if best else Verdict.UNKNOWN
            module = best.module if best else "-"
            t.add_row(
                h.ip,
                Text(h.hostname or "-", style="dim"),
                _state_text(h.state),
                _verdict_text(verdict),
                module,
                _session_cell(h))
        title = (f"results   vuln {stats.exploitable}   pwn {stats.exploited}"
                 f"   sessions {stats.sessions}")
        return Panel(t, title=title, title_align="left", box=box.ROUNDED,
                     border_style="magenta", padding=(0, 1))

    # -- teardown summary (printed to the restored screen) --

    def _print_final_summary(self):
        try:
            stats = self.run.stats()
        except Exception:
            return
        head = Text.assemble(
            ("run complete   ", "bold"),
            (f"{_fmt_elapsed(stats.elapsed)}   ", ""),
            (f"{stats.live} live", "green"), ("   ", ""),
            (f"{stats.exploitable} exploitable", "magenta"), ("   ", ""),
            (f"{stats.exploited} exploited", "bold green"), ("   ", ""),
            (f"{stats.sessions} session(s)", "cyan"))
        self.console.print(head)

        exploited = [h for h in self.run.result_hosts()
                     if h.state == HostState.EXPLOITED and h.sessions]
        if not exploited:
            return
        t = Table(box=box.SIMPLE_HEAD, title="sessions", title_justify="left")
        t.add_column("ip", no_wrap=True)
        t.add_column("host", overflow="ellipsis")
        t.add_column("module", overflow="ellipsis")
        t.add_column("session")
        t.add_column("payload", overflow="ellipsis")
        for h in exploited:
            for s in h.sessions:
                t.add_row(h.ip, h.hostname or "-", s.module or "-",
                          str(s.session_id), s.payload or "-")
        self.console.print(t)


# --- cell + format helpers -------------------------------------------------

def _seg(text, label, value, value_style):
    text.append(label, style="dim")
    text.append(value, style=value_style)


def _state_text(state):
    return Text(state.value, style=_STATE_STYLE.get(state, ""))


def _verdict_text(verdict):
    return Text(verdict.value, style=_VERDICT_STYLE.get(verdict, ""))


def _cve_cell(host):
    total = host.cve_count
    exploit = host.exploit_cve_count
    style = "bold white" if exploit else ("white" if total else "dim")
    return Text(f"{total}/{exploit}", style=style)


def _detail_cell(host):
    if host.state == HostState.ERROR and host.error:
        return Text(host.error, style="red")
    best = _best_candidate(host)
    live = (HostState.CANDIDATES, HostState.CHECKING, HostState.EXPLOITING)
    if best is not None and host.state in live:
        txt = Text(f"{_module_leaf(best.module)} ")
        txt.append(best.check_result.value,
                   style=_VERDICT_STYLE.get(best.check_result, ""))
        return txt
    if host.notes:
        return Text(host.notes, style="dim")
    return Text("")


def _session_cell(host):
    if not host.sessions:
        return Text("-", style="dim")
    parts = [f"{s.session_id} {s.payload}".strip() for s in host.sessions]
    return Text(", ".join(parts), style="bold green")


def _best_candidate(host):
    if not host.candidates:
        return None
    return max(host.candidates,
               key=lambda c: (_VERDICT_RANK.get(c.check_result, 0),
                              1 if c.source == "msf" else 0))


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


__all__ = ["Dashboard"]
