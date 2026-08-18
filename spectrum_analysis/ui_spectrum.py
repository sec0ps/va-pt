#!/usr/bin/env python3
# =============================================================================
# Location: ui_spectrum.py
#
# Author: Keith Pachulski
# Company: Red Cell Security LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
#
# License: MIT License
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation
#   the rights to use, copy, modify, merge, publish, distribute, sublicense,
#   and/or sell copies of the Software, and to permit persons to whom the
#   Software is furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#   DEALINGS IN THE SOFTWARE.
#
# Purpose:
#   Spectrum trace and waterfall display built on pyqtgraph, plus the composite
#   model that stitches per segment frames into one continuous display surface.
#
#   The display axis is a composite across the enabled bands rather than a linear
#   frequency axis. A band plan is deliberately non contiguous, so a linear axis
#   would spend nearly all of its width drawing empty spectrum between widely
#   separated bands. Each band is allotted screen width proportional to its own
#   span, separators are drawn at the joins, and the axis ticks are labelled in
#   true frequency. Every position on screen maps back to a real frequency
#   through the segment table, so the hover readout and any saved marker carry
#   actual Hz and never a screen coordinate.
#
#   The waterfall advances one row per completed sweep rather than one row per
#   segment visit. A row is a picture of the whole selected spectrum at one
#   moment, which is what an operator reads. Pushing a row per segment visit
#   would produce a waterfall that alternates between disjoint bands on
#   successive rows and is unreadable.
#
#   The waterfall buffer is a double height ring. Rows are written twice, once at
#   the write index and once one buffer height later, so the visible window is a
#   plain slice view rather than a scroll copy. This removes a full buffer memcpy
#   from every display update.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. This module renders energy
#   measurements only. It does not demodulate, decode, or display the content of
#   any transmission.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. Displayed levels
#   are dBFS relative to converter full scale and are not calibrated to absolute
#   power. Levels are comparable within a band and are not comparable across
#   bands where the antenna differs. The author and Red Cell Security LLC accept
#   no liability for any use of this software, whether authorized or otherwise.
# =============================================================================

"""Sweep composite model, spectrum trace, and waterfall display widgets."""

from typing import Dict, List, Optional, Tuple

import numpy as np
import pyqtgraph as pg
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QVBoxLayout, QWidget

# Row major so that display arrays are indexed as (row, column), matching the
# way the waterfall buffer is built and sliced.
pg.setConfigOptions(imageAxisOrder="row-major", antialias=False)

# Display level window in dBFS. Values outside are clipped. The floor is set well
# below the noise floor of an 8 bit converter at any usable gain setting so that
# real signals are never clipped at the bottom of the colour scale.
DISPLAY_DB_FLOOR = -130.0
DISPLAY_DB_CEIL = 0.0

# Waterfall history depth in rows, and total display columns across all bands.
DEFAULT_HISTORY_ROWS = 400
DEFAULT_DISPLAY_COLS = 1400

# Minimum columns any one band is allotted, so that a narrow band such as PMR446
# at 200 kHz beside a wide band is still wide enough to be readable.
MIN_BAND_COLS = 24

# Peak hold decay per completed sweep, in dB. A pure maximum hold saturates the
# display within a minute of sweeping and stops conveying anything. A slow decay
# keeps recent peaks visible while letting the trace forget stale ones.
PEAK_DECAY_DB = 0.35


class SweepComposite:
    """Maps per segment frames onto one continuous display surface.

    Owns the mapping in both directions. Segment frames are written into the
    composite by column range, and any composite column can be resolved back to a
    true frequency, which is what makes the hover readout and click to mark
    correct across a non contiguous band plan.
    """

    def __init__(self, segments: List, total_cols: int = DEFAULT_DISPLAY_COLS):
        self.segments = list(segments)
        self.total_cols = int(total_cols)

        # Per segment display allocation, as (segment, col_start, col_end).
        self.spans: List[Tuple[object, int, int]] = []
        # Column index where each band begins, used to draw separators.
        self.band_edges: List[Tuple[int, str]] = []

        self._build_layout()

        self.current = np.full(self.total_cols, DISPLAY_DB_FLOOR, dtype=np.float32)
        self.peak_hold = np.full(self.total_cols, DISPLAY_DB_FLOOR, dtype=np.float32)
        self.floor = np.full(self.total_cols, DISPLAY_DB_FLOOR, dtype=np.float32)
        # Tracks which segments have been written since the last sweep boundary,
        # so that a row is emitted only when the whole span has been refreshed.
        self._written = set()

    def _build_layout(self) -> None:
        """Allocate display columns to segments proportionally to their span."""
        if not self.segments:
            return

        widths = [max(1, seg.usable_stop_hz - seg.usable_start_hz) for seg in self.segments]
        total_width = float(sum(widths))

        # Proportional allocation with a floor. The floor is applied first and the
        # remainder distributed proportionally, so a narrow band stays legible
        # without a wide band being starved.
        raw = [max(MIN_BAND_COLS, int(self.total_cols * w / total_width)) for w in widths]
        scale = self.total_cols / float(sum(raw))
        cols = [max(MIN_BAND_COLS, int(round(c * scale))) for c in raw]

        # Absorb any rounding residue into the widest allocation.
        residue = self.total_cols - sum(cols)
        if residue != 0:
            widest = int(np.argmax(cols))
            cols[widest] += residue

        cursor = 0
        last_band = None
        for seg, width in zip(self.segments, cols):
            self.spans.append((seg, cursor, cursor + width))
            if seg.band_name != last_band:
                self.band_edges.append((cursor, seg.band_name))
                last_band = seg.band_name
            cursor += width

    def col_to_hz(self, col: float) -> Optional[float]:
        """Resolve a composite column to a true frequency.

        Interpolation is linear inside the owning segment. Returns None outside
        the composite so the caller can suppress a readout rather than display a
        fabricated frequency.
        """
        if not self.spans:
            return None
        col = float(col)
        for seg, start, end in self.spans:
            if start <= col < end:
                fraction = (col - start) / float(end - start)
                span_hz = seg.usable_stop_hz - seg.usable_start_hz
                return seg.usable_start_hz + fraction * span_hz
        if col < self.spans[0][1]:
            return float(self.spans[0][0].usable_start_hz)
        return float(self.spans[-1][0].usable_stop_hz)

    def hz_to_col(self, hz: float) -> Optional[float]:
        """Resolve a true frequency to a composite column, or None if not shown."""
        for seg, start, end in self.spans:
            if seg.usable_start_hz <= hz <= seg.usable_stop_hz:
                span_hz = float(seg.usable_stop_hz - seg.usable_start_hz)
                fraction = (hz - seg.usable_start_hz) / span_hz
                return start + fraction * (end - start)
        return None

    def segment_at_col(self, col: float) -> Optional[object]:
        """Return the segment owning a composite column, for the readout."""
        for seg, start, end in self.spans:
            if start <= col < end:
                return seg
        return None

    def ingest(self, frame, floor_dbfs: Optional[np.ndarray] = None) -> bool:
        """Write one segment frame into the composite.

        Returns True when this frame completes a full pass over every segment,
        which is the signal to advance the waterfall by one row.
        """
        span = None
        for seg, start, end in self.spans:
            if seg.segment_id == frame.segment_id:
                span = (start, end)
                break
        if span is None:
            return False

        start, end = span
        width = end - start
        self.current[start:end] = self._resample(frame.power_dbfs, width)

        if floor_dbfs is not None and floor_dbfs.size == frame.power_dbfs.size:
            self.floor[start:end] = self._resample(floor_dbfs, width, use_max=False)

        # Peak hold decays every update rather than only on sweep completion, so
        # the decay rate is independent of how many segments are in the plan.
        self.peak_hold[start:end] -= PEAK_DECAY_DB
        np.maximum(self.peak_hold[start:end], self.current[start:end],
                   out=self.peak_hold[start:end])

        self._written.add(frame.segment_id)
        if len(self._written) >= len(self.spans):
            self._written.clear()
            return True
        return False

    @staticmethod
    def _resample(source: np.ndarray, width: int, use_max: bool = True) -> np.ndarray:
        """Resize a full resolution array to a display column count.

        Downsampling takes a maximum over each group rather than a mean. A mean
        averages an occupied bin against its unoccupied neighbours and attenuates
        a narrow carrier by the reduction ratio, which hides exactly the signals
        this display exists to reveal. The floor overlay is the one exception and
        uses interpolation, since a maximum of the floor would overstate it.
        """
        n = int(source.size)
        if n == width:
            return source.astype(np.float32)

        if n > width and use_max:
            group = n // width
            trimmed = group * width
            reduced = source[:trimmed].reshape(width, group).max(axis=1)
            if trimmed < n:
                reduced[-1] = max(float(reduced[-1]), float(source[trimmed:].max()))
            return reduced.astype(np.float32)

        # Upsampling, or downsampling the floor overlay.
        return np.interp(
            np.linspace(0.0, n - 1.0, width),
            np.arange(n, dtype=np.float64),
            source.astype(np.float64),
        ).astype(np.float32)

    def reset(self) -> None:
        """Clear traces without rebuilding layout. Used on a gain change."""
        self.current[:] = DISPLAY_DB_FLOOR
        self.peak_hold[:] = DISPLAY_DB_FLOOR
        self.floor[:] = DISPLAY_DB_FLOOR
        self._written.clear()


class FrequencyAxis(pg.AxisItem):
    """Axis that labels composite columns with the true frequency they represent."""

    def __init__(self, composite: Optional[SweepComposite] = None, **kwargs):
        super().__init__(**kwargs)
        self.composite = composite

    def tickStrings(self, values, scale, spacing):
        if self.composite is None:
            return ["" for _ in values]
        labels = []
        for value in values:
            hz = self.composite.col_to_hz(value)
            if hz is None:
                labels.append("")
            elif hz >= 1e9:
                labels.append("{0:.4f}G".format(hz / 1e9))
            else:
                labels.append("{0:.3f}".format(hz / 1e6))
        return labels


class SpectrumDisplay(QWidget):
    """Linked spectrum trace and waterfall with hover readout and click to mark.

    Emits hover_changed on every pointer move over either panel, carrying the
    resolved frequency and level, and emits marker_requested on a click so the
    main window can bind the click to a detected event.
    """

    hover_changed = Signal(dict)
    marker_requested = Signal(float)

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.composite: Optional[SweepComposite] = None
        self.history_rows = DEFAULT_HISTORY_ROWS

        # Double height ring buffer. Every row is written at both idx and
        # idx + history_rows so that the visible window is a contiguous slice
        # view, avoiding a full buffer copy on each advance.
        self._waterfall = None
        self._write_row = 0

        self._event_markers: List[pg.LinearRegionItem] = []
        self._saved_markers: List[pg.InfiniteLine] = []
        self._band_separators: List[pg.InfiniteLine] = []

        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.graphics = pg.GraphicsLayoutWidget()
        self.graphics.setBackground("#0d0f12")
        layout.addWidget(self.graphics)

        mono = QFont("Monospace", 9)
        mono.setStyleHint(QFont.TypeWriter)

        self.trace_axis = FrequencyAxis(orientation="bottom")
        self.trace_plot = self.graphics.addPlot(row=0, col=0, axisItems={"bottom": self.trace_axis})
        self.trace_plot.setLabel("left", "dBFS")
        self.trace_plot.showGrid(x=True, y=True, alpha=0.18)
        self.trace_plot.setMouseEnabled(x=True, y=False)
        self.trace_plot.setYRange(DISPLAY_DB_FLOOR, DISPLAY_DB_CEIL, padding=0.0)
        self.trace_plot.setMenuEnabled(False)

        self.peak_curve = self.trace_plot.plot(pen=pg.mkPen("#3a5f8a", width=1))
        self.floor_curve = self.trace_plot.plot(
            pen=pg.mkPen("#8a5a2a", width=1, style=Qt.DashLine)
        )
        self.threshold_curve = self.trace_plot.plot(
            pen=pg.mkPen("#a03030", width=1, style=Qt.DotLine)
        )
        self.trace_curve = self.trace_plot.plot(pen=pg.mkPen("#4ec9b0", width=1))

        self.waterfall_axis = FrequencyAxis(orientation="bottom")
        self.waterfall_plot = self.graphics.addPlot(
            row=1, col=0, axisItems={"bottom": self.waterfall_axis}
        )
        self.waterfall_plot.setLabel("left", "history")
        self.waterfall_plot.setMouseEnabled(x=True, y=False)
        self.waterfall_plot.setMenuEnabled(False)
        self.waterfall_plot.hideAxis("left")

        self.waterfall_image = pg.ImageItem()
        self.waterfall_plot.addItem(self.waterfall_image)
        colormap = pg.colormap.get("inferno")
        self.waterfall_image.setLookupTable(colormap.getLookupTable(0.0, 1.0, 256))
        self.waterfall_image.setLevels([0, 255])

        # X axes are linked so that panning or zooming either panel moves both,
        # and so a feature in the waterfall always sits directly under the same
        # feature in the trace.
        self.waterfall_plot.setXLink(self.trace_plot)

        self.graphics.ci.layout.setRowStretchFactor(0, 2)
        self.graphics.ci.layout.setRowStretchFactor(1, 3)

        self.cursor_line = pg.InfiniteLine(angle=90, movable=False,
                                           pen=pg.mkPen("#ffffff", width=1, style=Qt.DashLine))
        self.cursor_line.setZValue(100)
        self.trace_plot.addItem(self.cursor_line, ignoreBounds=True)
        self.cursor_line_wf = pg.InfiniteLine(angle=90, movable=False,
                                              pen=pg.mkPen("#ffffff", width=1, style=Qt.DashLine))
        self.cursor_line_wf.setZValue(100)
        self.waterfall_plot.addItem(self.cursor_line_wf, ignoreBounds=True)

        self.graphics.scene().sigMouseMoved.connect(self._on_mouse_moved)
        self.graphics.scene().sigMouseClicked.connect(self._on_mouse_clicked)

    def set_plan(self, segments: List, history_rows: int = DEFAULT_HISTORY_ROWS) -> None:
        """Rebuild the composite and the waterfall for a new band plan."""
        self.composite = SweepComposite(segments)
        self.history_rows = int(history_rows)
        self.trace_axis.composite = self.composite
        self.waterfall_axis.composite = self.composite

        cols = self.composite.total_cols
        self._waterfall = np.zeros((self.history_rows * 2, cols), dtype=np.uint8)
        self._write_row = 0

        self.trace_plot.setXRange(0, cols, padding=0.0)
        self.waterfall_image.setRect(0, 0, cols, self.history_rows)
        self.waterfall_plot.setYRange(0, self.history_rows, padding=0.0)

        self._clear_items(self._band_separators, self.trace_plot)
        self._band_separators = []
        for col, name in self.composite.band_edges:
            if col == 0:
                continue
            for plot in (self.trace_plot, self.waterfall_plot):
                line = pg.InfiniteLine(
                    pos=col, angle=90, movable=False,
                    pen=pg.mkPen("#4a4a55", width=1, style=Qt.DashDotLine),
                )
                line.setZValue(50)
                plot.addItem(line, ignoreBounds=True)
                self._band_separators.append(line)

        self.clear_event_markers()

    def ingest(self, frame, floor_dbfs: Optional[np.ndarray] = None) -> None:
        """Fold one segment frame into the display, advancing on sweep completion."""
        if self.composite is None:
            return
        completed = self.composite.ingest(frame, floor_dbfs)
        if completed:
            self._advance_waterfall()

    def _advance_waterfall(self) -> None:
        """Write the current composite as a new waterfall row."""
        if self._waterfall is None:
            return
        span = DISPLAY_DB_CEIL - DISPLAY_DB_FLOOR
        clipped = np.clip(self.composite.current, DISPLAY_DB_FLOOR, DISPLAY_DB_CEIL)
        row = ((clipped - DISPLAY_DB_FLOOR) * (255.0 / span)).astype(np.uint8)

        self._waterfall[self._write_row] = row
        self._waterfall[self._write_row + self.history_rows] = row
        self._write_row = (self._write_row + 1) % self.history_rows

    def redraw(self, threshold_offset_db: float = 6.0) -> None:
        """Repaint traces and waterfall. Called on a display timer, not per frame.

        Decoupling repaint from frame arrival is what keeps the UI responsive. The
        sweeper produces frames far faster than a display needs to update, and
        repainting on every frame would spend the whole budget in the renderer for
        no visible benefit.
        """
        if self.composite is None or self._waterfall is None:
            return

        x = np.arange(self.composite.total_cols, dtype=np.float32)
        self.trace_curve.setData(x, self.composite.current)
        self.peak_curve.setData(x, self.composite.peak_hold)
        self.floor_curve.setData(x, self.composite.floor)
        self.threshold_curve.setData(x, self.composite.floor + threshold_offset_db)

        # Slice view into the ring, newest row at the top of the visible window.
        start = self._write_row
        view = self._waterfall[start:start + self.history_rows]
        self.waterfall_image.setImage(view[::-1], autoLevels=False, levels=[0, 255])

    def show_events(self, events: List[Dict]) -> None:
        """Draw a shaded region over each active detection on the trace."""
        if self.composite is None:
            return
        self.clear_event_markers()

        colours = {
            "new": (80, 200, 120, 55),
            "intermittent": (200, 170, 60, 45),
            "persistent": (110, 110, 130, 30),
            "unknown": (120, 160, 200, 40),
        }

        for event in events:
            low = self.composite.hz_to_col(event["center_hz"] - event["occupied_bw_hz"] / 2.0)
            high = self.composite.hz_to_col(event["center_hz"] + event["occupied_bw_hz"] / 2.0)
            if low is None or high is None:
                continue
            # Guarantee a minimum visible width so a narrow carrier is not drawn
            # as a zero width region that the operator cannot see or click.
            if high - low < 2.0:
                centre = (low + high) / 2.0
                low, high = centre - 1.0, centre + 1.0
            region = pg.LinearRegionItem(
                values=(low, high),
                brush=pg.mkBrush(*colours.get(event.get("classification", "unknown"))),
                movable=False,
            )
            region.setZValue(-10)
            self.trace_plot.addItem(region)
            self._event_markers.append(region)

    def show_saved_markers(self, markers: List[Dict]) -> None:
        """Draw a labelled vertical line for each saved marker on both panels."""
        if self.composite is None:
            return
        self._clear_items(self._saved_markers, None)
        self._saved_markers = []

        for marker in markers:
            col = self.composite.hz_to_col(marker["center_hz"])
            if col is None:
                continue
            for plot, with_label in ((self.trace_plot, True), (self.waterfall_plot, False)):
                line = pg.InfiniteLine(
                    pos=col, angle=90, movable=False,
                    pen=pg.mkPen("#e05c5c", width=1),
                    label=marker["label"] if with_label else None,
                    labelOpts={"position": 0.92, "color": "#e05c5c", "movable": False},
                )
                line.setZValue(60)
                plot.addItem(line, ignoreBounds=True)
                self._saved_markers.append(line)

    def clear_event_markers(self) -> None:
        """Remove all detection regions from the trace."""
        for region in self._event_markers:
            self.trace_plot.removeItem(region)
        self._event_markers = []

    @staticmethod
    def _clear_items(items: List, plot) -> None:
        """Remove items from whichever plot currently owns them."""
        for item in items:
            scene = item.scene()
            if scene is not None:
                for view in scene.views():
                    pass
            if item.parentItem() is not None or scene is not None:
                try:
                    item.getViewBox().removeItem(item)
                except Exception:
                    pass

    def _resolve_pointer(self, scene_pos) -> Optional[dict]:
        """Convert a scene position into frequency, level, and segment context."""
        if self.composite is None:
            return None

        for plot in (self.trace_plot, self.waterfall_plot):
            if not plot.sceneBoundingRect().contains(scene_pos):
                continue
            point = plot.vb.mapSceneToView(scene_pos)
            col = float(point.x())
            if col < 0 or col >= self.composite.total_cols:
                return None

            hz = self.composite.col_to_hz(col)
            if hz is None:
                return None
            segment = self.composite.segment_at_col(col)
            index = int(min(max(col, 0), self.composite.total_cols - 1))

            return {
                "hz": hz,
                "col": col,
                "level_dbfs": float(self.composite.current[index]),
                "peak_dbfs": float(self.composite.peak_hold[index]),
                "floor_dbfs": float(self.composite.floor[index]),
                "band_name": segment.band_name if segment is not None else "",
                "segment_id": segment.segment_id if segment is not None else -1,
                "rbw_hz": segment.rbw_hz if segment is not None else 0.0,
            }
        return None

    def _on_mouse_moved(self, scene_pos) -> None:
        info = self._resolve_pointer(scene_pos)
        if info is None:
            return
        self.cursor_line.setPos(info["col"])
        self.cursor_line_wf.setPos(info["col"])
        self.hover_changed.emit(info)

    def _on_mouse_clicked(self, event) -> None:
        if event.button() != Qt.LeftButton:
            return
        info = self._resolve_pointer(event.scenePos())
        if info is None:
            return
        self.marker_requested.emit(info["hz"])
