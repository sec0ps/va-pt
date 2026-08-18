#!/usr/bin/env python3
# =============================================================================
# Location: ui_main.py
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
#   Main application window. Hosts the spectrum display, the band plan and gain
#   controls, the live event list, and the saved marker list, and owns the worker
#   thread that turns capture blocks into spectrum frames and burst events.
#
#   Threading model. The sweep engine owns the radio on its own plain thread and
#   publishes capture blocks to a bounded queue. A worker object living in a
#   QThread drains that queue, runs the PSD estimate and the burst detector, and
#   publishes results as Qt signals. Qt delivers cross thread signals through the
#   receiving thread's event loop, so the GUI thread touches widgets and nothing
#   else touches them. No Qt object is created on or accessed from the sweep
#   thread.
#
#   Display repaint is driven by a timer rather than by frame arrival. The sweeper
#   produces frames an order of magnitude faster than a display needs to update,
#   and repainting per frame would spend the entire budget in the renderer for no
#   visible gain. Detection is unaffected, since it runs in the worker on every
#   frame regardless of what the display is doing.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. The interface presents energy
#   detection results only. It provides no demodulation, decoding, or recovery of
#   communications content. Operators remain responsible for confirming that the
#   frequencies swept fall within the authorized scope for the engagement and
#   jurisdiction.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. Displayed and
#   recorded levels are dBFS relative to converter full scale and are not
#   calibrated to absolute power. The author and Red Cell Security LLC accept no
#   liability for any use of this software, whether authorized or otherwise.
# =============================================================================

"""Main window, processing worker thread, and operator controls."""

import queue
import time
from typing import Dict, List, Optional

import numpy as np
from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDockWidget,
    QFormLayout, QFrame, QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSlider,
    QSizePolicy, QSpinBox, QStatusBar, QTableWidget, QTableWidgetItem, QTabWidget,
    QVBoxLayout, QWidget,
)

import band_plan
import calibrate
from burst_detect import BurstDetector
from dsp_psd import PSDEstimator
from sdr_capture import GainProfile
from store import Store
from ui_spectrum import DEFAULT_PEAK_DECAY_DB, SpectrumDisplay

# Display repaint interval. Roughly 20 frames per second, which is above the rate
# at which a waterfall reads as continuous and well below the rate at which the
# renderer starts competing with the detector for CPU.
REDRAW_INTERVAL_MS = 50

# Interval for the health and statistics line.
STATS_INTERVAL_MS = 500

# Maximum rows retained in the live event table. Old rows are discarded from the
# bottom, since an unbounded table is the easiest way to turn a long engagement
# into an out of memory failure.
MAX_EVENT_ROWS = 300

# Maximum closed detections retained on the display while hold is enabled. Held
# detections exist so a transient is still there to be clicked and recorded
# minutes after it ended, but a busy band would otherwise accumulate them without
# limit until the trace is unreadable and the process is out of memory. The oldest
# are shed first, so the most recent activity is always what survives.
MAX_HELD_EVENTS = 400

STYLE = """
QMainWindow, QWidget { background: #0d0f12; color: #c8ccd4; }
QGroupBox {
    border: 1px solid #23262e; border-radius: 3px;
    margin-top: 8px; padding-top: 8px; font-weight: bold;
}
QGroupBox::title { subcontrol-origin: margin; left: 8px; color: #7f8796; }
QTableWidget {
    background: #101319; alternate-background-color: #14171e;
    gridline-color: #23262e; border: 1px solid #23262e;
    selection-background-color: #1f3a4d;
}
QHeaderView::section {
    background: #171b22; color: #7f8796;
    border: none; border-right: 1px solid #23262e; padding: 4px;
}
QPushButton {
    background: #1a1e26; border: 1px solid #2c313b;
    border-radius: 3px; padding: 5px 12px;
}
QPushButton:hover { background: #232833; }
QPushButton:pressed { background: #2c313b; }
QComboBox, QLineEdit, QSpinBox, QPlainTextEdit {
    background: #101319; border: 1px solid #2c313b;
    border-radius: 3px; padding: 3px 6px;
}
QDockWidget { titlebar-close-icon: none; }
QScrollArea { border: none; background: #0d0f12; }
QDockWidget::title { background: #171b22; padding: 5px; }
QTabBar::tab {
    background: #171b22; padding: 6px 14px; border: 1px solid #23262e;
}
QTabBar::tab:selected { background: #1f2530; color: #4ec9b0; }
QStatusBar { background: #171b22; border-top: 1px solid #23262e; }
QLabel#readout { font-family: monospace; color: #4ec9b0; }
QLabel#warning { color: #d4a04a; }
"""


class ProcessingWorker(QObject):
    """Drains capture blocks, runs DSP and detection, publishes Qt signals.

    Lives in a QThread. Holds no references to widgets. Everything leaving this
    object goes out as a signal, which Qt marshals onto the GUI thread's event
    loop, so no widget is ever touched from here.
    """

    frame_ready = Signal(object, object)
    events_changed = Signal(dict)
    error = Signal(str)

    def __init__(self, capture_queue: "queue.Queue", detector: BurstDetector):
        super().__init__()
        self._queue = capture_queue
        self._detector = detector
        self._estimators: Dict[int, PSDEstimator] = {}
        self._running = False

    @Slot()
    def run(self) -> None:
        """Main worker loop. Exits when stop is called."""
        self._running = True
        while self._running:
            try:
                block = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                estimator = self._estimators.get(block.segment.fft_size)
                if estimator is None:
                    estimator = PSDEstimator(block.segment.fft_size)
                    self._estimators[block.segment.fft_size] = estimator

                frame = estimator.compute(
                    block.iq, block.segment,
                    overruns=block.overruns, timestamp=block.timestamp,
                )
                result = self._detector.process(frame)
                floor = self._detector.floor_for_segment(frame.segment_id)

                self.frame_ready.emit(frame, floor)
                if result["opened"] or result["closed"]:
                    self.events_changed.emit(result)
            except Exception as exc:
                # A malformed block must not kill the worker, or the display goes
                # dark permanently after one transient fault in the capture path.
                self.error.emit("processing error: {0}".format(exc))

    @Slot()
    def stop(self) -> None:
        self._running = False


class MarkerDialog(QDialog):
    """Prompts for a label and notes when saving a detected signal."""

    def __init__(self, event: Dict, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Save marker")
        self.setMinimumWidth(420)
        self.event = event

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.label_edit = QLineEdit()
        self.label_edit.setText("{0:.4f} MHz".format(event["center_hz"] / 1e6))
        self.label_edit.selectAll()
        form.addRow("Label", self.label_edit)

        # Measured values are shown read only. They come from the detector, not
        # from the click, and are recorded exactly as measured.
        measured = [
            ("Center", "{0:.6f} MHz".format(event["center_hz"] / 1e6)),
            ("Occupied BW", "{0:.2f} kHz".format(event.get("occupied_bw_hz", 0) / 1e3)),
            ("Peak", "{0:.1f} dBFS".format(event.get("peak_dbfs", 0))),
            ("SNR", "{0:.1f} dB".format(event.get("snr_db", 0))),
            ("Duration", "{0:.3f} s".format(event.get("duration_s", 0))),
            ("Class", event.get("classification", "unknown")),
            ("Band", event.get("band_name", "")),
        ]
        for name, value in measured:
            field = QLabel(value)
            field.setObjectName("readout")
            form.addRow(name, field)

        antenna = event.get("antenna_note", "")
        if antenna:
            note = QLabel(antenna)
            note.setWordWrap(True)
            note.setObjectName("warning")
            form.addRow("Antenna", note)

        layout.addLayout(form)
        layout.addWidget(QLabel("Notes"))
        self.notes_edit = QPlainTextEdit()
        self.notes_edit.setMaximumHeight(90)
        layout.addWidget(self.notes_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self) -> tuple:
        return self.label_edit.text().strip(), self.notes_edit.toPlainText().strip()


class MainWindow(QMainWindow):
    """Application window. Owns the sweep engine, worker thread, and store."""

    def __init__(self, sweep_engine, detector: BurstDetector, store: Store,
                 preset_key: str = band_plan.DEFAULT_PRESET_KEY):
        super().__init__()
        self.setWindowTitle("Red Cell Security  RF Spectrum Analyzer")
        self.setStyleSheet(STYLE)

        # Sized against the screen actually attached rather than a fixed figure.
        # A hardcoded size larger than the display pushes the control dock off the
        # edge, where its buttons are unreachable and there is no obvious way to
        # recover, since the window cannot be dragged smaller than its contents.
        available = QGuiApplication.primaryScreen().availableGeometry()
        self.resize(min(1600, int(available.width() * 0.94)),
                    min(950, int(available.height() * 0.90)))

        self.engine = sweep_engine
        self.detector = detector
        self.store = store
        self.preset_key = preset_key

        self._active_events: Dict[int, Dict] = {}
        # Detections that have ended but are being retained for the record. Kept
        # separate from active ones so the display can distinguish present
        # activity from past activity.
        self._held_events: Dict[int, Dict] = {}
        self._last_hover: Optional[Dict] = None

        self._build_ui()
        self._start_worker()
        self._apply_preset(preset_key, initial=True)

        self.redraw_timer = QTimer(self)
        self.redraw_timer.timeout.connect(self._redraw)
        self.redraw_timer.start(REDRAW_INTERVAL_MS)

        self.stats_timer = QTimer(self)
        self.stats_timer.timeout.connect(self._update_stats)
        self.stats_timer.start(STATS_INTERVAL_MS)

    def _build_ui(self) -> None:
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        self.readout = QLabel("hover the spectrum for a frequency readout")
        self.readout.setObjectName("readout")
        mono = QFont("Monospace", 9)
        mono.setStyleHint(QFont.TypeWriter)
        self.readout.setFont(mono)
        # Allowed to shrink below its natural width. A fixed width readout sets a
        # floor on the whole window, which on a small display is what pushes the
        # control dock past the edge of the screen.
        self.readout.setMinimumWidth(1)
        self.readout.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Fixed)
        layout.addWidget(self.readout)

        self.display = SpectrumDisplay()
        self.display.hover_changed.connect(self._on_hover)
        self.display.marker_requested.connect(self._on_marker_requested)
        layout.addWidget(self.display, stretch=1)

        self.setCentralWidget(central)
        self.setStatusBar(QStatusBar())
        self._build_dock()

    def _build_dock(self) -> None:
        dock = QDockWidget("Control", self)
        dock.setAllowedAreas(Qt.RightDockWidgetArea | Qt.LeftDockWidgetArea)
        dock.setFeatures(QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable)

        tabs = QTabWidget()
        # The config tab is taller than any laptop screen once every group is
        # expanded, so it scrolls. Without this the lower controls are simply
        # clipped away with nothing to indicate they exist.
        tabs.addTab(self._scrollable(self._build_config_tab()), "Config")
        tabs.addTab(self._build_events_tab(), "Events")
        tabs.addTab(self._build_markers_tab(), "Markers")

        dock.setWidget(tabs)
        dock.setMinimumWidth(300)
        self.addDockWidget(Qt.RightDockWidgetArea, dock)

        # Given a width proportional to the window rather than a fixed one, so a
        # small display keeps most of its pixels for the spectrum.
        self.resizeDocks([dock], [max(340, min(460, self.width() // 3))], Qt.Horizontal)

    @staticmethod
    def _scrollable(page: QWidget) -> QScrollArea:
        """Wrap a panel so overflowing content scrolls instead of being clipped."""
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        area.setWidget(page)
        return area

    def _build_config_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        plan_box = QGroupBox("Band plan")
        plan_layout = QVBoxLayout(plan_box)

        self.region_combo = QComboBox()
        self.region_combo.addItems(["US", "EU", "SA", "GLOBAL"])
        self.region_combo.currentTextChanged.connect(self._populate_presets)
        plan_layout.addWidget(self.region_combo)

        self.preset_combo = QComboBox()
        plan_layout.addWidget(self.preset_combo)

        apply_button = QPushButton("Apply preset")
        apply_button.clicked.connect(self._on_apply_preset)
        plan_layout.addWidget(apply_button)

        # Entry fields on their own row and the button beneath, so the group stays
        # legible at the narrowest dock width rather than pushing the stop field
        # off the edge.
        custom_row = QHBoxLayout()
        self.custom_start = QLineEdit()
        self.custom_start.setPlaceholderText("start MHz")
        self.custom_stop = QLineEdit()
        self.custom_stop.setPlaceholderText("stop MHz")
        custom_row.addWidget(self.custom_start)
        custom_row.addWidget(self.custom_stop)
        plan_layout.addLayout(custom_row)

        custom_button = QPushButton("Apply custom range")
        custom_button.clicked.connect(self._apply_custom_range)
        plan_layout.addWidget(custom_button)

        # The sweep consequences are shown live because a wide span silently
        # trades away the ability to see short transmissions, and an operator who
        # is not told that reads an empty waterfall as an empty band.
        # Both labels wrap and are told to grow vertically. Without the size
        # policy a long warning is clipped by the group box rather than making it
        # taller, which is how the sweep metrics ended up drawn over the button
        # above them.
        self.metrics_label = QLabel()
        self.metrics_label.setObjectName("readout")
        self.metrics_label.setWordWrap(True)
        self.metrics_label.setMinimumHeight(34)
        self.metrics_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.MinimumExpanding)
        plan_layout.addWidget(self.metrics_label)

        self.warning_label = QLabel()
        self.warning_label.setObjectName("warning")
        self.warning_label.setWordWrap(True)
        self.warning_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.MinimumExpanding)
        plan_layout.addWidget(self.warning_label)

        layout.addWidget(plan_box)

        gain_box = QGroupBox("Gain")
        gain_layout = QFormLayout(gain_box)

        self.amp_combo = QComboBox()
        self.amp_combo.addItems(["off", "14 dB"])
        gain_layout.addRow("Front end amp", self.amp_combo)

        self.lna_slider, lna_row = self._make_slider(0, 40, 8, 16)
        gain_layout.addRow("LNA", lna_row)
        self.vga_slider, vga_row = self._make_slider(0, 62, 2, 20)
        gain_layout.addRow("VGA", vga_row)

        gain_button = QPushButton("Apply gain")
        gain_button.clicked.connect(self._apply_gain)
        gain_layout.addRow(gain_button)

        gain_note = QLabel(
            "Raising gain past the point where the floor lifts costs dynamic "
            "range and creates false wideband detections. Detector state resets "
            "on every gain change."
        )
        gain_note.setWordWrap(True)
        gain_note.setObjectName("warning")
        gain_layout.addRow(gain_note)

        layout.addWidget(gain_box)

        detect_box = QGroupBox("Detector")
        detect_layout = QFormLayout(detect_box)

        self.threshold_spin = QSpinBox()
        self.threshold_spin.setRange(3, 30)
        self.threshold_spin.setValue(int(self.detector.threshold_on_db))
        self.threshold_spin.setSuffix(" dB")
        self.threshold_spin.valueChanged.connect(self._apply_threshold)
        detect_layout.addRow("Trigger above floor", self.threshold_spin)

        self.open_spin = QSpinBox()
        self.open_spin.setRange(1, 10)
        self.open_spin.setValue(self.detector.open_frames)
        self.open_spin.valueChanged.connect(self._apply_open_frames)
        detect_layout.addRow("Confirm visits", self.open_spin)

        reject_button = QPushButton("Toggle persistent rejection")
        reject_button.clicked.connect(self._toggle_reject)
        detect_layout.addRow(reject_button)

        self.reject_label = QLabel()
        self.reject_label.setObjectName("readout")
        detect_layout.addRow(self.reject_label)
        self._update_reject_label()

        layout.addWidget(detect_box)
        layout.addWidget(self._build_display_box())
        layout.addWidget(self._build_calibration_box())
        layout.addStretch(1)
        return page

    def _build_display_box(self) -> QGroupBox:
        """Controls governing whether the display forgets what it has seen."""
        box = QGroupBox("Display retention")
        layout = QVBoxLayout(box)

        self.hold_peaks_check = QCheckBox("Hold peaks, no decay")
        self.hold_peaks_check.toggled.connect(self._apply_peak_hold)
        layout.addWidget(self.hold_peaks_check)

        self.hold_events_check = QCheckBox("Keep detections after they end")
        self.hold_events_check.toggled.connect(self._apply_event_hold)
        layout.addWidget(self.hold_events_check)

        clear_button = QPushButton("Clear held peaks and detections")
        clear_button.clicked.connect(self._clear_held)
        layout.addWidget(clear_button)

        self.held_label = QLabel("holding 0 detections")
        self.held_label.setObjectName("readout")
        layout.addWidget(self.held_label)

        note = QLabel(
            "By default the trace sheds old peaks and a detection disappears when "
            "the transmission stops, which suits watching a band live. Enable both "
            "to turn the display into a record instead, so a burst that keyed once "
            "an hour ago is still visible and still clickable to save as a marker."
        )
        note.setWordWrap(True)
        note.setObjectName("warning")
        layout.addWidget(note)
        return box

    def _apply_peak_hold(self, held: bool) -> None:
        """Stop or resume peak decay on the trace."""
        self.display.set_peak_decay(0.0 if held else DEFAULT_PEAK_DECAY_DB)

    def _apply_event_hold(self, held: bool) -> None:
        """Start or stop retaining detections past the end of a transmission."""
        if not held:
            self._held_events.clear()
            self._update_held_label()

    def _clear_held(self) -> None:
        """Discard accumulated peaks and held detections, keeping the floor."""
        self.display.clear_peak_hold()
        self._held_events.clear()
        self._update_held_label()
        self.statusBar().showMessage("held peaks and detections cleared", 3000)

    def _update_held_label(self) -> None:
        self.held_label.setText("holding {0} detections".format(len(self._held_events)))

    def _build_calibration_box(self) -> QGroupBox:
        """Controls for deriving and applying the oscillator correction."""
        box = QGroupBox("Frequency calibration")
        layout = QVBoxLayout(box)

        self.raster_combo = QComboBox()
        for key, raster in calibrate.RASTERS.items():
            self.raster_combo.addItem(raster.name, key)
        layout.addWidget(self.raster_combo)

        run_button = QPushButton("Calibrate from detections")
        run_button.clicked.connect(self._run_calibration)
        layout.addWidget(run_button)

        self.ppm_label = QLabel("correction 0.000 ppm, not yet measured")
        self.ppm_label.setObjectName("readout")
        self.ppm_label.setWordWrap(True)
        layout.addWidget(self.ppm_label)

        note = QLabel(
            "Select the broadcast preset for your region, let the sweep settle "
            "until several carriers are listed under Events, then calibrate. The "
            "HackRF has no temperature compensated oscillator and drifts most in "
            "the first ten minutes after power on, so recalibrate once warm."
        )
        note.setWordWrap(True)
        note.setObjectName("warning")
        layout.addWidget(note)
        return box

    def _run_calibration(self) -> None:
        """Derive the oscillator correction from currently detected carriers.

        Applied to the sweep engine so subsequent tuning is corrected, and stored
        against the session so markers taken under it can be reconciled later.
        Nothing already measured is retroactively adjusted, since the correction
        is only valid from the moment it is applied.
        """
        raster_key = self.raster_combo.currentData()
        events = list(self._active_events.values()) + self.detector.active_events()

        result = calibrate.estimate_ppm(events, raster_key)

        if not result.confident:
            self.ppm_label.setText(result.summary())
            QMessageBox.information(self, "Calibration", result.message)
            return

        self.engine.set_ppm(result.ppm)
        self.store.set_ppm_correction(result.ppm)
        # Every tuned frequency shifts, so floors learned at the old tuning no
        # longer describe the same bins.
        self.detector.reset()
        if self.display.composite is not None:
            self.display.composite.reset()

        self.ppm_label.setText(result.summary())
        detail = "\n".join(
            "  {0:.4f} MHz  assigned {1:.4f}  offset {2:+.0f} Hz".format(
                s["measured_hz"] / 1e6, s["expected_hz"] / 1e6, s["offset_hz"]
            )
            for s in result.stations
        )
        QMessageBox.information(
            self, "Calibration applied",
            "{0}\n\nStations used:\n{1}".format(result.summary(), detail),
        )
        self.statusBar().showMessage(
            "calibration applied, {0:+.2f} ppm".format(result.ppm), 5000
        )

    @staticmethod
    def _make_slider(low: int, high: int, step: int, value: int) -> tuple:
        """Slider with a live numeric label, stepped to hardware granularity."""
        container = QWidget()
        row = QHBoxLayout(container)
        row.setContentsMargins(0, 0, 0, 0)

        slider = QSlider(Qt.Horizontal)
        slider.setRange(low, high)
        slider.setSingleStep(step)
        slider.setPageStep(step)
        slider.setTickInterval(step)
        slider.setValue(value)

        label = QLabel("{0} dB".format(value))
        label.setMinimumWidth(52)
        label.setObjectName("readout")
        slider.valueChanged.connect(lambda v: label.setText("{0} dB".format(v)))

        row.addWidget(slider)
        row.addWidget(label)
        return slider, container

    def _build_events_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        self.events_table = QTableWidget(0, 6)
        self.events_table.setHorizontalHeaderLabels(
            ["Freq MHz", "BW kHz", "SNR", "Class", "Dur s", "Band"]
        )
        self.events_table.setAlternatingRowColors(True)
        self.events_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.events_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.events_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.events_table.itemDoubleClicked.connect(self._on_event_double_click)
        layout.addWidget(self.events_table)

        layout.addWidget(QLabel("Double click an event to save it as a marker."))
        return page

    def _build_markers_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        self.markers_table = QTableWidget(0, 4)
        self.markers_table.setHorizontalHeaderLabels(["Label", "Freq MHz", "BW kHz", "Class"])
        self.markers_table.setAlternatingRowColors(True)
        self.markers_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.markers_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.markers_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.markers_table)

        row = QHBoxLayout()
        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(self._delete_marker)
        export_button = QPushButton("Export CSV")
        export_button.clicked.connect(self._export_markers)
        row.addWidget(delete_button)
        row.addWidget(export_button)
        layout.addLayout(row)
        return page

    def _start_worker(self) -> None:
        """Move the processing worker onto its own QThread and start it."""
        self.worker_thread = QThread()
        self.worker = ProcessingWorker(self.engine.queue, self.detector)
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.frame_ready.connect(self._on_frame)
        self.worker.events_changed.connect(self._on_events)
        self.worker.error.connect(self._on_worker_error)
        self.worker_thread.start()

    def _populate_presets(self, region: str) -> None:
        self.preset_combo.clear()
        for preset in band_plan.list_presets(region):
            self.preset_combo.addItem(preset.name, preset.key)

    def _on_apply_preset(self) -> None:
        key = self.preset_combo.currentData()
        if key:
            self._apply_preset(key)

    def _apply_preset(self, key: str, initial: bool = False) -> None:
        """Switch the band plan, resetting display and detector state."""
        try:
            segments, metrics = band_plan.plan_from_preset(key)
        except (KeyError, ValueError) as exc:
            QMessageBox.warning(self, "Band plan", str(exc))
            return

        self.preset_key = key
        preset = band_plan.get_preset(key)

        if initial:
            self.region_combo.setCurrentText(preset.region)
            self._populate_presets(preset.region)
            index = self.preset_combo.findData(key)
            if index >= 0:
                self.preset_combo.setCurrentIndex(index)

        # Antenna notes travel with the band so that events and markers record
        # what was connected when a level was measured.
        self.detector.antenna_notes = {
            band.name: band.antenna_note for band in preset.bands
        }
        self._install_plan(segments, metrics)

    def _apply_custom_range(self) -> None:
        """Apply an operator entered range in MHz."""
        try:
            start_hz = int(float(self.custom_start.text()) * 1e6)
            stop_hz = int(float(self.custom_stop.text()) * 1e6)
        except ValueError:
            QMessageBox.warning(self, "Range", "Enter start and stop in MHz.")
            return

        try:
            segments, metrics = band_plan.plan_from_custom_range(start_hz, stop_hz)
        except ValueError as exc:
            QMessageBox.warning(self, "Range", str(exc))
            return

        self.preset_key = "custom"
        self.detector.antenna_notes = {}
        self._install_plan(segments, metrics)

    def _install_plan(self, segments: List, metrics) -> None:
        """Push a new segment plan to the engine, display, and detector."""
        self.engine.set_segments(segments)
        self.display.set_plan(segments)
        # State learned under the previous plan describes different frequencies
        # and different sample rates, so it is discarded rather than carried over.
        self.detector.reset()
        self._active_events.clear()
        self._held_events.clear()
        self._update_held_label()
        self.events_table.setRowCount(0)

        self.metrics_label.setText(
            "{0} segments, {1:.1f} MHz span\n"
            "revisit {2:.0f} ms, shortest burst {3:.0f} ms\n"
            "coarsest RBW {4:.0f} Hz".format(
                metrics.segment_count,
                metrics.total_span_hz / 1e6,
                metrics.revisit_ms,
                metrics.min_reliable_burst_ms,
                metrics.coarsest_rbw_hz,
            )
        )
        self.warning_label.setText("\n".join(metrics.warnings))
        self._refresh_markers()

    def _apply_gain(self) -> None:
        gain = GainProfile(
            amp_db=14 if self.amp_combo.currentIndex() == 1 else 0,
            lna_db=self.lna_slider.value(),
            vga_db=self.vga_slider.value(),
        )
        self.engine.set_gain(gain)
        # Every level in the frame shifts by the gain delta, so a floor learned at
        # the old setting is wrong by that amount and would blind or flood the
        # detector until it reconverged.
        self.detector.reset()
        if self.display.composite is not None:
            self.display.composite.reset()
        self.statusBar().showMessage("gain applied, detector reset", 3000)

    def _apply_threshold(self, value: int) -> None:
        self.detector.threshold_on_db = float(value)
        self.detector.threshold_off_db = float(value) - 2.0

    def _apply_open_frames(self, value: int) -> None:
        self.detector.open_frames = int(value)

    def _toggle_reject(self) -> None:
        self.detector.reject_persistent = not self.detector.reject_persistent
        self._update_reject_label()

    def _update_reject_label(self) -> None:
        state = "on" if self.detector.reject_persistent else "off"
        self.reject_label.setText(
            "persistent rejection {0}, always on carriers {1} raise events".format(
                state, "do not" if self.detector.reject_persistent else "do"
            )
        )

    @Slot(object, object)
    def _on_frame(self, frame, floor) -> None:
        self.display.ingest(frame, floor)

    @Slot(dict)
    def _on_events(self, result: Dict) -> None:
        for event in result["opened"]:
            self._active_events[event["event_id"]] = event
            self._add_event_row(event)
        for event in result["closed"]:
            self._active_events.pop(event["event_id"], None)
            if self.hold_events_check.isChecked():
                held = dict(event)
                held["classification"] = "held"
                self._held_events[event["event_id"]] = held
                # Oldest shed first, so a long session keeps the most recent
                # activity rather than the first few minutes of it.
                while len(self._held_events) > MAX_HELD_EVENTS:
                    oldest = min(self._held_events,
                                 key=lambda k: self._held_events[k]["last_seen"])
                    del self._held_events[oldest]
                self._update_held_label()

    @Slot(str)
    def _on_worker_error(self, message: str) -> None:
        self.statusBar().showMessage(message, 5000)

    def _add_event_row(self, event: Dict) -> None:
        """Insert a detection at the top of the live event table."""
        self.events_table.insertRow(0)
        cells = [
            "{0:.4f}".format(event["center_hz"] / 1e6),
            "{0:.1f}".format(event.get("occupied_bw_hz", 0) / 1e3),
            "{0:.1f}".format(event.get("snr_db", 0)),
            event.get("classification", "unknown"),
            "{0:.2f}".format(event.get("duration_s", 0)),
            event.get("band_name", ""),
        ]
        for column, text in enumerate(cells):
            item = QTableWidgetItem(text)
            if column == 0:
                item.setData(Qt.UserRole, event)
            self.events_table.setItem(0, column, item)

        while self.events_table.rowCount() > MAX_EVENT_ROWS:
            self.events_table.removeRow(self.events_table.rowCount() - 1)

    def _on_event_double_click(self, item: QTableWidgetItem) -> None:
        event = self.events_table.item(item.row(), 0).data(Qt.UserRole)
        if event:
            self._save_marker(event)

    def _on_hover(self, info: Dict) -> None:
        """Update the frequency readout from a pointer position."""
        self._last_hover = info
        self.readout.setText(
            "{0:.6f} MHz   level {1:.1f}   peak {2:.1f}   "
            "floor {3:.1f} dBFS   RBW {4:.0f} Hz   {5}".format(
                info["hz"] / 1e6, info["level_dbfs"], info["peak_dbfs"],
                info["floor_dbfs"], info["rbw_hz"], info["band_name"],
            )
        )

    def _on_marker_requested(self, hz: float) -> None:
        """Bind a click to the nearest active detection, or to the raw cursor.

        The detected event is preferred because it carries measured center
        frequency and occupied bandwidth, whereas the click carries only wherever
        the pointer happened to land. Matching tolerance scales with the event's
        own occupied bandwidth so that a wide signal is clickable across its whole
        width and a narrow one is not captured from far away.
        """
        best = None
        best_distance = None
        # Held detections are searched alongside active ones. A retained spike
        # that cannot be clicked is a picture rather than a record, which defeats
        # the point of retaining it.
        candidates = list(self._active_events.values()) + list(self._held_events.values())
        for event in candidates:
            tolerance = max(event.get("occupied_bw_hz", 0.0), 5000.0)
            distance = abs(event["center_hz"] - hz)
            if distance <= tolerance and (best_distance is None or distance < best_distance):
                best = event
                best_distance = distance

        if best is None:
            info = self._last_hover or {}
            best = {
                "center_hz": hz,
                "occupied_bw_hz": 0.0,
                "peak_dbfs": info.get("level_dbfs", 0.0),
                "floor_dbfs": info.get("floor_dbfs", 0.0),
                "snr_db": info.get("level_dbfs", 0.0) - info.get("floor_dbfs", 0.0),
                "first_seen": time.time(),
                "last_seen": time.time(),
                "duration_s": 0.0,
                "frame_count": 0,
                "classification": "manual",
                "band_name": info.get("band_name", ""),
                "antenna_note": "",
            }
        self._save_marker(best)

    def _save_marker(self, event: Dict) -> None:
        dialog = MarkerDialog(event, self)
        if dialog.exec() != QDialog.Accepted:
            return
        label, notes = dialog.values()
        if not label:
            return
        try:
            self.store.save_marker(label, event, notes)
        except RuntimeError as exc:
            QMessageBox.warning(self, "Marker", str(exc))
            return
        self._refresh_markers()
        self.statusBar().showMessage("marker saved: {0}".format(label), 3000)

    def _refresh_markers(self) -> None:
        markers = self.store.list_markers()
        self.markers_table.setRowCount(len(markers))
        for row, marker in enumerate(markers):
            cells = [
                marker["label"],
                "{0:.6f}".format(marker["center_hz"] / 1e6),
                "{0:.1f}".format((marker["occupied_bw_hz"] or 0) / 1e3),
                marker["classification"] or "",
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 0:
                    item.setData(Qt.UserRole, marker["id"])
                self.markers_table.setItem(row, column, item)
        self.display.show_saved_markers(markers)

    def _delete_marker(self) -> None:
        row = self.markers_table.currentRow()
        if row < 0:
            return
        marker_id = self.markers_table.item(row, 0).data(Qt.UserRole)
        self.store.delete_marker(marker_id)
        self._refresh_markers()

    def _export_markers(self) -> None:
        path = "markers_{0}.csv".format(int(time.time()))
        count = self.store.export_session_csv(path)
        self.statusBar().showMessage("exported {0} markers to {1}".format(count, path), 5000)

    def _redraw(self) -> None:
        self.display.redraw(threshold_offset_db=self.detector.threshold_on_db)
        # Held detections are drawn under the active ones, so current activity is
        # never obscured by the record of past activity.
        self.display.show_events(
            list(self._held_events.values()) + list(self._active_events.values())
        )

    def _update_stats(self) -> None:
        stats = self.engine.stats()
        recording = ""
        if stats.get("recording") and self.engine.recorder is not None:
            rec = self.engine.recorder.stats()
            recording = "   REC {0} MB ({1}%)".format(rec["megabytes"], rec["percent_full"])
        self.statusBar().showMessage(
            "device {0}   sweeps {1}   queue {2}   dropped {3}   overruns {4}   "
            "ppm {5:+.2f}   active events {6}{7}".format(
                "connected" if stats["connected"] else "DISCONNECTED",
                stats["sweeps"], stats["queue_depth"], stats["dropped_frames"],
                stats["overruns"], stats.get("ppm", 0.0),
                len(self._active_events), recording,
            )
        )

    def closeEvent(self, event) -> None:
        """Shut down the worker, the sweep thread, and the store in order."""
        self.redraw_timer.stop()
        self.stats_timer.stop()
        self.worker.stop()
        self.worker_thread.quit()
        self.worker_thread.wait(3000)
        self.engine.stop()
        if self.engine.recorder is not None:
            self.engine.recorder.stop()
        self.store.close()
        super().closeEvent(event)
