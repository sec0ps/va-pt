#!/usr/bin/env python3
# =============================================================================
# Location: main.py
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
#   Application entry point. Provisions and enters the virtual environment, parses
#   arguments, selects a capture source, opens the engagement session store, wires
#   the sweep engine to the detector and the user interface, and runs the Qt event
#   loop.
#
#   Import order in this file is deliberate and load bearing. The bootstrap runs
#   before any third party import, because a missing dependency would otherwise
#   raise on import and terminate the process before the code able to install that
#   dependency had run. Everything below the bootstrap call is safe to import
#   because the bootstrap either satisfied it or replaced the process with an
#   interpreter where it is satisfied.
#
#   Three capture sources are selectable. The radio is the operational path. The
#   synthetic source generates tones of known frequency for validating the chain
#   with no hardware present. The replay source serves previously recorded IQ, so
#   a detector change can be measured against the real RF environment of a site
#   rather than against generated signals.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. The application is receive only and
#   performs energy detection without demodulation or recovery of communications
#   content. Raw IQ recording is available but disabled by default, and a
#   recording preserves the full modulated content of every transmission in the
#   captured span, which is materially more sensitive than the detection metadata
#   the platform otherwise produces. Whether recording falls within scope is
#   governed by the engagement rules of engagement. Session records and recordings
#   are written unencrypted and inherit the protection of the filesystem holding
#   them.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""Entry point. Bootstraps the environment, then wires capture, DSP, and the UI."""

import os
import sys

# Bootstrap before anything else. This import and call must precede every third
# party import in the process. Moving any import above them reintroduces the
# failure the bootstrap exists to prevent.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bootstrap

# Consumed before argparse exists, since the bootstrap has to run before any
# third party import and argparse cannot be reached through one.
def _take_flag(flag: str) -> bool:
    present = flag in sys.argv
    if present:
        sys.argv.remove(flag)
    return present


_SKIP_BOOTSTRAP = _take_flag("--no-bootstrap")

bootstrap.ensure_environment(skip=_SKIP_BOOTSTRAP)

# Safe from here. Everything below either was importable already or was installed
# by the bootstrap above.
import argparse
import json
import logging
import time

from PySide6.QtWidgets import QApplication, QMessageBox

import band_plan
import calibrate
from burst_detect import BurstDetector
from iq_replay import IQRecorder, ReplaySource, describe
from sdr_capture import (
    GainProfile, HackRFSource, SweepEngine, SyntheticSource,
    HACKRF_AVAILABLE, enumerate_devices,
)
from store import Store
from ui_main import MainWindow

LOG = logging.getLogger("rfspectrum")

# Tones injected by the synthetic source, placed on real FRS, GMRS, and MURS
# channel centers so a detected frequency can be checked against a published
# assignment rather than against an arbitrary test value.
SYNTHETIC_TONES = (
    151_820_000,
    462_562_500,
    462_687_500,
    467_612_500,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Red Cell Security RF spectrum analyzer, single HackRF sweep and detect.",
        epilog="On first launch a virtual environment is created beside this "
               "script, Python dependencies are installed into it, and the system "
               "Nothing requires root. Radio access uses the libhackrf shared "
               "library already on the host, so there is nothing to compile. "
               "--no-bootstrap uses the current interpreter instead and is "
               "handled before argument parsing.",
    )
    source_group = parser.add_argument_group("capture source")
    source_group.add_argument("--synthetic", action="store_true",
                              help="generated IQ with known tones, no radio required")
    source_group.add_argument("--replay", metavar="FILE", default=None,
                              help="replay a previously recorded IQ capture")
    source_group.add_argument("--replay-once", action="store_true",
                              help="stop at the end of a replay instead of looping")
    source_group.add_argument("--replay-fast", action="store_true",
                              help="replay without pacing, for fast regression runs")
    source_group.add_argument("--serial", default=None,
                              help="HackRF serial, needed only with more than one attached")

    record_group = parser.add_argument_group("recording")
    record_group.add_argument("--record", metavar="FILE", default=None,
                              help="record raw IQ, roughly 28 MB/s on the default preset")
    record_group.add_argument("--record-max-gb", type=float, default=2.0,
                              help="recording size ceiling in GB, default 2.0")

    parser.add_argument("--preset", default=band_plan.DEFAULT_PRESET_KEY,
                        help="starting band plan preset key")
    parser.add_argument("--ppm", type=float, default=0.0,
                        help="oscillator correction in ppm, or calibrate from the UI")
    parser.add_argument("--reset-layout", action="store_true",
                        help="ignore the saved window layout and start from defaults")
    parser.add_argument("--session", default=None,
                        help="engagement session name, defaults to a timestamp")
    parser.add_argument("--db", default="spectrum.db", help="path to the session database")
    parser.add_argument("--lna", type=int, default=16, help="LNA gain in dB, 0 to 40")
    parser.add_argument("--vga", type=int, default=20, help="VGA gain in dB, 0 to 62")
    parser.add_argument("--amp", action="store_true",
                        help="enable the 14 dB front end amplifier, off by default")

    info_group = parser.add_argument_group("information")
    info_group.add_argument("--list-devices", action="store_true",
                            help="enumerate attached SDRs and exit")
    info_group.add_argument("--list-presets", action="store_true",
                            help="print every preset with its sweep metrics and exit")
    info_group.add_argument("--describe", metavar="FILE", default=None,
                            help="summarize an IQ recording and exit")
    info_group.add_argument("--verbose", action="store_true", help="debug level logging")

    # Declared for help output only. These are stripped from argv before argparse
    # runs, because the bootstrap they control must execute before any third party
    # import and therefore before a parser can exist.
    boot_group = parser.add_argument_group("environment bootstrap")
    boot_group.add_argument("--no-bootstrap", action="store_true",
                            help="use the current interpreter, skip the virtual environment")
    return parser.parse_args()


def print_presets() -> None:
    """Print the operator facing consequences of every preset."""
    header = "{0:<24} {1:<34} {2:>5} {3:>11} {4:>10} {5:>11}".format(
        "Key", "Preset", "Segs", "Span", "Revisit", "Min burst"
    )
    print(header)
    print("-" * len(header))
    for preset in band_plan.list_presets():
        try:
            _, metrics = band_plan.plan_from_preset(preset.key)
        except ValueError as exc:
            print("{0:<24} {1:<34} error {2}".format(preset.key, preset.name, exc))
            continue
        print("{0:<24} {1:<34} {2:>5} {3:>9.1f} M {4:>8.0f} ms {5:>9.0f} ms".format(
            preset.key, preset.name, metrics.segment_count,
            metrics.total_span_hz / 1e6, metrics.revisit_ms,
            metrics.min_reliable_burst_ms,
        ))


def build_source(args: argparse.Namespace, gain: GainProfile):
    """Select the capture source. Returns (source, segments_override, kind)."""
    if args.replay:
        source = ReplaySource(
            args.replay,
            loop=not args.replay_once,
            realtime=not args.replay_fast,
        )
        source.open()
        # The recording carries its own segment plan. Replaying against a
        # different plan would feed the detector blocks captured at frequencies
        # and sample rates it was not told about.
        return source, source.segments, "replay"

    if args.synthetic:
        return SyntheticSource(tones_hz=SYNTHETIC_TONES, gain=gain,
                               burst_period_s=1.2, burst_duty=0.35), None, "synthetic"

    if not HACKRF_AVAILABLE:
        LOG.error("libhackrf could not be loaded, cannot open hardware")
        return None, None, "none"

    hackrfs = enumerate_devices()
    if not hackrfs:
        LOG.error("no HackRF found. Confirm the device is attached and that "
                  "hackrf_info sees it.")
        return None, None, "none"
    if len(hackrfs) > 1 and args.serial is None:
        LOG.warning("%d HackRF devices attached, opening the first, "
                    "pass --serial to choose. Serials: %s", len(hackrfs),
                    ", ".join(str(d.get("serial")) for d in hackrfs))

    return HackRFSource(serial=args.serial, gain=gain), None, "hardware"


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
    )

    if args.list_presets:
        print_presets()
        return 0

    if args.describe:
        try:
            print(json.dumps(describe(args.describe), indent=2))
        except (OSError, ValueError) as exc:
            LOG.error("%s", exc)
            return 1
        return 0

    if args.list_devices:
        devices = enumerate_devices()
        if not devices:
            print("no HackRF devices found")
            if not HACKRF_AVAILABLE:
                print("libhackrf could not be loaded on this host")
        for device in devices:
            print("[{0}] {1}  serial {2}".format(
                device["index"], device["board"], device["serial"]))
        return 0 if devices else 1

    gain = GainProfile(amp_db=14 if args.amp else 0, lna_db=args.lna, vga_db=args.vga).clamp()

    try:
        source, plan_override, kind = build_source(args, gain)
    except (OSError, ValueError) as exc:
        LOG.error("capture source failed to open: %s", exc)
        return 1

    if source is None:
        LOG.error("no capture source available. Use --synthetic to work without a "
                  "radio, or --replay to work from a recording.")
        return 1

    if plan_override is not None:
        segments = plan_override
        metrics = band_plan.sweep_metrics(segments)
        preset_key = "replay"
    else:
        try:
            segments, metrics = band_plan.plan_from_preset(args.preset)
        except (KeyError, ValueError) as exc:
            LOG.error("%s", exc)
            return 1
        preset_key = args.preset

    app = QApplication(sys.argv)

    store = Store(args.db)
    session_name = args.session or time.strftime("session-%Y%m%d-%H%M%S")
    store.start_session(
        name=session_name,
        preset_key=preset_key,
        band_plan=[
            {"segment_id": s.segment_id, "band": s.band_name,
             "center_hz": s.center_hz, "sample_rate_hz": s.sample_rate_hz}
            for s in segments
        ],
        gain=gain.to_dict(),
    )
    if args.ppm:
        store.set_ppm_correction(args.ppm)
    LOG.info("session %s opened in %s", session_name, args.db)

    detector = BurstDetector()
    if plan_override is None:
        preset = band_plan.get_preset(preset_key)
        detector.antenna_notes = {band.name: band.antenna_note for band in preset.bands}

    recorder = None
    if args.record:
        if kind == "replay":
            LOG.error("refusing to record a replay, the source is already a recording")
            return 1
        recorder = IQRecorder(
            args.record, segments, gain=gain.to_dict(),
            max_bytes=int(args.record_max_gb * 1e9),
            notes="session {0}, preset {1}".format(session_name, preset_key),
        )

    engine = SweepEngine(source, segments, ppm_correction=args.ppm, recorder=recorder)
    engine.start()

    window = MainWindow(engine, detector, store, preset_key=preset_key,
                        reset_layout=args.reset_layout)
    if plan_override is not None:
        # A replay is bound to the plan inside the recording, so the display is
        # pointed at that plan rather than at whatever preset was named.
        window.display.set_plan(segments)
    window.show()

    if kind == "synthetic":
        # Stated plainly and unmissably. An operator who mistakes generated tones
        # for live spectrum will record findings that do not exist.
        QMessageBox.information(
            window, "Synthetic source active",
            "No radio is attached. Displayed signals are generated test tones at "
            "151.820, 462.5625, 462.6875, and 467.6125 MHz.\n\n"
            "Nothing shown here is live spectrum.",
        )
    elif kind == "replay":
        info = source.stats()
        QMessageBox.information(
            window, "Replay active",
            "Replaying {0}\n\n{1} blocks, {2:.1f} s of capture.\n\n"
            "This is recorded spectrum, not live. Frequencies and levels are "
            "those of the original capture.".format(
                args.replay, info["blocks"], info["duration_s"]),
        )

    if recorder is not None:
        QMessageBox.warning(
            window, "IQ recording active",
            "Recording raw IQ to {0}, ceiling {1:.1f} GB.\n\n"
            "A raw recording preserves the full content of every transmission in "
            "the captured span. Confirm this is within the engagement scope."
            .format(args.record, args.record_max_gb),
        )

    LOG.info(
        "sweeping %d segments, revisit %.0f ms, shortest reliable burst %.0f ms",
        metrics.segment_count, metrics.revisit_ms, metrics.min_reliable_burst_ms,
    )
    for warning in metrics.warnings:
        LOG.warning("%s", warning)
    if args.ppm:
        LOG.info("oscillator correction %+.3f ppm applied at tune", args.ppm)

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
