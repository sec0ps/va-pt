#!/usr/bin/env python3
# =============================================================================
# Location: calibrate.py
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
#   Derives the frequency error of the receiver from detections against a known
#   channel raster, expressed in parts per million.
#
#   The HackRF ships without a temperature compensated oscillator. Its error is
#   commonly tens of parts per million and drifts most in the first minutes after
#   power on, which at 900 MHz is tens of kilohertz of walk during warm up. A
#   marker saved cold and a marker saved warm will disagree about the same
#   emitter, and neither will match a published assignment.
#
#   Correction is derived from the broadcast raster rather than from the FM
#   stereo pilot. The pilot method is more precise but requires demodulating the
#   multiplex, which belongs to the listening tier and does not exist here. The
#   raster method uses only what the burst detector already produces. Broadcast
#   allocations sit on an exact grid, so each detected carrier can be snapped to
#   its nearest grid slot and the systematic difference across all of them is the
#   oscillator error. Random measurement error averages out across stations while
#   oscillator error does not, which is what makes the estimate converge.
#
#   Robustness matters more than precision here. A single carrier snapped to the
#   wrong grid slot would corrupt a least squares fit badly, so the estimate is
#   the median of the per station errors rather than the mean, and any station
#   whose offset approaches half the grid spacing is discarded outright as
#   unassignable rather than being allowed to vote.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. Calibration observes broadcast
#   carriers that are publicly and continuously transmitted, and performs energy
#   measurement only with no demodulation or recovery of programme content.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. A correction
#   derived here is valid for the receiver temperature and session in which it
#   was measured and should be re-derived after warm up or after any significant
#   change in operating conditions. The author and Red Cell Security LLC accept
#   no liability for any use of this software, whether authorized or otherwise.
# =============================================================================

"""Receiver frequency error estimation from a known broadcast channel raster."""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Raster:
    """A regular channel grid against which detections can be assigned."""

    key: str
    name: str
    start_hz: int
    stop_hz: int
    spacing_hz: int
    # Offset of the first channel from start_hz. US FM begins at 88.1 rather than
    # 88.0, so the grid is not simply a multiple of the spacing from the band edge.
    offset_hz: int = 0

    def nearest(self, hz: float) -> float:
        """Snap a frequency to the nearest slot on this grid."""
        base = self.start_hz + self.offset_hz
        index = round((hz - base) / float(self.spacing_hz))
        return base + index * self.spacing_hz

    def contains(self, hz: float) -> bool:
        return self.start_hz <= hz <= self.stop_hz


RASTERS: Dict[str, Raster] = {
    # ITU Region 2 FM broadcast. Odd tenths of a megahertz, 200 kHz spacing.
    "fm_us": Raster("fm_us", "FM broadcast, Americas", 88_000_000, 108_000_000, 200_000, 100_000),
    # ITU Region 1 FM broadcast. 100 kHz spacing across a wider band edge.
    "fm_eu": Raster("fm_eu", "FM broadcast, Europe", 87_500_000, 108_000_000, 100_000, 0),
    # Airband AM, 25 kHz spacing. Coarser and more intermittent than FM, usable
    # where FM is unavailable but a weaker reference.
    "airband": Raster("airband", "Airband AM", 108_000_000, 137_000_000, 25_000, 0),
}

# Minimum stations required before a result is reported as usable. Below this the
# median has no resistance to a single misassigned carrier.
MIN_STATIONS = 3

# Minimum signal to noise for a detection to be eligible. A weak carrier has a
# noisy centroid and contributes error rather than information.
MIN_SNR_DB = 12.0

# Minimum visits a detection must have accumulated before its averaged center is
# trusted.
#
# A modulated signal has no stable instantaneous centroid, so this threshold is
# what separates a usable calibration from a meaningless one. Centroid noise falls
# as the square root of the visit count, and wideband FM carries roughly four
# kilohertz of per visit centroid wander, which at broadcast frequencies is about
# forty parts per million of noise on a single observation. Measured against
# eight stations, a thousand visits brings station to station disagreement below
# one part per million and returns a confident result better than nine times in
# ten. On the FM validation preset that is a little under six seconds of sweeping,
# which is a negligible wait for a figure the whole session's frequency accuracy
# depends on.
MIN_FRAME_COUNT = 1000

# A detection whose offset from its nearest grid slot exceeds this fraction of the
# spacing cannot be confidently assigned and is discarded. At half the spacing the
# assignment is a coin toss between two adjacent slots.
MAX_OFFSET_FRACTION = 0.35


@dataclass
class CalibrationResult:
    """Outcome of a calibration attempt, including the evidence behind it."""

    ppm: float = 0.0
    station_count: int = 0
    residual_hz: float = 0.0
    spread_ppm: float = 0.0
    confident: bool = False
    message: str = ""
    stations: List[Dict] = field(default_factory=list)

    def summary(self) -> str:
        if not self.confident:
            return "calibration not confident: {0}".format(self.message)
        return (
            "{0:+.2f} ppm from {1} stations, spread {2:.2f} ppm, "
            "residual {3:.0f} Hz".format(
                self.ppm, self.station_count, self.spread_ppm, self.residual_hz
            )
        )


def estimate_ppm(events: List[Dict], raster_key: str = "fm_us") -> CalibrationResult:
    """Estimate receiver frequency error from detections against a channel grid.

    Each eligible detection is snapped to its nearest grid slot, and the relative
    error against that slot is one estimate of the oscillator error. The reported
    figure is the median across stations, which tolerates a misassignment that
    would badly skew a mean, and the spread across stations is reported alongside
    so the operator can see whether the stations agree.
    """
    raster = RASTERS.get(raster_key)
    if raster is None:
        return CalibrationResult(message="unknown raster '{0}'".format(raster_key))

    candidates = []
    thin = 0
    for event in events:
        # The averaged center is used rather than the instantaneous one. For a
        # modulated signal the per visit centroid moves with programme content
        # while its mean converges on the carrier, and calibration is precisely
        # the case where that difference decides whether the answer is usable.
        hz = float(event.get("center_mean_hz") or event.get("center_hz", 0.0))
        if not raster.contains(hz):
            continue
        if float(event.get("snr_db", 0.0)) < MIN_SNR_DB:
            continue
        if int(event.get("frame_count", 0)) < MIN_FRAME_COUNT:
            thin += 1
            continue

        expected = raster.nearest(hz)
        offset = hz - expected
        if abs(offset) > raster.spacing_hz * MAX_OFFSET_FRACTION:
            # Too far from any slot to assign. Usually a spur, an image, or an
            # adjacent channel sideband rather than a carrier.
            continue

        # Reported frequency reads low by the oscillator error, so the error is
        # the shortfall against the true assignment relative to that assignment.
        ppm = 1e6 * (expected - hz) / expected
        candidates.append({
            "measured_hz": hz,
            "expected_hz": expected,
            "offset_hz": offset,
            "ppm": ppm,
            "snr_db": float(event.get("snr_db", 0.0)),
        })

    if len(candidates) < MIN_STATIONS:
        return CalibrationResult(
            station_count=len(candidates),
            stations=candidates,
            message="only {0} usable carriers found, {1} required.{2} Confirm the "
                    "antenna is connected and that the sweep covers the "
                    "broadcast band.".format(
                        len(candidates), MIN_STATIONS,
                        " {0} carriers have been seen but need {1} visits each to "
                        "average out modulation, let the sweep run a few more "
                        "seconds.".format(thin, MIN_FRAME_COUNT)
                        if thin else ""),
        )

    values = np.array([c["ppm"] for c in candidates], dtype=np.float64)
    ppm = float(np.median(values))

    # Spread as median absolute deviation scaled to a standard deviation
    # equivalent. Resistant to an outlier in a way a plain standard deviation is
    # not, which matters because one misassigned carrier is the expected failure.
    mad = float(np.median(np.abs(values - ppm)))
    spread = mad * 1.4826

    residual = float(np.median([
        abs(c["offset_hz"] - ppm * 1e-6 * c["expected_hz"]) for c in candidates
    ]))

    # Agreement across stations is the confidence test. Oscillator error is common
    # to every measurement, so genuine stations should agree closely. Wide
    # disagreement means the assignments are wrong, not that the oscillator is
    # unstable.
    confident = spread < 2.0
    message = "" if confident else (
        "stations disagree by {0:.2f} ppm, assignments are unreliable. Check that "
        "the correct regional raster is selected.".format(spread)
    )

    result = CalibrationResult(
        ppm=ppm,
        station_count=len(candidates),
        residual_hz=residual,
        spread_ppm=spread,
        confident=confident,
        message=message,
        stations=sorted(candidates, key=lambda c: c["measured_hz"]),
    )
    LOG.info("calibration: %s", result.summary())
    return result


def apply_ppm(frequency_hz: float, ppm: float) -> float:
    """Convert a commanded frequency into the value to send to the hardware.

    An oscillator running fast places the local oscillator above the commanded
    frequency by the same proportion, so the command is scaled down by the error
    to land the local oscillator where it was asked to be. Frame metadata
    continues to report the intended frequency, which keeps the correction
    invisible to everything downstream of the tuner.
    """
    return frequency_hz * (1.0 - ppm * 1e-6)


def recommended_raster(region: str) -> str:
    """Pick the broadcast grid matching an operating region."""
    return "fm_eu" if str(region).upper() == "EU" else "fm_us"
