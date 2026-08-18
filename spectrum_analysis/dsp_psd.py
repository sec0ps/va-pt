#!/usr/bin/env python3
# =============================================================================
# Location: dsp_psd.py
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
#   Converts complex baseband IQ blocks from one segment dwell into a power
#   spectral density frame expressed in dBFS, and reduces that frame to display
#   width for transport to the browser.
#
#   Two representations leave this module. Full resolution PSD feeds the burst
#   detector, because detection sensitivity must not be limited by how wide the
#   operator happens to have sized the browser window. Display reduced PSD feeds
#   the transport layer as quantized bytes. Reduction uses a maximum over each
#   group of source bins rather than a mean, since a mean averages a narrow
#   carrier against its neighbouring noise bins and buries exactly the narrow
#   signals the analyzer exists to find.
#
#   All power figures are dBFS relative to a full scale complex sinusoid. They
#   are not calibrated to dBm. Absolute level depends on gain distribution,
#   antenna, feedline, and frontend conversion loss, none of which this module
#   knows. Levels are comparable within a segment and within a band. They are not
#   comparable across bands where the antenna changes.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. This module performs energy
#   detection only. It does not demodulate, decode, or recover the content of any
#   transmission. Any capability that recovers communications content is governed
#   separately by the engagement rules of engagement.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""PSD estimation, display bin reduction, and spectrum frame assembly."""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

import numpy as np

# Floor applied to linear power before the logarithm, preventing a divide by
# zero or a negative infinity when a bin contains no energy at all. Chosen well
# below the noise floor of an 8 bit converter so it never clips a real reading.
POWER_EPSILON = 1e-20

# Number of FFT bins either side of DC that are discarded. The HackRF exhibits a
# strong DC offset spike at the tuner center from LO leakage and converter offset
# and it is an artifact, not a signal. Masking is applied here rather than in the
# detector so that both the display and the detector see the same masked data.
DC_MASK_BINS = 3

# Quantization range for display transport. Values are clamped into this window
# before being scaled to a byte, so the browser receives a uint8 per bin plus a
# scale and offset in the frame header rather than four bytes of float per bin.
DISPLAY_DB_FLOOR = -130.0
DISPLAY_DB_CEIL = 0.0


@dataclass
class SpectrumFrame:
    """One segment observation, carrying its own frequency metadata.

    Every frame is self describing. Frequency metadata travels with the data
    rather than being inferred by the browser from a remembered configuration,
    because the sweeper retunes constantly and a browser that assumes a stale
    center frequency will map hover position to the wrong frequency. Correctness
    of the hover readout depends on this and nothing else.
    """

    segment_id: int
    band_name: str
    center_hz: int
    sample_rate_hz: int
    f_start_hz: float
    f_stop_hz: float
    f_step_hz: float
    n_bins: int
    rbw_hz: float
    timestamp: float

    # Full resolution PSD in dBFS across the usable portion of the segment.
    # Consumed by the burst detector. Not transported.
    power_dbfs: np.ndarray = field(repr=False, default=None)

    # Display reduced PSD quantized to uint8 with the scale carried alongside.
    display_bins: np.ndarray = field(repr=False, default=None)
    display_db_min: float = DISPLAY_DB_FLOOR
    display_db_max: float = DISPLAY_DB_CEIL

    # Count of samples the capture layer reported as dropped or overrun during
    # this dwell. A nonzero value means the frame is time discontinuous and the
    # detector should not treat it as a clean consecutive observation.
    overruns: int = 0

    def bin_to_hz(self, bin_index: float) -> float:
        """Map a fractional bin index to frequency. Mirrors the browser math."""
        return self.f_start_hz + bin_index * self.f_step_hz

    def hz_to_bin(self, hz: float) -> float:
        """Map a frequency to fractional bin index within this frame."""
        return (hz - self.f_start_hz) / self.f_step_hz

    def transport_header(self) -> Dict:
        """Metadata dict paired with the display byte payload on the wire."""
        return {
            "segment_id": self.segment_id,
            "band_name": self.band_name,
            "center_hz": self.center_hz,
            "sample_rate_hz": self.sample_rate_hz,
            "f_start_hz": self.f_start_hz,
            "f_stop_hz": self.f_stop_hz,
            "f_step_hz": self.f_step_hz,
            "n_bins": self.n_bins,
            "rbw_hz": self.rbw_hz,
            "timestamp": self.timestamp,
            "display_n": int(self.display_bins.size) if self.display_bins is not None else 0,
            "db_min": self.display_db_min,
            "db_max": self.display_db_max,
            "overruns": self.overruns,
        }


class WindowCache:
    """Caches FFT windows and their coherent gain by length.

    Window construction is pure arithmetic on a fixed length and would otherwise
    repeat on every dwell. Since the planner assigns different sample rates per
    band but a constant FFT size, this cache normally holds a single entry, but
    it is keyed by length so that a future variable resolution mode costs nothing
    extra.
    """

    def __init__(self):
        self._windows: Dict[int, Tuple[np.ndarray, float]] = {}

    def get(self, length: int) -> Tuple[np.ndarray, float]:
        """Return the window and the correction factor for its coherent gain.

        A Hann window is used. It trades a slightly wider main lobe against far
        lower sidelobes than a rectangular window, which matters here because a
        strong carrier with rectangular windowing smears sidelobe energy across
        dozens of neighbouring bins and the detector reads that smear as a wide
        burst. Sidelobe suppression is what keeps occupied bandwidth estimates
        honest next to a strong emitter.
        """
        cached = self._windows.get(length)
        if cached is not None:
            return cached
        window = np.hanning(length).astype(np.float32)
        # Coherent gain correction. The window attenuates the signal overall, so
        # power is normalized by the sum of window samples to keep a full scale
        # sinusoid reading 0 dBFS regardless of window choice.
        coherent_gain = float(np.sum(window))
        entry = (window, coherent_gain)
        self._windows[length] = entry
        return entry


class PSDEstimator:
    """Averaged periodogram PSD estimator with preallocated working buffers.

    Buffers are allocated once per FFT size and reused across dwells. At the
    revisit intervals the planner produces, per frame allocation of multi
    kilobyte arrays would put the garbage collector directly in the hot path.
    """

    def __init__(self, fft_size: int, display_bins: int = 1024):
        self.fft_size = int(fft_size)
        self.display_bins = int(display_bins)
        self._windows = WindowCache()
        # Accumulator for averaged power across the periodograms of one dwell.
        self._accum = np.zeros(self.fft_size, dtype=np.float64)

    def compute(
        self,
        iq: np.ndarray,
        segment,
        overruns: int = 0,
        timestamp: Optional[float] = None,
    ) -> SpectrumFrame:
        """Estimate PSD for one segment dwell and assemble a transport frame.

        The IQ block is split into as many non overlapping FFT length chunks as
        it contains and the resulting periodograms are averaged in the linear
        power domain. Averaging in linear power rather than in dB is deliberate.
        Averaging dB values biases the estimate low and understates a burst that
        is present in only some of the averaged chunks, which is precisely the
        signal class this analyzer targets.
        """
        if timestamp is None:
            timestamp = time.time()

        n = self.fft_size
        usable_chunks = int(iq.size // n)
        if usable_chunks < 1:
            raise ValueError(
                "IQ block of {0} samples is shorter than the FFT size {1}".format(iq.size, n)
            )

        window, coherent_gain = self._windows.get(n)
        self._accum[:] = 0.0

        for chunk_index in range(usable_chunks):
            start = chunk_index * n
            chunk = iq[start:start + n]
            spectrum = np.fft.fft(chunk * window)
            # Magnitude squared gives power. Normalizing by coherent gain squared
            # undoes the window attenuation so the scale stays in dBFS.
            self._accum += (spectrum.real ** 2 + spectrum.imag ** 2)

        self._accum /= float(usable_chunks) * (coherent_gain ** 2)

        # Shift so that DC sits in the middle and the array reads low frequency
        # to high frequency left to right, matching the display.
        power_linear = np.fft.fftshift(self._accum)

        # Mask the DC region. The spike there is converter offset and LO leakage.
        # Interpolating across it rather than zeroing avoids creating an
        # artificial notch that the detector would have to learn to ignore.
        center = n // 2
        lo = max(0, center - DC_MASK_BINS)
        hi = min(n, center + DC_MASK_BINS + 1)
        if hi - lo < n:
            left_ref = power_linear[lo - 1] if lo > 0 else power_linear[hi]
            right_ref = power_linear[hi] if hi < n else power_linear[lo - 1]
            power_linear[lo:hi] = 0.5 * (left_ref + right_ref)

        power_dbfs = 10.0 * np.log10(np.maximum(power_linear, POWER_EPSILON))
        power_dbfs = power_dbfs.astype(np.float32)

        # Trim to the usable portion of the segment. The outer bins carry filter
        # skirt roll off rather than true level, and the planner already overlaps
        # segments by the discarded amount so no spectrum is lost.
        full_start = segment.center_hz - segment.sample_rate_hz / 2.0
        f_step = segment.sample_rate_hz / float(n)
        lo_bin = int(round((segment.usable_start_hz - full_start) / f_step))
        hi_bin = int(round((segment.usable_stop_hz - full_start) / f_step))
        lo_bin = max(0, min(lo_bin, n - 2))
        hi_bin = max(lo_bin + 1, min(hi_bin, n))
        usable = power_dbfs[lo_bin:hi_bin]

        f_start = full_start + lo_bin * f_step
        f_stop = full_start + hi_bin * f_step

        frame = SpectrumFrame(
            segment_id=segment.segment_id,
            band_name=segment.band_name,
            center_hz=segment.center_hz,
            sample_rate_hz=segment.sample_rate_hz,
            f_start_hz=f_start,
            f_stop_hz=f_stop,
            f_step_hz=f_step,
            n_bins=int(usable.size),
            rbw_hz=f_step,
            timestamp=timestamp,
            power_dbfs=usable,
            overruns=overruns,
        )
        frame.display_bins = self.reduce_for_display(usable, self.display_bins)
        return frame

    @staticmethod
    def reduce_for_display(power_dbfs: np.ndarray, target_bins: int) -> np.ndarray:
        """Reduce a PSD array to display width and quantize to bytes.

        Maximum is taken over each group of source bins rather than a mean. A
        mean would average a single occupied bin against its unoccupied
        neighbours and attenuate a narrow carrier by the reduction ratio, which
        at typical ratios hides narrowband signals entirely. Maximum preserves
        peak level at the cost of slightly widening the apparent occupied
        bandwidth on screen, which is the correct trade for a monitoring display.
        """
        source_n = int(power_dbfs.size)
        if source_n == 0:
            return np.zeros(0, dtype=np.uint8)

        if source_n <= target_bins:
            reduced = power_dbfs
        else:
            group = source_n // target_bins
            trimmed_n = group * target_bins
            # Reshape and take the maximum along the group axis. The tail bins
            # that do not divide evenly are folded into the final group so no
            # spectrum is silently dropped off the right hand edge.
            head = power_dbfs[:trimmed_n].reshape(target_bins, group)
            reduced = head.max(axis=1)
            if trimmed_n < source_n:
                tail_max = power_dbfs[trimmed_n:].max()
                reduced[-1] = max(float(reduced[-1]), float(tail_max))

        clipped = np.clip(reduced, DISPLAY_DB_FLOOR, DISPLAY_DB_CEIL)
        span = DISPLAY_DB_CEIL - DISPLAY_DB_FLOOR
        scaled = (clipped - DISPLAY_DB_FLOOR) * (255.0 / span)
        return scaled.astype(np.uint8)


def synthetic_iq(
    segment,
    n_samples: int,
    tones_hz: Optional[Tuple[float, ...]] = None,
    tone_db: float = -30.0,
    noise_db: float = -75.0,
    seed: Optional[int] = None,
) -> np.ndarray:
    """Generate test IQ with known tones for validating the chain without hardware.

    This is the loopback substitute for a bench signal generator. Placing a tone
    at a known absolute frequency and confirming the detector reports that same
    frequency validates the entire bin to frequency mapping, including the usable
    window trim and the segment center offset, which is where off by one errors
    hide.
    """
    rng = np.random.default_rng(seed)
    noise_amp = 10.0 ** (noise_db / 20.0)
    iq = (
        rng.normal(0.0, noise_amp / np.sqrt(2.0), n_samples)
        + 1j * rng.normal(0.0, noise_amp / np.sqrt(2.0), n_samples)
    ).astype(np.complex64)

    if tones_hz:
        tone_amp = 10.0 ** (tone_db / 20.0)
        t = np.arange(n_samples, dtype=np.float64) / float(segment.sample_rate_hz)
        for tone_hz in tones_hz:
            # Convert absolute frequency to baseband offset from the tuner center.
            offset = float(tone_hz) - float(segment.center_hz)
            iq += (tone_amp * np.exp(2j * np.pi * offset * t)).astype(np.complex64)

    return iq
