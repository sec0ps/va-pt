#!/usr/bin/env python3
# =============================================================================
# Location: sdr_capture.py
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
#   Owns the physical SDR. Enumerates devices, applies a three stage gain
#   profile, and runs the sweep loop that walks the segment plan produced by
#   band_plan, retuning and capturing one IQ block per segment dwell.
#
#   The sweep loop is the only component that touches the device, and it runs on
#   its own thread. Captured blocks are handed to a consumer through a bounded
#   queue with an explicit drop policy. Under a slow consumer the queue drops the
#   oldest frame rather than growing, because in a real time monitoring display a
#   stale frame has no value and an unbounded queue converts a transient
#   slowdown into permanent latency and eventual memory exhaustion.
#
#   Hardware faults are expected rather than exceptional. A USB disconnect mid
#   engagement, a stream overrun under CPU contention, and a read timeout are all
#   handled without terminating the sweep. Overruns are counted and passed
#   downstream so that the detector knows a frame is time discontinuous and does
#   not treat it as a clean consecutive observation.
#
#   A synthetic source implementing the same interface is provided so that the
#   DSP, detector, transport, and UI layers can be exercised and regression
#   tested with no radio attached and with signals of known frequency and level.
#
#   Frequency correction is applied here, at the point of tuning, rather than
#   anywhere downstream. The commanded frequency is scaled by the measured
#   oscillator error so that the local oscillator lands where it was asked to,
#   while frame metadata continues to report the intended frequency. Correcting at
#   the tuner keeps the correction invisible to the DSP, the detector, the
#   display, and saved markers, none of which need to know it happened.
#
#   Recording is optional and off by default. When enabled, every capture block is
#   appended to a replayable container before being published, so that a detector
#   change can later be evaluated against the real RF environment of a site rather
#   than against synthetic tones.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. This module is receive only. It does
#   not configure, enable, or expose any transmit path on the device, and it does
#   not demodulate or record communications content. Operators remain responsible
#   for confirming that the frequencies swept fall inside the authorized scope
#   for the engagement and jurisdiction.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""HackRF device management, swept capture engine, and synthetic test source."""

import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

import numpy as np

import band_plan
from dsp_psd import synthetic_iq

LOG = logging.getLogger(__name__)

# SoapySDR is imported lazily so that this module can be imported, tested, and
# run against the synthetic source on a host with no SDR runtime installed.
try:
    import SoapySDR
    from SoapySDR import SOAPY_SDR_RX, SOAPY_SDR_CF32, SOAPY_SDR_OVERFLOW, SOAPY_SDR_TIMEOUT
    SOAPY_AVAILABLE = True
except ImportError:
    SoapySDR = None
    SOAPY_SDR_RX = 0
    SOAPY_SDR_CF32 = "CF32"
    SOAPY_SDR_OVERFLOW = -4
    SOAPY_SDR_TIMEOUT = -1
    SOAPY_AVAILABLE = False

# Stream read timeout. Long enough to cover a dwell at the slowest sample rate,
# short enough that a wedged device is noticed within a fraction of a second.
READ_TIMEOUT_US = 500_000

# Reconnect backoff bounds after a device fault, in seconds.
RECONNECT_MIN_S = 1.0
RECONNECT_MAX_S = 15.0

# Consecutive read failures tolerated before the device is torn down and
# reopened. A single overrun is routine, a sustained run of them is a symptom.
MAX_CONSECUTIVE_FAULTS = 20


@dataclass
class GainProfile:
    """Three stage HackRF receive gain.

    The HackRF exposes three independent stages rather than a single gain figure.
    Defaults here start conservative because the converter is only 8 bits, which
    gives roughly 48 dB of usable dynamic range in one capture. Too much gain
    saturates the converter on the strongest emitter in the segment and raises the
    apparent noise floor across every bin in that segment, which reads as a
    wideband burst and hides everything weak. Too little gain leaves the noise
    floor below the converter least significant bit and wastes sensitivity.

    amp_db: front end amplifier, 0 or 14 only. Off by default. It overloads
        readily in dense RF and its damage to segment wide dynamic range usually
        outweighs the sensitivity it buys.
    lna_db: intermediate frequency gain, 0 to 40 in 8 dB steps.
    vga_db: baseband gain, 0 to 62 in 2 dB steps.
    """

    amp_db: int = 0
    lna_db: int = 16
    vga_db: int = 20

    def clamp(self) -> "GainProfile":
        """Snap values to what the hardware actually accepts.

        Silently accepting an out of range or off step value produces a device
        that is set to something other than what the operator sees on screen, and
        every level reading afterwards is quietly wrong.
        """
        amp = 14 if self.amp_db >= 7 else 0
        lna = int(round(max(0, min(40, self.lna_db)) / 8.0)) * 8
        vga = int(round(max(0, min(62, self.vga_db)) / 2.0)) * 2
        return GainProfile(amp_db=amp, lna_db=lna, vga_db=vga)

    def to_dict(self) -> dict:
        return {"amp_db": self.amp_db, "lna_db": self.lna_db, "vga_db": self.vga_db}

    @property
    def total_db(self) -> int:
        """Sum of all stages, for display and for floor shift bookkeeping."""
        return self.amp_db + self.lna_db + self.vga_db


@dataclass
class CaptureBlock:
    """One segment dwell of IQ with the context needed to interpret it."""

    segment: band_plan.Segment
    iq: np.ndarray
    timestamp: float
    overruns: int = 0
    sweep_index: int = 0


class DeviceError(Exception):
    """Raised for any fault that requires tearing down and reopening the device."""


def enumerate_devices() -> List[dict]:
    """List attached SDRs. Returns an empty list when no SDR runtime is present."""
    if not SOAPY_AVAILABLE:
        LOG.warning("SoapySDR not installed, no hardware devices can be enumerated")
        return []
    try:
        return [dict(result) for result in SoapySDR.Device.enumerate()]
    except Exception as exc:
        LOG.error("device enumeration failed: %s", exc)
        return []


class HackRFSource:
    """Thin wrapper over one HackRF, exposing tune, gain, and read.

    Kept deliberately narrow. It knows how to configure and read the device and
    nothing about sweeping, DSP, or detection, so that the synthetic source can
    substitute for it by implementing the same four methods.
    """

    def __init__(self, serial: Optional[str] = None, gain: Optional[GainProfile] = None):
        if not SOAPY_AVAILABLE:
            raise DeviceError(
                "SoapySDR is not installed. Install the SoapySDR Python bindings "
                "and the SoapyHackRF module, or run with the synthetic source."
            )
        self.serial = serial
        self.gain = (gain or GainProfile()).clamp()
        self._device = None
        self._stream = None
        self._sample_rate = None
        self._center_hz = None

    def open(self) -> None:
        """Open the device and activate the receive stream."""
        args = {"driver": "hackrf"}
        if self.serial:
            args["serial"] = self.serial
        try:
            self._device = SoapySDR.Device(args)
            self._stream = self._device.setupStream(SOAPY_SDR_RX, SOAPY_SDR_CF32)
            self._device.activateStream(self._stream)
        except Exception as exc:
            self.close()
            raise DeviceError("failed to open HackRF: {0}".format(exc)) from exc
        self.apply_gain(self.gain)
        LOG.info("HackRF opened, serial %s, gain %s", self.serial or "any", self.gain.to_dict())

    def close(self) -> None:
        """Tear down stream and device, tolerating a partially open state."""
        if self._device is not None and self._stream is not None:
            try:
                self._device.deactivateStream(self._stream)
                self._device.closeStream(self._stream)
            except Exception as exc:
                LOG.debug("stream teardown raised during close: %s", exc)
        self._stream = None
        self._device = None
        self._sample_rate = None
        self._center_hz = None

    def apply_gain(self, gain: GainProfile) -> None:
        """Set all three gain stages by name."""
        self.gain = gain.clamp()
        if self._device is None:
            return
        try:
            self._device.setGain(SOAPY_SDR_RX, 0, "AMP", float(self.gain.amp_db))
            self._device.setGain(SOAPY_SDR_RX, 0, "LNA", float(self.gain.lna_db))
            self._device.setGain(SOAPY_SDR_RX, 0, "VGA", float(self.gain.vga_db))
        except Exception as exc:
            raise DeviceError("failed to set gain: {0}".format(exc)) from exc

    def tune(self, center_hz: int, sample_rate_hz: int) -> None:
        """Retune and set sample rate, skipping calls that would be no ops.

        Sample rate is only reapplied when it actually changes. Setting it forces
        a filter reconfiguration inside the device that costs far more than a
        frequency change alone, and the planner groups segments by band so the
        rate usually holds across several consecutive dwells.
        """
        if self._device is None:
            raise DeviceError("tune called before device was opened")
        try:
            if sample_rate_hz != self._sample_rate:
                self._device.setSampleRate(SOAPY_SDR_RX, 0, float(sample_rate_hz))
                # Baseband filter set to the sample rate. Narrower would cut into
                # the usable window the planner already accounted for, wider would
                # alias energy from outside the segment into it.
                self._device.setBandwidth(SOAPY_SDR_RX, 0, float(sample_rate_hz))
                self._sample_rate = sample_rate_hz
            if center_hz != self._center_hz:
                self._device.setFrequency(SOAPY_SDR_RX, 0, float(center_hz))
                self._center_hz = center_hz
        except Exception as exc:
            raise DeviceError("failed to tune to {0} Hz: {1}".format(center_hz, exc)) from exc

    def read(self, n_samples: int) -> tuple:
        """Read exactly n_samples of complex baseband, returning (iq, overruns).

        readStream returns short reads routinely, so the loop accumulates until
        the request is satisfied. An overflow return code means the device
        produced samples faster than they were consumed and the driver discarded
        some. The already read portion stays valid, so the count is recorded and
        reading continues rather than discarding the whole dwell.
        """
        if self._device is None or self._stream is None:
            raise DeviceError("read called before device was opened")

        out = np.empty(n_samples, dtype=np.complex64)
        filled = 0
        overruns = 0
        faults = 0

        while filled < n_samples:
            chunk = out[filled:]
            try:
                status = self._device.readStream(self._stream, [chunk], chunk.size, timeoutUs=READ_TIMEOUT_US)
            except Exception as exc:
                raise DeviceError("readStream raised: {0}".format(exc)) from exc

            count = status.ret
            if count > 0:
                filled += count
                faults = 0
                continue

            if count == SOAPY_SDR_OVERFLOW:
                overruns += 1
                faults += 1
            elif count == SOAPY_SDR_TIMEOUT:
                faults += 1
                LOG.debug("stream read timeout at %s Hz", self._center_hz)
            else:
                faults += 1
                LOG.warning("stream read returned %s", count)

            if faults >= MAX_CONSECUTIVE_FAULTS:
                raise DeviceError(
                    "{0} consecutive stream faults, device considered lost".format(faults)
                )

        return out, overruns


class SyntheticSource:
    """Drop in replacement for HackRFSource that fabricates IQ with known tones.

    Exists so the whole chain above the radio can be tested deterministically. A
    tone placed at a known absolute frequency should be reported by the detector
    at that same frequency, which validates the bin to frequency mapping through
    the usable window trim and the segment center offset. That mapping is where
    off by one errors hide, and they are invisible on live spectrum because
    nothing on air announces its exact frequency.
    """

    def __init__(self, tones_hz: tuple = (), gain: Optional[GainProfile] = None,
                 burst_period_s: float = 0.0, burst_duty: float = 0.5, seed: int = 0):
        self.tones_hz = tuple(tones_hz)
        self.gain = (gain or GainProfile()).clamp()
        self.burst_period_s = float(burst_period_s)
        self.burst_duty = float(burst_duty)
        self._seed_counter = int(seed)
        self._segment = None
        self._t0 = time.time()

    def open(self) -> None:
        self._t0 = time.time()
        LOG.info("synthetic source active, tones %s", self.tones_hz)

    def close(self) -> None:
        pass

    def apply_gain(self, gain: GainProfile) -> None:
        self.gain = gain.clamp()

    def tune(self, center_hz: int, sample_rate_hz: int) -> None:
        self._pending = (center_hz, sample_rate_hz)

    def set_segment(self, segment) -> None:
        """Supplied by the sweep engine so tones can be placed in the right span."""
        self._segment = segment

    def read(self, n_samples: int) -> tuple:
        if self._segment is None:
            raise DeviceError("synthetic source read before a segment was set")

        # Keep only tones that fall inside this segment, since a tone outside the
        # tuned window would alias into it and produce a signal at a frequency
        # that no real receiver would report.
        in_band = tuple(
            f for f in self.tones_hz
            if self._segment.usable_start_hz <= f <= self._segment.usable_stop_hz
        )

        # Optional on off keying so the burst detector lifecycle can be exercised
        # against a signal with a known duty cycle.
        if self.burst_period_s > 0.0 and in_band:
            phase = ((time.time() - self._t0) % self.burst_period_s) / self.burst_period_s
            if phase > self.burst_duty:
                in_band = ()

        self._seed_counter += 1
        iq = synthetic_iq(
            self._segment,
            n_samples,
            tones_hz=in_band,
            tone_db=-30.0,
            noise_db=-75.0,
            seed=self._seed_counter,
        )
        return iq, 0


class SweepEngine:
    """Walks a segment plan on a dedicated thread and emits capture blocks.

    Owns the device lifecycle including reconnection. The consumer sees a queue of
    capture blocks and never touches the radio, which keeps device faults from
    propagating into the DSP and transport layers as anything other than a gap in
    frames.
    """

    def __init__(
        self,
        source,
        segments: List[band_plan.Segment],
        queue_depth: int = 8,
        on_status: Optional[Callable[[dict], None]] = None,
        ppm_correction: float = 0.0,
        recorder=None,
    ):
        self.source = source
        self._segments = list(segments)
        self.queue: "queue.Queue[CaptureBlock]" = queue.Queue(maxsize=queue_depth)
        self.on_status = on_status
        self.ppm_correction = float(ppm_correction)
        self.recorder = recorder

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._plan_lock = threading.Lock()
        self._plan_dirty = threading.Event()
        self._pending_gain: Optional[GainProfile] = None

        self.dropped_frames = 0
        self.total_overruns = 0
        self.sweep_count = 0
        self.connected = False

    def start(self) -> None:
        """Launch the sweep thread. Idempotent."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="sweep", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the sweep thread to exit and wait for the device to release."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def set_segments(self, segments: List[band_plan.Segment]) -> None:
        """Swap the band plan without restarting the thread or the device."""
        with self._plan_lock:
            self._segments = list(segments)
        self._plan_dirty.set()

    def set_gain(self, gain: GainProfile) -> None:
        """Queue a gain change to be applied by the sweep thread.

        Applied on the sweep thread rather than the caller thread because the
        device is not safe for concurrent access and a gain write racing a stream
        read produces a driver level fault rather than a clean exception.
        """
        self._pending_gain = gain.clamp()

    def set_ppm(self, ppm: float) -> None:
        """Apply a measured oscillator correction to all subsequent tuning.

        Read by the sweep thread on the next dwell rather than applied to the
        device immediately, so no device access races an in flight stream read. A
        float assignment is atomic under the interpreter lock, so no additional
        synchronisation is required for a single scalar.
        """
        self.ppm_correction = float(ppm)

    def set_recorder(self, recorder) -> None:
        """Attach or detach an IQ recorder. Pass None to stop recording."""
        self.recorder = recorder

    def _status(self, **fields) -> None:
        if self.on_status is None:
            return
        try:
            self.on_status(fields)
        except Exception as exc:
            LOG.debug("status callback raised: %s", exc)

    def _emit(self, block: CaptureBlock) -> None:
        """Enqueue a block, dropping the oldest under backpressure.

        Dropping the oldest rather than the newest is correct for a live display.
        The newest frame is the one the operator wants to see, and a queue that
        preferentially retains stale frames shows a display that lags further
        behind real time the busier the machine gets.
        """
        try:
            self.queue.put_nowait(block)
        except queue.Full:
            try:
                self.queue.get_nowait()
                self.dropped_frames += 1
            except queue.Empty:
                pass
            try:
                self.queue.put_nowait(block)
            except queue.Full:
                self.dropped_frames += 1

    def _run(self) -> None:
        """Sweep thread body. Owns open, reconnect, and the segment walk."""
        backoff = RECONNECT_MIN_S

        while not self._stop.is_set():
            try:
                self.source.open()
                self.connected = True
                backoff = RECONNECT_MIN_S
                self._status(connected=True, message="device open")
                self._sweep_forever()
            except DeviceError as exc:
                self.connected = False
                LOG.error("device fault: %s", exc)
                self._status(connected=False, message=str(exc))
            except Exception as exc:
                self.connected = False
                LOG.exception("unexpected sweep failure")
                self._status(connected=False, message="unexpected failure: {0}".format(exc))
            finally:
                try:
                    self.source.close()
                except Exception as exc:
                    LOG.debug("close raised during fault recovery: %s", exc)
                self.connected = False

            if self._stop.is_set():
                break

            # Exponential backoff on reconnect. A device that was physically
            # unplugged will fail immediately and repeatedly, and hammering the
            # USB subsystem in a tight loop makes the host less likely to
            # enumerate it cleanly when it comes back.
            LOG.info("reconnecting in %.1f s", backoff)
            if self._stop.wait(backoff):
                break
            backoff = min(backoff * 2.0, RECONNECT_MAX_S)

    def _sweep_forever(self) -> None:
        """Walk the plan repeatedly until stopped or the device faults."""
        while not self._stop.is_set():
            with self._plan_lock:
                segments = list(self._segments)
            self._plan_dirty.clear()

            if not segments:
                # No bands selected. Idle rather than spinning, and stay responsive
                # to a plan change arriving from the UI.
                if self._stop.wait(0.25):
                    return
                continue

            for segment in segments:
                if self._stop.is_set() or self._plan_dirty.is_set():
                    break

                if self._pending_gain is not None:
                    self.source.apply_gain(self._pending_gain)
                    self._status(gain=self._pending_gain.to_dict(), gain_changed=True)
                    self._pending_gain = None

                self._dwell(segment)

            self.sweep_count += 1

    def _dwell(self, segment: band_plan.Segment) -> None:
        """Tune to one segment, discard settle samples, capture, and emit.

        The commanded frequency carries the oscillator correction, while the
        segment handed downstream carries the intended frequency. Everything after
        this point therefore works in true frequency without knowing a correction
        was applied.
        """
        commanded_hz = int(round(segment.center_hz * (1.0 - self.ppm_correction * 1e-6)))
        self.source.tune(commanded_hz, segment.sample_rate_hz)
        if hasattr(self.source, "set_segment"):
            self.source.set_segment(segment)

        # Samples taken during PLL settle contain a frequency sweep artifact that
        # smears across the whole span and reads as broadband energy. They are
        # read and thrown away rather than skipped, because the stream is free
        # running and not reading them would leave them in the buffer to
        # contaminate the following dwell.
        settle_samples = int(band_plan.DEFAULT_SETTLE_MS * segment.sample_rate_hz / 1000.0)
        overruns = 0
        if settle_samples > 0:
            _, settle_overruns = self.source.read(settle_samples)
            overruns += settle_overruns

        needed = segment.fft_size * segment.averages
        iq, read_overruns = self.source.read(needed)
        overruns += read_overruns
        self.total_overruns += overruns

        block = CaptureBlock(
            segment=segment,
            iq=iq,
            timestamp=time.time(),
            overruns=overruns,
            sweep_index=self.sweep_count,
        )

        # Recorded before publication so that the recording is a faithful copy of
        # what the detector received, including any block later dropped by the
        # queue under backpressure.
        if self.recorder is not None:
            try:
                if not self.recorder.write(block):
                    self.recorder = None
                    self._status(recording=False, message="IQ recording stopped")
            except Exception as exc:
                LOG.error("IQ recording failed, continuing without it: %s", exc)
                self.recorder = None

        self._emit(block)

    def stats(self) -> dict:
        """Counters for the operator health display."""
        return {
            "connected": self.connected,
            "sweeps": self.sweep_count,
            "dropped_frames": self.dropped_frames,
            "overruns": self.total_overruns,
            "queue_depth": self.queue.qsize(),
            "segments": len(self._segments),
            "ppm": round(self.ppm_correction, 3),
            "recording": self.recorder is not None,
        }
