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
#   Owns the HackRF. Enumerates devices, applies the three stage gain profile,
#   selects the baseband filter, and runs the sweep loop that walks the segment
#   plan produced by band_plan, retuning and capturing one IQ block per dwell.
#
#   This layer targets libhackrf directly through python_hackrf rather than going
#   through a generic multi vendor abstraction. The platform is HackRF only, so an
#   abstraction over hardware that is never attached costs a system dependency
#   with nothing bought in return, and it hides the firmware sweep mode that only
#   the native library exposes.
#
#   libhackrf is callback driven. A USB transfer thread inside the library hands
#   up buffers of interleaved signed 8 bit samples whenever they arrive, which
#   does not match the blocking read the sweep loop wants. The gap is bridged with
#   a bounded queue of raw transfers and a condition variable, so the sweep loop
#   keeps its simple sequential shape while the library keeps its callback. Sample
#   conversion is deliberately deferred out of the callback, because that callback
#   runs on the USB transfer thread and any time spent there is time not spent
#   servicing the next transfer, which shows up as dropped samples.
#
#   The queue drops the oldest transfer under backpressure rather than growing.
#   For a live monitoring display a stale sample block has no value, and an
#   unbounded queue converts a transient stall into permanent latency and
#   eventually exhausts memory.
#
#   Hardware faults are expected rather than exceptional. A USB disconnect mid
#   engagement, a stalled transfer thread, and a read timeout are all handled
#   without terminating the sweep. Lost samples are counted and passed downstream
#   so the detector knows a frame is time discontinuous and does not treat it as a
#   clean consecutive observation.
#
#   A synthetic source implementing the same interface is provided so that the
#   DSP, detector, and UI layers can be exercised with no radio attached and with
#   signals of known frequency and level.
#
#   Frequency correction is applied here, at the point of tuning. The commanded
#   frequency is scaled by the measured oscillator error so the local oscillator
#   lands where it was asked to, while frame metadata continues to report the
#   intended frequency. Correcting at the tuner keeps the correction invisible to
#   the DSP, the detector, the display, and saved markers.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. This module is receive only. It never
#   calls any transmit function of the underlying library, never enables the
#   transmit amplifier, and never enables the antenna port bias tee. It does not
#   demodulate or record communications content. Operators remain responsible for
#   confirming that the frequencies swept fall inside the authorized scope for the
#   engagement and jurisdiction.
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
from collections import deque
from dataclasses import dataclass
from typing import Callable, List, Optional

import numpy as np

import band_plan
from dsp_psd import synthetic_iq

LOG = logging.getLogger(__name__)

# Imported lazily so this module can be imported, tested, and run against the
# synthetic source on a host with no HackRF runtime present.
try:
    from python_hackrf import pyhackrf
    HACKRF_AVAILABLE = True
except ImportError:
    pyhackrf = None
    HACKRF_AVAILABLE = False

# Samples arrive as interleaved signed 8 bit values. Full scale is 127, so the
# reciprocal of 128 maps the converter range onto plus or minus one and keeps the
# dBFS scale in dsp_psd meaningful.
SAMPLE_SCALE = 1.0 / 128.0

# Discrete baseband filter bandwidths of the MAX2837, in Hz. The filter cannot be
# set to an arbitrary value, so the usable fraction of any segment is decided by
# which of these steps is available rather than by preference.
MAX2837_FILTER_HZ = (
    1_750_000, 2_500_000, 3_500_000, 5_000_000, 5_500_000, 6_000_000,
    7_000_000, 8_000_000, 9_000_000, 10_000_000, 12_000_000, 14_000_000,
    15_000_000, 20_000_000, 24_000_000, 28_000_000,
)

# Transfers retained before the oldest is discarded. One transfer at 20 MS/s is
# roughly 131072 samples, so this is about a tenth of a second of history, far
# more than any single dwell needs and small enough to bound memory.
MAX_QUEUED_TRANSFERS = 16

# How long a blocking read waits for the callback to deliver enough samples. Long
# enough to cover a dwell at the slowest sample rate, short enough that a wedged
# device is noticed within a fraction of a second.
READ_TIMEOUT_S = 1.0

# Reconnect backoff bounds after a device fault, in seconds.
RECONNECT_MIN_S = 1.0
RECONNECT_MAX_S = 15.0

# Guards the library wide init and exit calls, which are global rather than per
# device and must not be re-entered from several threads.
_LIB_LOCK = threading.Lock()
_LIB_REFCOUNT = 0


class DeviceError(Exception):
    """Raised for any fault that requires tearing down and reopening the device."""


def _library_acquire() -> None:
    """Initialize the library on first use, reference counted."""
    global _LIB_REFCOUNT
    with _LIB_LOCK:
        if _LIB_REFCOUNT == 0:
            pyhackrf.pyhackrf_init()
        _LIB_REFCOUNT += 1


def _library_release() -> None:
    """Shut the library down once the last device has closed."""
    global _LIB_REFCOUNT
    with _LIB_LOCK:
        _LIB_REFCOUNT = max(0, _LIB_REFCOUNT - 1)
        if _LIB_REFCOUNT == 0:
            try:
                pyhackrf.pyhackrf_exit()
            except Exception as exc:
                LOG.debug("library exit raised: %s", exc)


def select_baseband_filter(sample_rate_hz: int, usable_fraction: float) -> int:
    """Choose the narrowest filter step that still passes the usable window.

    The filter has to be at least as wide as the portion of the segment actually
    kept, or the outermost bins sit in the filter skirt and read low, which the
    detector would see as a level step at every segment boundary. Among the steps
    that satisfy that, the narrowest is taken, since anything wider admits energy
    from outside the segment that aliases back into it.
    """
    required = sample_rate_hz * usable_fraction
    for candidate in MAX2837_FILTER_HZ:
        if candidate >= required:
            return candidate
    return MAX2837_FILTER_HZ[-1]


@dataclass
class GainProfile:
    """Three stage HackRF receive gain.

    The HackRF exposes three independent stages rather than a single gain figure.
    Defaults start conservative because the converter is only 8 bits, giving
    roughly 48 dB of usable dynamic range in one capture. Too much gain saturates
    the converter on the strongest emitter in the segment and lifts the apparent
    noise floor across every bin in that segment, which reads as a wideband burst
    and hides everything weak. Too little leaves the noise floor below the least
    significant bit and wastes sensitivity.

    amp_db: front end amplifier, 0 or 14 only. Off by default. It overloads
        readily in dense RF and the damage to segment wide dynamic range usually
        outweighs the sensitivity it buys.
    lna_db: intermediate frequency gain, 0 to 40 in 8 dB steps.
    vga_db: baseband gain, 0 to 62 in 2 dB steps.
    """

    amp_db: int = 0
    lna_db: int = 16
    vga_db: int = 20

    def clamp(self) -> "GainProfile":
        """Snap values to what the hardware actually accepts.

        Silently accepting an out of range or off step value produces a device set
        to something other than what the operator sees on screen, and every level
        reading afterwards is quietly wrong.
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


def enumerate_devices() -> List[dict]:
    """List attached HackRFs. Empty when no runtime or no hardware is present."""
    if not HACKRF_AVAILABLE:
        LOG.warning("python_hackrf not installed, no devices can be enumerated")
        return []
    try:
        _library_acquire()
        try:
            listing = pyhackrf.PyHackRFDeviceList()
            devices = []
            for index in range(listing.device_count):
                devices.append({
                    "index": index,
                    "driver": "hackrf",
                    "serial": listing.serial_numbers[index],
                    "board": listing.pyhackrf_board_id_name(index),
                })
            return devices
        finally:
            _library_release()
    except Exception as exc:
        LOG.error("device enumeration failed: %s", exc)
        return []


class HackRFSource:
    """One HackRF, presenting a blocking read over the library's callback stream.

    Deliberately narrow. It knows how to configure and read the device and nothing
    about sweeping, DSP, or detection, so the synthetic and replay sources can
    substitute for it by implementing the same handful of methods.
    """

    def __init__(self, serial: Optional[str] = None, gain: Optional[GainProfile] = None,
                 usable_fraction: float = band_plan.USABLE_FRACTION):
        if not HACKRF_AVAILABLE:
            raise DeviceError(
                "python_hackrf is not installed. Install it with "
                "'pip install python-hackrf', which needs the HackRF host "
                "software and its headers present, or run with --synthetic."
            )
        self.serial = serial
        self.gain = (gain or GainProfile()).clamp()
        self.usable_fraction = float(usable_fraction)

        self._device = None
        self._acquired = False
        self._streaming = False
        self._sample_rate = None
        self._center_hz = None

        # Raw int8 transfers awaiting conversion, oldest first.
        self._chunks = deque()
        self._available = 0
        self._lost_samples = 0
        self._condition = threading.Condition()

    def open(self) -> None:
        """Open the device, apply configuration, and start the receive stream."""
        try:
            _library_acquire()
            self._acquired = True

            if self.serial:
                self._device = pyhackrf.pyhackrf_open_by_serial(self.serial)
            else:
                self._device = pyhackrf.pyhackrf_open()

            if self._device is None:
                raise DeviceError("no HackRF could be opened")

            self._device.set_rx_callback(self._rx_callback)
            self.apply_gain(self.gain)

            # Explicitly off. Neither is needed for passive monitoring, and the
            # bias tee will feed 3.3 V into whatever is connected to the antenna
            # port, which can damage a passive antenna or a splitter.
            self._device.pyhackrf_set_antenna_enable(False)

        except DeviceError:
            self.close()
            raise
        except Exception as exc:
            self.close()
            raise DeviceError("failed to open HackRF: {0}".format(exc)) from exc

        LOG.info("HackRF opened, serial %s, gain %s",
                 self.serial or "first available", self.gain.to_dict())

    def close(self) -> None:
        """Stop streaming and release the device, tolerating a partial open."""
        if self._device is not None:
            try:
                if self._streaming:
                    self._device.pyhackrf_stop_rx()
            except Exception as exc:
                LOG.debug("stop_rx raised during close: %s", exc)
            try:
                self._device.pyhackrf_close()
            except Exception as exc:
                LOG.debug("close raised during close: %s", exc)

        self._device = None
        self._streaming = False
        self._sample_rate = None
        self._center_hz = None
        self._flush()

        if self._acquired:
            _library_release()
            self._acquired = False

    def _rx_callback(self, device, buffer, buffer_length, valid_length) -> int:
        """Receive one USB transfer. Runs on the library's transfer thread.

        Kept as short as possible. The buffer is copied and queued raw, with the
        conversion to complex baseband deferred to the consumer, because every
        microsecond spent here is a microsecond not spent servicing the next
        transfer and shows up downstream as lost samples.

        Returning zero asks the library to keep calling. Any other value stops the
        stream, so this must return zero on every path including error paths.
        """
        try:
            valid = int(valid_length)
            if valid <= 0:
                return 0

            # Copy before returning. The library reuses the underlying buffer for
            # the next transfer, so a retained reference would be overwritten
            # under the consumer.
            chunk = np.array(buffer[:valid], dtype=np.int8)

            with self._condition:
                self._chunks.append(chunk)
                self._available += chunk.size // 2

                # Drop oldest under backpressure. The newest transfer is the one
                # the display wants, and preferentially keeping stale data would
                # make the display lag further behind the busier the host gets.
                while len(self._chunks) > MAX_QUEUED_TRANSFERS:
                    stale = self._chunks.popleft()
                    lost = stale.size // 2
                    self._available -= lost
                    self._lost_samples += lost

                self._condition.notify_all()
        except Exception as exc:
            LOG.error("receive callback failed: %s", exc)
        return 0

    def _flush(self) -> None:
        """Discard queued transfers. Called after any retune.

        Everything queued was captured at the previous tuning, so serving it after
        a retune would attribute samples from one frequency to another.
        """
        with self._condition:
            self._chunks.clear()
            self._available = 0

    def apply_gain(self, gain: GainProfile) -> None:
        """Set all three receive gain stages."""
        self.gain = gain.clamp()
        if self._device is None:
            return
        try:
            self._device.pyhackrf_set_amp_enable(bool(self.gain.amp_db))
            self._device.pyhackrf_set_lna_gain(int(self.gain.lna_db))
            self._device.pyhackrf_set_vga_gain(int(self.gain.vga_db))
        except Exception as exc:
            raise DeviceError("failed to set gain: {0}".format(exc)) from exc

    def tune(self, center_hz: int, sample_rate_hz: int) -> None:
        """Retune, adjusting sample rate and baseband filter only when they change.

        Setting the sample rate reconfigures the baseband filter inside the
        transceiver and costs far more than a frequency change alone. The planner
        groups segments by band, so the rate usually holds across several
        consecutive dwells and this check skips most of that cost.
        """
        if self._device is None:
            raise DeviceError("tune called before device was opened")

        try:
            if sample_rate_hz != self._sample_rate:
                self._device.pyhackrf_set_sample_rate(float(sample_rate_hz))
                # Applied after the sample rate, because setting the rate also
                # sets the filter and would otherwise overwrite this.
                self._device.pyhackrf_set_baseband_filter_bandwidth(
                    select_baseband_filter(sample_rate_hz, self.usable_fraction)
                )
                self._sample_rate = sample_rate_hz

            if center_hz != self._center_hz:
                self._device.pyhackrf_set_freq(int(center_hz))
                self._center_hz = center_hz

            if not self._streaming:
                self._device.pyhackrf_start_rx()
                self._streaming = True
        except Exception as exc:
            raise DeviceError("failed to tune to {0} Hz: {1}".format(center_hz, exc)) from exc

        self._flush()

    def read(self, n_samples: int) -> tuple:
        """Block until n_samples of complex baseband are available.

        Returns the samples and the count of transfers lost to backpressure since
        the last read, which the detector uses to recognise a frame as time
        discontinuous rather than as a clean consecutive observation.
        """
        if self._device is None:
            raise DeviceError("read called before device was opened")

        deadline = time.monotonic() + READ_TIMEOUT_S
        needed_values = int(n_samples) * 2

        with self._condition:
            while self._available < n_samples:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DeviceError(
                        "no samples for {0:.1f} s, device considered lost".format(READ_TIMEOUT_S)
                    )
                self._condition.wait(timeout=remaining)

            collected = []
            gathered = 0
            while gathered < needed_values:
                chunk = self._chunks.popleft()
                if gathered + chunk.size <= needed_values:
                    collected.append(chunk)
                    gathered += chunk.size
                else:
                    take = needed_values - gathered
                    collected.append(chunk[:take])
                    # Return the unconsumed tail so no samples are silently lost
                    # between reads.
                    self._chunks.appendleft(chunk[take:])
                    gathered = needed_values

            self._available -= n_samples
            lost = self._lost_samples
            self._lost_samples = 0

        raw = collected[0] if len(collected) == 1 else np.concatenate(collected)

        # Conversion happens here, on the consumer thread, rather than in the
        # callback. Scaling into float32 first and assigning the real and
        # imaginary parts avoids building an intermediate complex temporary.
        scaled = raw.astype(np.float32)
        scaled *= SAMPLE_SCALE
        iq = np.empty(n_samples, dtype=np.complex64)
        iq.real = scaled[0::2]
        iq.imag = scaled[1::2]

        # Lost samples are reported as an overrun count, one per transfer sized
        # gap, which is what the detector's discontinuity flag expects.
        return iq, (1 if lost else 0)

    def clock_status(self) -> dict:
        """Report external reference detection, for the dual radio clock chain.

        Not used by the single radio analyzer. Present because the second HackRF
        will be slaved to this one's clock output, and confirming the reference is
        actually detected is the difference between two radios sharing a timebase
        and two radios silently drifting apart.
        """
        if self._device is None:
            return {"clkin_detected": False, "available": False}
        try:
            return {
                "clkin_detected": bool(self._device.pyhackrf_get_clkin_status()),
                "available": True,
            }
        except Exception as exc:
            LOG.debug("clock status unavailable: %s", exc)
            return {"clkin_detected": False, "available": False}


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

        # Keep only tones inside this segment. A tone outside the tuned window
        # would alias into it and appear at a frequency no real receiver would
        # report.
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
        device is not safe for concurrent access and a gain write racing a
        transfer produces a library level fault rather than a clean exception.
        """
        self._pending_gain = gain.clamp()

    def set_ppm(self, ppm: float) -> None:
        """Apply a measured oscillator correction to all subsequent tuning.

        Read by the sweep thread on the next dwell rather than applied to the
        device immediately, so no device access races an in flight transfer. A
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
        """Enqueue a block, dropping the oldest under backpressure."""
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

            # Exponential backoff on reconnect. A device physically unplugged
            # fails immediately and repeatedly, and hammering the USB subsystem in
            # a tight loop makes the host less likely to enumerate it cleanly when
            # it comes back.
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
                # No bands selected. Idle rather than spinning, and stay
                # responsive to a plan change arriving from the UI.
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

        The commanded frequency carries the oscillator correction while the segment
        handed downstream carries the intended frequency, so everything after this
        point works in true frequency without knowing a correction was applied.
        """
        commanded_hz = int(round(segment.center_hz * (1.0 - self.ppm_correction * 1e-6)))
        self.source.tune(commanded_hz, segment.sample_rate_hz)
        if hasattr(self.source, "set_segment"):
            self.source.set_segment(segment)

        # Samples taken during synthesizer settle contain a frequency sweep
        # artifact that smears across the whole span and reads as broadband
        # energy. They are read and thrown away rather than skipped, because the
        # stream is free running and leaving them queued would contaminate the
        # following dwell.
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

        # Recorded before publication so the recording is a faithful copy of what
        # the detector received, including any block later dropped by the queue
        # under backpressure.
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
