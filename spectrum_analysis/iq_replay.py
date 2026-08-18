#!/usr/bin/env python3
# =============================================================================
# Location: iq_replay.py
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
#   Records raw IQ from a live sweep and replays it later through the same
#   interface the radio presents, so that a detector change can be evaluated
#   against real spectrum rather than against synthetic tones.
#
#   This closes the loop that synthetic testing cannot. Synthetic IQ proves the
#   detector behaves correctly against noise and clean carriers of known
#   frequency. It says nothing about how the detector behaves against the actual
#   RF environment of a site, where the interference, the multipath, the adjacent
#   channel splatter, and the intermittent emitters are what generate false
#   positives. A recording taken once on site becomes a fixed regression case
#   that every subsequent threshold change is measured against.
#
#   Raw IQ is expensive. A two segment plan at the default settings produces
#   roughly 28 MB per second, so a minute of capture is about 1.7 GB. The recorder
#   therefore enforces a size ceiling and stops cleanly on reaching it, rather
#   than filling the disk underneath a running engagement.
#
#   The container is a JSON header followed by length prefixed blocks. It is
#   deliberately plain rather than a standard interchange format, because the
#   segment plan, sample rate per segment, and overrun flags all have to survive
#   the round trip for a replay to reproduce the original detector input exactly,
#   and a generic single rate IQ container cannot carry them.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. A raw IQ recording preserves the
#   complete received signal across the recorded span, including the modulated
#   content of every transmission present, and is therefore materially more
#   sensitive than the energy detection metadata the rest of this platform
#   produces. Recording is off by default and must be requested explicitly.
#   Whether recording falls inside the authorized scope is governed by the
#   engagement rules of engagement and by applicable regulation. Recordings are
#   unencrypted and must be handled, stored, and destroyed at the classification
#   of the engagement that produced them.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""Raw IQ recording and replay through the standard capture source interface."""

import json
import logging
import os
import struct
import threading
import time
from typing import Dict, List, Optional

import numpy as np

import band_plan

LOG = logging.getLogger(__name__)

MAGIC = b"RCSIQ001"

# Per block header. Segment id, timestamp, overrun count, sample count.
BLOCK_HEADER = struct.Struct("<idii")

# Default ceiling. Reached in roughly one minute on a two segment plan at full
# rate, which is long enough for a useful regression case and short enough that
# an operator who forgets to stop it does not lose the disk.
DEFAULT_MAX_BYTES = 2 * 1024 * 1024 * 1024


class IQRecorder:
    """Writes capture blocks to a replayable container, bounded by size.

    Writes happen on the caller's thread, which is the sweep thread. That is
    acceptable because the write is a sequential append of an already contiguous
    buffer and the operating system buffers it, but a slow or full disk will show
    up as capture overruns rather than as a recorder error, so the byte counter is
    exposed for the health display.
    """

    def __init__(self, path: str, segments: List, gain: Optional[Dict] = None,
                 max_bytes: int = DEFAULT_MAX_BYTES, notes: str = ""):
        self.path = path
        self.max_bytes = int(max_bytes)
        self.bytes_written = 0
        self.blocks_written = 0
        self.stopped = False
        self._lock = threading.Lock()

        directory = os.path.dirname(os.path.abspath(path))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)

        header = {
            "created_at": time.time(),
            "notes": notes,
            "gain": gain or {},
            "settle_ms": band_plan.DEFAULT_SETTLE_MS,
            "segments": [
                {
                    "segment_id": s.segment_id,
                    "band_name": s.band_name,
                    "center_hz": s.center_hz,
                    "sample_rate_hz": s.sample_rate_hz,
                    "usable_start_hz": s.usable_start_hz,
                    "usable_stop_hz": s.usable_stop_hz,
                    "fft_size": s.fft_size,
                    "averages": s.averages,
                }
                for s in segments
            ],
        }

        self._handle = open(path, "wb")
        blob = json.dumps(header).encode("utf-8")
        self._handle.write(MAGIC)
        self._handle.write(struct.pack("<i", len(blob)))
        self._handle.write(blob)
        self.bytes_written = len(MAGIC) + 4 + len(blob)
        LOG.info("recording IQ to %s, ceiling %.1f GB", path, self.max_bytes / 1e9)

    def write(self, block) -> bool:
        """Append one capture block. Returns False once the ceiling is reached."""
        with self._lock:
            if self.stopped:
                return False

            payload = block.iq.astype(np.complex64, copy=False).tobytes()
            need = BLOCK_HEADER.size + len(payload)
            if self.bytes_written + need > self.max_bytes:
                LOG.warning("IQ recording ceiling reached at %.2f GB, stopping",
                            self.bytes_written / 1e9)
                self._close()
                return False

            self._handle.write(BLOCK_HEADER.pack(
                block.segment.segment_id,
                float(block.timestamp),
                int(block.overruns),
                int(block.iq.size),
            ))
            self._handle.write(payload)
            self.bytes_written += need
            self.blocks_written += 1
            return True

    def stop(self) -> None:
        with self._lock:
            self._close()

    def _close(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        try:
            self._handle.flush()
            self._handle.close()
        except OSError as exc:
            LOG.error("closing recording failed: %s", exc)
        LOG.info("recording closed, %d blocks, %.2f GB",
                 self.blocks_written, self.bytes_written / 1e9)

    def stats(self) -> Dict:
        return {
            "recording": not self.stopped,
            "blocks": self.blocks_written,
            "megabytes": round(self.bytes_written / 1e6, 1),
            "percent_full": round(100.0 * self.bytes_written / self.max_bytes, 1),
        }


class ReplaySource:
    """Serves recorded IQ through the same interface as a live radio.

    Implements open, close, apply_gain, tune, set_segment, and read, so it
    substitutes for HackRFSource inside SweepEngine with no other change. The
    sweep engine walks the same segment plan the recording carries, so blocks are
    served in the order they were captured and the detector sees exactly the input
    it saw live.

    The whole recording is memory mapped rather than read into memory, because a
    two gigabyte file would otherwise have to be resident before the first frame
    could be served.
    """

    def __init__(self, path: str, loop: bool = True, realtime: bool = True):
        self.path = path
        self.loop = bool(loop)
        # When true, playback is paced to the original inter block timing. The
        # detector counts consecutive visits rather than elapsed time, so pacing
        # does not change detection, but it does make the display readable and
        # makes reported burst durations match the original capture.
        self.realtime = bool(realtime)

        self.header: Dict = {}
        self.segments: List = []
        self._index: List[tuple] = []
        self._position = 0
        self._map = None
        self._handle = None
        self._last_served_ts = None
        self._exhausted = False

    def open(self) -> None:
        """Open the recording, parse the header, and index every block."""
        import mmap

        self._handle = open(self.path, "rb")
        magic = self._handle.read(len(MAGIC))
        if magic != MAGIC:
            self._handle.close()
            raise ValueError("{0} is not a Red Cell IQ recording".format(self.path))

        length = struct.unpack("<i", self._handle.read(4))[0]
        self.header = json.loads(self._handle.read(length).decode("utf-8"))

        self._map = mmap.mmap(self._handle.fileno(), 0, access=mmap.ACCESS_READ)

        # Index rather than parse on demand, so a seek to any block is constant
        # time and looping does not require rewinding through the file.
        offset = len(MAGIC) + 4 + length
        total = len(self._map)
        self._index = []
        while offset + BLOCK_HEADER.size <= total:
            seg_id, timestamp, overruns, n_samples = BLOCK_HEADER.unpack(
                self._map[offset:offset + BLOCK_HEADER.size]
            )
            data_offset = offset + BLOCK_HEADER.size
            data_bytes = n_samples * 8
            if data_offset + data_bytes > total:
                LOG.warning("truncated final block in %s, ignoring it", self.path)
                break
            self._index.append((seg_id, timestamp, overruns, data_offset, n_samples))
            offset = data_offset + data_bytes

        self.segments = self._rebuild_segments()
        self._position = 0
        self._exhausted = False
        LOG.info("replay opened, %d blocks over %d segments, %.1f s of capture",
                 len(self._index), len(self.segments), self.duration_s)

    def _rebuild_segments(self) -> List:
        """Reconstruct the original segment plan from the recording header."""
        segments = []
        for entry in self.header.get("segments", []):
            segments.append(band_plan.Segment(
                segment_id=entry["segment_id"],
                band_name=entry["band_name"],
                center_hz=entry["center_hz"],
                sample_rate_hz=entry["sample_rate_hz"],
                usable_start_hz=entry["usable_start_hz"],
                usable_stop_hz=entry["usable_stop_hz"],
                fft_size=entry["fft_size"],
                averages=entry["averages"],
            ))
        return segments

    @property
    def duration_s(self) -> float:
        if len(self._index) < 2:
            return 0.0
        return float(self._index[-1][1] - self._index[0][1])

    def close(self) -> None:
        if self._map is not None:
            self._map.close()
            self._map = None
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def apply_gain(self, gain) -> None:
        """Accepted and ignored. Gain was fixed when the recording was made."""

    def tune(self, center_hz: int, sample_rate_hz: int) -> None:
        """Accepted and ignored. Replay follows the recorded segment order."""

    def set_segment(self, segment) -> None:
        """Accepted and ignored, for interface parity with the synthetic source."""

    def read(self, n_samples: int) -> tuple:
        """Serve the next recorded block.

        The requested sample count is ignored in favour of what was recorded. The
        sweep engine also reads a settle block before each dwell, which was never
        recorded because settle samples are discarded at capture time. Serving the
        recorded block for both reads would consume the file at twice the intended
        rate, so a short read is answered with zeros and only a full length read
        advances the position.
        """
        if self._map is None:
            raise RuntimeError("replay source read before open")

        if self._position >= len(self._index):
            if not self.loop:
                self._exhausted = True
                return np.zeros(n_samples, dtype=np.complex64), 0
            self._position = 0
            self._last_served_ts = None

        seg_id, timestamp, overruns, offset, count = self._index[self._position]

        # Settle reads are always shorter than a capture block. Answer them
        # without advancing, so the recorded blocks line up with the capture reads
        # they came from.
        if n_samples < count:
            return np.zeros(n_samples, dtype=np.complex64), 0

        if self.realtime and self._last_served_ts is not None:
            delay = timestamp - self._last_served_ts
            if 0.0 < delay < 1.0:
                time.sleep(delay)
        self._last_served_ts = timestamp

        raw = self._map[offset:offset + count * 8]
        iq = np.frombuffer(raw, dtype=np.complex64, count=count)

        self._position += 1
        # Copy rather than hand out a view into the memory map. The consumer holds
        # the array across the queue and the map may be closed underneath it.
        return iq.copy(), int(overruns)

    def stats(self) -> Dict:
        return {
            "blocks": len(self._index),
            "position": self._position,
            "duration_s": round(self.duration_s, 2),
            "exhausted": self._exhausted,
            "notes": self.header.get("notes", ""),
        }


def describe(path: str) -> Dict:
    """Summarize a recording without replaying it, for the command line."""
    source = ReplaySource(path, loop=False, realtime=False)
    source.open()
    info = {
        "path": path,
        "created_at": source.header.get("created_at"),
        "notes": source.header.get("notes", ""),
        "gain": source.header.get("gain", {}),
        "blocks": len(source._index),
        "duration_s": round(source.duration_s, 2),
        "size_mb": round(os.path.getsize(path) / 1e6, 1),
        "segments": [
            {
                "band": s.band_name,
                "start_mhz": round(s.usable_start_hz / 1e6, 4),
                "stop_mhz": round(s.usable_stop_hz / 1e6, 4),
                "rate_msps": round(s.sample_rate_hz / 1e6, 3),
            }
            for s in source.segments
        ],
    }
    source.close()
    return info
