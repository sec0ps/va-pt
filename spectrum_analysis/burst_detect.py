#!/usr/bin/env python3
# =============================================================================
# Location: burst_detect.py
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
#   Detects transmission bursts in the spectrum frames produced by dsp_psd, and
#   maintains the lifecycle of each detected signal from first appearance through
#   sustained presence to closure.
#
#   Detection state is kept per segment rather than globally. Each segment has
#   its own noise floor because instantaneous bandwidth on a HackRF is wide
#   enough that one strong emitter inside a segment desenses the entire segment,
#   and because the planner assigns different sample rates to different bands. A
#   single global floor across a stitched sweep would read every segment boundary
#   as a signal edge.
#
#   The floor estimator excludes bins that are currently occupied rather than
#   tracking them slowly. Any estimator that follows an occupied bin at all will
#   eventually absorb a continuous carrier into the floor and go blind to it, and
#   an estimator that follows occupied bins asymmetrically settles below the true
#   noise mean and silently lowers the effective detection threshold. Excluding
#   occupied bins gives an unbiased estimate of the noise mean from unoccupied
#   bins only, which is what the threshold offsets are defined against.
#
#   The module also classifies each detection by how often it has been present in
#   its own segment history. With no known target list, presence is not
#   informative and change is. A cell site is always on and tells the operator
#   nothing. A handheld that keys up for the first time is the entire point. The
#   persistent, intermittent, and new classification is what separates the two,
#   and the same occupancy statistic doubles as the rejection mechanism for
#   fixed spurs and images.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. Detection here is energy based only.
#   It establishes that a transmission occurred at a frequency and time. It does
#   not demodulate, decode, identify a transmitting party, or recover any
#   communications content.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""Per segment noise floor tracking, burst event detection, and classification."""

import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np
from scipy.ndimage import median_filter

# Threshold offsets above the tracked noise floor, in dB. Two values give
# hysteresis. A signal must exceed the on threshold to be considered present and
# must fall below the off threshold to be considered gone.
#
# The on threshold is set against the statistics of the PSD estimate rather than
# by taste. With N averaged periodograms the standard deviation of a noise bin is
# about 4.34 divided by the square root of N, in dB. At the default four averages
# that is roughly 2.2 dB, so a 6 dB offset sits near 2.7 standard deviations and
# a single noise bin exceeds it about four times in a thousand. Requiring several
# consecutive visits cubes that figure, which is what brings the false alarm rate
# across several thousand bins down to a fraction of one per sweep. Lowering this
# offset without raising the averages or the consecutive visit requirement will
# reintroduce noise detections.
DEFAULT_THRESHOLD_ON_DB = 6.0
DEFAULT_THRESHOLD_OFF_DB = 4.0

# Consecutive segment visits a signal must be present before an event opens.
# In a swept analyzer this counts revisits, not milliseconds, so it multiplies
# directly into the minimum detectable burst duration reported by band_plan.
DEFAULT_OPEN_FRAMES = 3

# Consecutive visits a signal must be absent before an event closes. Set higher
# than the open requirement so that a brief fade inside one transmission does not
# split it into two events.
DEFAULT_CLOSE_FRAMES = 4

# Floor tracking rate for bins that are not currently occupied. Moderate and
# symmetric. Fast enough to follow a genuine change in the noise environment
# within a second or so of sweeping, slow enough that the estimate is not itself
# noisy.
DEFAULT_FLOOR_ALPHA = 0.05

# Kernel width in bins for the median filter used to seed the floor from the
# first observed frame. Wide enough to span any plausible signal and reject it,
# narrow enough to preserve the genuine tilt of the analog filter response across
# the segment. Seeding from the raw frame instead would write any carrier that
# happened to be transmitting at sweep start directly into the floor and render
# that carrier permanently undetectable.
FLOOR_SEED_KERNEL = 129

# Fraction of bins in a segment that may be simultaneously active before the
# excluded bin floor update is overridden and every bin is updated.
#
# Excluding occupied bins is correct when occupancy is sparse. When a real change
# raises the level across most of the segment, such as a gain change, an AGC
# event, or a strong wideband interferer arriving, most bins go active at once,
# and excluding them would freeze the floor at the old level and pin the whole
# segment into permanent detection. Above this fraction the situation is read as
# a floor shift rather than as signal.
FLOOR_SHIFT_ACTIVE_FRACTION = 0.5

# Occupancy tracking rate. Governs how many visits of history meaningfully
# influence the persistent versus new classification.
DEFAULT_OCCUPANCY_ALPHA = 0.01

# Visits that must accumulate before occupancy statistics mean anything. Below
# this the classification is reported as unknown, which is more honest than
# labelling every signal new during the first seconds of a sweep.
CLASSIFY_WARMUP_FRAMES = 50

# Occupancy thresholds for classification and for spur rejection.
PERSISTENT_OCCUPANCY = 0.85
NEW_OCCUPANCY = 0.05

# Minimum contiguous bins a detection must span. A single isolated bin above
# threshold is far more often an FFT sidelobe or an impulse than a transmission,
# since any real signal occupies at least a few resolution bandwidths.
DEFAULT_MIN_BINS = 2

# Bins either side of a detection group that may be merged into it. Real signals
# have skirts that dip below threshold in places, and without bridging one
# transmission fragments into several adjacent events.
DEFAULT_BRIDGE_BINS = 2

# Occupied bandwidth is measured at this many dB below the group peak.
OCCUPIED_BW_DROP_DB = 6.0


@dataclass
class BurstEvent:
    """One detected transmission, tracked from first appearance to closure."""

    event_id: int
    segment_id: int
    band_name: str
    center_hz: float
    occupied_bw_hz: float
    peak_dbfs: float
    floor_dbfs: float
    snr_db: float
    first_seen: float
    last_seen: float
    frame_count: int = 1
    classification: str = "unknown"
    active: bool = True
    # Cumulative mean of center frequency across every visit in which this event
    # was seen. A single visit's centroid is a noisy estimate for any modulated
    # signal, because the instantaneous power distribution moves with the
    # modulation. Wideband FM is the extreme case, having no discrete carrier at
    # all, so its per visit centroid wanders by kilohertz while its long term mean
    # converges on the true carrier. Anything needing frequency precision, saved
    # markers and oscillator calibration in particular, should read this rather
    # than the instantaneous value.
    center_mean_hz: float = 0.0
    # Visits since the signal was last seen. Drives closure.
    missing_frames: int = 0
    # Antenna in use when this event was observed, carried through to any marker
    # the operator saves so that level readings stay interpretable later.
    antenna_note: str = ""

    @property
    def duration_s(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def to_dict(self) -> Dict:
        """Serialize for websocket transport and for marker persistence."""
        return {
            "event_id": self.event_id,
            "segment_id": self.segment_id,
            "band_name": self.band_name,
            "center_hz": self.center_hz,
            "center_mean_hz": self.center_mean_hz or self.center_hz,
            "occupied_bw_hz": self.occupied_bw_hz,
            "peak_dbfs": round(self.peak_dbfs, 2),
            "floor_dbfs": round(self.floor_dbfs, 2),
            "snr_db": round(self.snr_db, 2),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_s": round(self.duration_s, 3),
            "frame_count": self.frame_count,
            "classification": self.classification,
            "active": self.active,
            "antenna_note": self.antenna_note,
        }


@dataclass
class _SegmentState:
    """Detector state for one segment, sized on first frame from that segment."""

    n_bins: int
    # Tracked noise floor in dBFS, one value per full resolution bin.
    floor: np.ndarray = field(repr=False, default=None)
    # Exponential moving fraction of visits in which each bin was active.
    occupancy: np.ndarray = field(repr=False, default=None)
    # Consecutive visits each bin has been active.
    above_run: np.ndarray = field(repr=False, default=None)
    # Bins that have already satisfied the consecutive visit requirement. Only
    # these are permitted to sustain on the lower hysteresis threshold.
    confirmed: np.ndarray = field(repr=False, default=None)
    # Active mask from the previous visit, used to exclude occupied bins from the
    # floor update without a circular dependency on the current threshold.
    active_prev: np.ndarray = field(repr=False, default=None)
    # Events currently open in this segment, keyed by event id.
    open_events: Dict[int, BurstEvent] = field(default_factory=dict, repr=False)
    frames_seen: int = 0

    @classmethod
    def create(cls, n_bins: int, first_power: np.ndarray) -> "_SegmentState":
        """Seed state from a median filtered first frame.

        The median filter rejects any signal narrower than roughly half the kernel
        while preserving the broad shape of the analog filter response across the
        segment. Seeding from the raw frame would capture any carrier transmitting
        at that instant into the floor, and because the tracker then excludes
        occupied bins from updates, that carrier would stay buried in the floor
        for the life of the session.
        """
        kernel = min(FLOOR_SEED_KERNEL, max(3, (n_bins // 4) | 1))
        seed = median_filter(first_power.astype(np.float32), size=kernel, mode="nearest")
        return cls(
            n_bins=n_bins,
            floor=seed.astype(np.float32),
            occupancy=np.zeros(n_bins, dtype=np.float32),
            above_run=np.zeros(n_bins, dtype=np.int32),
            confirmed=np.zeros(n_bins, dtype=bool),
            active_prev=np.zeros(n_bins, dtype=bool),
        )


class BurstDetector:
    """Stateful burst detector operating on full resolution spectrum frames.

    One instance serves the whole sweep. Segment state is created lazily on the
    first frame from each segment and is keyed by segment id, so a band plan
    change simply produces new segment ids and abandons the old state rather than
    contaminating the new bands with floors learned from the old ones.
    """

    def __init__(
        self,
        threshold_on_db: float = DEFAULT_THRESHOLD_ON_DB,
        threshold_off_db: float = DEFAULT_THRESHOLD_OFF_DB,
        open_frames: int = DEFAULT_OPEN_FRAMES,
        close_frames: int = DEFAULT_CLOSE_FRAMES,
        min_bins: int = DEFAULT_MIN_BINS,
        bridge_bins: int = DEFAULT_BRIDGE_BINS,
        floor_alpha: float = DEFAULT_FLOOR_ALPHA,
        occupancy_alpha: float = DEFAULT_OCCUPANCY_ALPHA,
        reject_persistent: bool = True,
    ):
        self.threshold_on_db = float(threshold_on_db)
        self.threshold_off_db = float(threshold_off_db)
        self.open_frames = int(open_frames)
        self.close_frames = int(close_frames)
        self.min_bins = int(min_bins)
        self.bridge_bins = int(bridge_bins)
        self.floor_alpha = float(floor_alpha)
        self.occupancy_alpha = float(occupancy_alpha)
        self.reject_persistent = bool(reject_persistent)

        self._segments: Dict[int, _SegmentState] = {}
        self._event_ids = itertools.count(1)
        # Antenna note per band, supplied by the caller from the band plan so that
        # events carry the antenna context forward into saved markers.
        self.antenna_notes: Dict[str, str] = {}

    def reset(self) -> None:
        """Discard all learned state. Call on band plan or gain change.

        A gain change shifts every level in the frame by the gain delta, so a
        floor learned at the old gain is wrong by that delta and would produce a
        full segment false detection or full segment blindness until it caught up.
        """
        self._segments.clear()

    def process(self, frame) -> Dict[str, List[Dict]]:
        """Update state from one frame and return event transitions.

        Returns a dict with opened, updated, and closed lists. The transport layer
        emits opened and closed as discrete events and may throttle updated, since
        a sustained transmission produces an update on every revisit and the
        operator does not need all of them.
        """
        power = frame.power_dbfs
        if power is None or power.size == 0:
            return {"opened": [], "updated": [], "closed": []}

        state = self._segments.get(frame.segment_id)
        if state is None or state.n_bins != power.size:
            state = _SegmentState.create(power.size, power)
            self._segments[frame.segment_id] = state

        # A frame that suffered a stream overrun is time discontinuous. Fold it
        # into the floor so tracking stays current, but do not advance the run
        # counters, since the consecutive visit requirement is meaningless across
        # a gap of unknown length.
        discontinuous = frame.overruns > 0

        self._update_floor(state, power)

        threshold_on = state.floor + self.threshold_on_db
        threshold_off = state.floor + self.threshold_off_db

        above_on = power > threshold_on
        above_off = power > threshold_off

        # Hysteresis applies only to bins that have already satisfied the
        # consecutive visit requirement. Allowing an unconfirmed bin to sustain on
        # the lower threshold makes a noise excursion trivially easy to extend
        # into a full run, because the lower threshold sits under two standard
        # deviations and is crossed by noise routinely.
        active = above_on | (state.confirmed & above_off)

        state.occupancy += self.occupancy_alpha * (active.astype(np.float32) - state.occupancy)

        if not discontinuous:
            state.above_run = np.where(active, state.above_run + 1, 0)
            state.frames_seen += 1

        eligible = state.above_run >= self.open_frames
        state.confirmed = eligible | (state.confirmed & above_off)
        state.active_prev = active

        if self.reject_persistent:
            # Fixed spurs, LO images, and continuous carriers sit above threshold
            # nearly always. Excluding them here keeps the detector focused on
            # change. They remain visible on the display and remain classifiable,
            # they simply do not generate repeated burst events.
            eligible = eligible & (state.occupancy < PERSISTENT_OCCUPANCY)

        groups = self._group_bins(eligible)
        return self._reconcile(frame, state, groups, power)

    def _update_floor(self, state: _SegmentState, power: np.ndarray) -> None:
        """Track the noise floor from unoccupied bins only.

        Bins that were active on the previous visit are excluded from the update
        so that neither a burst nor a continuous carrier can drag the floor up to
        meet itself. The exclusion is released as soon as a bin stops being
        active, so the floor follows a genuine drop within a few visits.

        The guard exists because exclusion is only correct while occupancy is
        sparse. If most of the segment goes active at once the cause is a shift in
        the floor itself rather than signal, and excluding those bins would freeze
        the estimate at a stale level and pin the segment into permanent
        detection.
        """
        delta = power - state.floor
        active_fraction = float(np.count_nonzero(state.active_prev)) / float(state.n_bins)

        if active_fraction > FLOOR_SHIFT_ACTIVE_FRACTION:
            state.floor += (self.floor_alpha * delta).astype(np.float32)
            return

        update_mask = ~state.active_prev
        state.floor[update_mask] += (self.floor_alpha * delta[update_mask]).astype(np.float32)

    def _group_bins(self, eligible: np.ndarray) -> List[tuple]:
        """Merge contiguous eligible bins into groups, bridging small gaps.

        Bridging is applied before the minimum width test so that a signal whose
        center dips below threshold, which is common on a modulated carrier with
        a suppressed carrier component, is measured as one signal rather than as
        two sidebands.
        """
        indices = np.flatnonzero(eligible)
        if indices.size == 0:
            return []

        groups = []
        start = int(indices[0])
        prev = start
        for idx in indices[1:]:
            idx = int(idx)
            if idx - prev > self.bridge_bins + 1:
                groups.append((start, prev))
                start = idx
            prev = idx
        groups.append((start, prev))

        return [(lo, hi) for lo, hi in groups if (hi - lo + 1) >= self.min_bins]

    def _reconcile(
        self,
        frame,
        state: _SegmentState,
        groups: List[tuple],
        power: np.ndarray,
    ) -> Dict[str, List[Dict]]:
        """Match detection groups against open events and emit transitions.

        Matching is by frequency overlap rather than by identity, since the
        detector has no persistent handle on a signal between visits. A group that
        overlaps an open event in frequency is treated as a continuation of that
        event. A group matching nothing opens a new event. An open event matching
        nothing this visit accumulates a miss and closes once misses exceed the
        close threshold.
        """
        now = frame.timestamp
        opened: List[Dict] = []
        updated: List[Dict] = []
        closed: List[Dict] = []
        matched_event_ids = set()

        antenna = self.antenna_notes.get(frame.band_name, "")

        for lo, hi in groups:
            metrics = self._measure(frame, state, power, lo, hi)
            existing = self._find_overlap(
                state, metrics["low_hz"], metrics["high_hz"], matched_event_ids
            )

            if existing is not None:
                existing.center_hz = metrics["center_hz"]
                # Cumulative mean, updated incrementally so no history is kept.
                existing.center_mean_hz += (
                    (metrics["center_hz"] - existing.center_mean_hz)
                    / float(existing.frame_count + 1)
                )
                existing.occupied_bw_hz = metrics["occupied_bw_hz"]
                existing.peak_dbfs = metrics["peak_dbfs"]
                existing.floor_dbfs = metrics["floor_dbfs"]
                existing.snr_db = metrics["snr_db"]
                existing.last_seen = now
                existing.frame_count += 1
                existing.missing_frames = 0
                existing.classification = self._classify(state, lo, hi)
                matched_event_ids.add(existing.event_id)
                updated.append(existing.to_dict())
                continue

            event = BurstEvent(
                event_id=next(self._event_ids),
                segment_id=frame.segment_id,
                band_name=frame.band_name,
                center_hz=metrics["center_hz"],
                center_mean_hz=metrics["center_hz"],
                occupied_bw_hz=metrics["occupied_bw_hz"],
                peak_dbfs=metrics["peak_dbfs"],
                floor_dbfs=metrics["floor_dbfs"],
                snr_db=metrics["snr_db"],
                first_seen=now,
                last_seen=now,
                classification=self._classify(state, lo, hi),
                antenna_note=antenna,
            )
            state.open_events[event.event_id] = event
            matched_event_ids.add(event.event_id)
            opened.append(event.to_dict())

        for event_id in list(state.open_events):
            if event_id in matched_event_ids:
                continue
            event = state.open_events[event_id]
            event.missing_frames += 1
            if event.missing_frames >= self.close_frames:
                event.active = False
                closed.append(event.to_dict())
                del state.open_events[event_id]

        return {"opened": opened, "updated": updated, "closed": closed}

    def _measure(self, frame, state: _SegmentState, power: np.ndarray, lo: int, hi: int) -> Dict:
        """Characterize one detection group.

        Center frequency is a power weighted centroid rather than the peak bin.
        The centroid is stable to a fraction of a bin across visits, whereas the
        peak bin jitters between adjacent bins on noise and would make a saved
        marker frequency depend on which visit the operator happened to click.

        Occupied bandwidth is measured where the group falls a fixed number of dB
        below its own peak, searched outward from the peak, which is the standard
        approach and is independent of where the detection threshold sat.
        """
        segment_slice = power[lo:hi + 1]
        peak_offset = int(np.argmax(segment_slice))
        peak_bin = lo + peak_offset
        peak_dbfs = float(segment_slice[peak_offset])
        floor_dbfs = float(np.median(state.floor[lo:hi + 1]))

        # Weight by power above the floor in the linear domain. Weighting by dBFS
        # directly would give near floor bins substantial weight and pull the
        # centroid toward whichever side of the signal has a longer skirt.
        excess_db = np.maximum(segment_slice - floor_dbfs, 0.0)
        weights = np.power(10.0, excess_db / 10.0) - 1.0
        weight_sum = float(np.sum(weights))
        if weight_sum > 0.0:
            bin_axis = np.arange(lo, hi + 1, dtype=np.float64)
            centroid_bin = float(np.sum(bin_axis * weights) / weight_sum)
        else:
            centroid_bin = float(peak_bin)

        cutoff = peak_dbfs - OCCUPIED_BW_DROP_DB
        left = peak_bin
        while left > 0 and power[left - 1] >= cutoff:
            left -= 1
        right = peak_bin
        last_bin = power.size - 1
        while right < last_bin and power[right + 1] >= cutoff:
            right += 1

        occupied_bw = (right - left + 1) * frame.f_step_hz

        return {
            "center_hz": frame.bin_to_hz(centroid_bin),
            "low_hz": frame.bin_to_hz(float(left)),
            "high_hz": frame.bin_to_hz(float(right + 1)),
            "occupied_bw_hz": occupied_bw,
            "peak_dbfs": peak_dbfs,
            "floor_dbfs": floor_dbfs,
            "snr_db": peak_dbfs - floor_dbfs,
        }

    @staticmethod
    def _find_overlap(
        state: _SegmentState,
        low_hz: float,
        high_hz: float,
        already_matched: set,
    ) -> Optional[BurstEvent]:
        """Return the open event whose occupied span overlaps this group most."""
        best = None
        best_overlap = 0.0
        for event in state.open_events.values():
            if event.event_id in already_matched:
                continue
            half = max(event.occupied_bw_hz, 1.0) / 2.0
            e_low = event.center_hz - half
            e_high = event.center_hz + half
            overlap = min(high_hz, e_high) - max(low_hz, e_low)
            if overlap > best_overlap:
                best_overlap = overlap
                best = event
        return best

    def _classify(self, state: _SegmentState, lo: int, hi: int) -> str:
        """Label a detection by how routinely it has occupied this frequency.

        Classification uses the maximum occupancy across the group rather than the
        mean, because a persistent narrow carrier sitting inside a wider detection
        should mark the whole group as furniture rather than being diluted by the
        unoccupied bins around it.
        """
        if state.frames_seen < CLASSIFY_WARMUP_FRAMES:
            return "unknown"
        occupancy = float(np.max(state.occupancy[lo:hi + 1]))
        if occupancy >= PERSISTENT_OCCUPANCY:
            return "persistent"
        if occupancy <= NEW_OCCUPANCY:
            return "new"
        return "intermittent"

    def active_events(self) -> List[Dict]:
        """Every currently open event across all segments, for UI state sync."""
        events: List[Dict] = []
        for state in self._segments.values():
            events.extend(event.to_dict() for event in state.open_events.values())
        return sorted(events, key=lambda e: e["last_seen"], reverse=True)

    def floor_for_segment(self, segment_id: int) -> Optional[np.ndarray]:
        """Current tracked floor for a segment, for the threshold display overlay."""
        state = self._segments.get(segment_id)
        return None if state is None else state.floor
