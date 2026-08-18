#!/usr/bin/env python3
# =============================================================================
# Location: band_plan.py
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
#   Defines the frequency band plan for the swept spectrum analyzer. Provides
#   regional operating presets for US, EU, and South America, converts a set of
#   bands into an ordered list of tuner segments, selects an appropriate sample
#   rate per band so that resolution bandwidth suits the channel spacing in that
#   band, and computes the resulting sweep revisit interval and the shortest
#   burst that the configured plan can reliably detect.
#
#   The revisit math is the governing constraint of the whole analyzer. A single
#   SDR observes only one segment at a time, so any emission occurring while the
#   tuner is parked elsewhere is not merely hard to detect, it is unobservable.
#   Callers are expected to surface sweep_metrics() output in the operator UI so
#   that an over-wide span is visibly reported rather than silently missing
#   traffic.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. Band definitions here describe
#   spectrum allocations only. They do not constitute authorization to receive,
#   record, decode, or act upon any transmission. Receive authority, retention
#   policy, and any demodulation of communications content are governed by the
#   engagement rules of engagement and by applicable regulation in the operating
#   jurisdiction.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. Spectrum
#   allocations vary by country and change over time. The allocations encoded in
#   this module are operator convenience defaults and are not a regulatory
#   reference. Verify allocations against the current national regulator table
#   for the operating jurisdiction before relying on them. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""Regional band plan, segment planning, and sweep revisit metrics."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# HackRF One hardware envelope.
HACKRF_MIN_HZ = 1_000_000
HACKRF_MAX_HZ = 6_000_000_000

# Sample rates the HackRF accepts cleanly. Lower rates buy finer resolution
# bandwidth at the cost of longer capture time for a fixed FFT size, so the
# planner picks the lowest rate that still covers a band in the fewest segments.
HACKRF_SAMPLE_RATES_HZ = (
    2_000_000,
    4_000_000,
    8_000_000,
    10_000_000,
    12_500_000,
    16_000_000,
    20_000_000,
)

# Fraction of the complex sample rate kept from each segment. The outer bins show
# filter skirt rather than true level, so they are discarded and segments are
# overlapped by the discarded amount.
#
# This value is set by hardware, not by preference. The MAX2837 baseband filter
# has discrete steps rather than a continuously variable bandwidth, and at the
# 20 MS/s maximum sample rate the widest step that still provides anti alias
# margin is 15 MHz. Three quarters is therefore the largest fraction that is
# actually inside the passband at the rate the analyzer uses for wide segments.
# Claiming more would place the outermost kept bins in the filter skirt, where
# they read low, and the detector would see a level step at every segment
# boundary.
USABLE_FRACTION = 0.75

# Tuner retune and PLL settle time. Measured empirically per host, this is a
# conservative default. Samples captured before settle completes contain a
# frequency sweep artifact and must be discarded.
DEFAULT_SETTLE_MS = 1.5

# Default FFT length and number of power spectrum averages per segment visit.
DEFAULT_FFT_SIZE = 4096
DEFAULT_AVERAGES = 4

# Number of consecutive segment visits a signal must be present for before the
# detector opens a burst event. In a swept analyzer, consecutive frames means
# consecutive revisits, not consecutive milliseconds, which is why this value
# multiplies into the minimum detectable burst duration.
DEFAULT_DETECT_DWELL_FRAMES = 3


@dataclass(frozen=True)
class Band:
    """A contiguous frequency range with the context needed to sweep it well."""

    name: str
    start_hz: int
    stop_hz: int
    channel_spacing_hz: Optional[int] = None
    antenna_note: str = ""
    note: str = ""

    @property
    def width_hz(self) -> int:
        return self.stop_hz - self.start_hz

    @property
    def center_hz(self) -> int:
        return (self.start_hz + self.stop_hz) // 2


@dataclass(frozen=True)
class Preset:
    """A named collection of bands scoped to an operating region."""

    key: str
    name: str
    region: str
    description: str
    bands: Tuple[Band, ...]
    verify_locally: bool = False


@dataclass(frozen=True)
class Segment:
    """One tuner dwell position produced by the planner."""

    segment_id: int
    band_name: str
    center_hz: int
    sample_rate_hz: int
    usable_start_hz: int
    usable_stop_hz: int
    fft_size: int
    averages: int

    @property
    def rbw_hz(self) -> float:
        """Resolution bandwidth. Governs whether adjacent channels separate."""
        return self.sample_rate_hz / float(self.fft_size)

    @property
    def dwell_ms(self) -> float:
        """Settle time plus the acquisition time for all averaged FFTs."""
        acquire_ms = (self.fft_size * self.averages / float(self.sample_rate_hz)) * 1000.0
        return DEFAULT_SETTLE_MS + acquire_ms


@dataclass
class SweepMetrics:
    """Operator facing consequences of a given band selection."""

    segment_count: int
    total_span_hz: int
    revisit_ms: float
    min_reliable_burst_ms: float
    coarsest_rbw_hz: float
    warnings: List[str] = field(default_factory=list)


# -----------------------------------------------------------------------------
# Band definitions
#
# Channel spacing drives sample rate selection. Where a band carries narrowband
# FM voice on 12.5 or 25 kHz channels, the planner needs a resolution bandwidth
# well under the spacing or adjacent channels merge into one apparent signal.
# Where a band carries wideband digital traffic, coarse resolution is fine and
# the wider sample rate is preferred for fewer segments.
# -----------------------------------------------------------------------------

# United States, ITU Region 2.
US_MURS = Band(
    "MURS", 151_800_000, 154_650_000, 12_500,
    "VHF whip, roughly 48 cm quarter wave",
    "Five license free VHF channels. Common on unlicensed handhelds.",
)
US_FRS_GMRS = Band(
    "FRS / GMRS", 462_500_000, 467_750_000, 12_500,
    "UHF whip, roughly 16 cm quarter wave",
    "Consumer and licensed handheld traffic. Includes both the 462 and 467 groups.",
)
US_LMR_VHF = Band(
    "LMR VHF", 150_000_000, 174_000_000, 12_500,
    "VHF whip",
    "Business, industrial, and public safety land mobile.",
)
US_LMR_UHF = Band(
    "LMR UHF", 450_000_000, 470_000_000, 12_500,
    "UHF whip",
    "Business and industrial land mobile, analog and DMR and P25.",
)
US_PS_700 = Band(
    "Public safety 700", 769_000_000, 806_000_000, 12_500,
    "700 to 800 MHz whip",
    "Narrowband public safety and adjacent commercial.",
)
US_PS_800 = Band(
    "Public safety 800", 806_000_000, 869_000_000, 25_000,
    "700 to 800 MHz whip",
    "Trunked public safety, SMR, and cellular adjacent allocations.",
)
US_HAM_2M = Band(
    "Amateur 2 m", 144_000_000, 148_000_000, 12_500,
    "VHF whip",
    "Region 2 amateur allocation. Repeater output and simplex.",
)
US_HAM_70CM = Band(
    "Amateur 70 cm", 420_000_000, 450_000_000, 12_500,
    "UHF whip",
    "Region 2 amateur allocation, wider than the Region 1 equivalent.",
)
US_ISM_902 = Band(
    "ISM 902 to 928", 902_000_000, 928_000_000, 200_000,
    "900 MHz whip",
    "Frequency hopping telemetry, LoRa, utility metering, cordless.",
)
US_CB = Band(
    "CB 27 MHz", 26_950_000, 27_450_000, 10_000,
    "HF whip or long wire, expect poor sensitivity without preselection",
    "Below the practical HackRF sensitivity floor without a preamp.",
)

# Europe, ITU Region 1.
EU_PMR446 = Band(
    "PMR446", 446_000_000, 446_200_000, 6_250,
    "UHF whip, roughly 16 cm quarter wave",
    "License free handheld voice, analog FM and dPMR and DMR Tier 1.",
)
EU_LPD433 = Band(
    "LPD433", 433_050_000, 434_790_000, 25_000,
    "433 MHz whip",
    "Short range devices, remotes, telemetry, license free handhelds.",
)
EU_SRD_868 = Band(
    "SRD 868", 863_000_000, 870_000_000, 200_000,
    "868 MHz whip",
    "Short range devices, LoRaWAN, alarms, metering.",
)
EU_TETRA_EMERGENCY = Band(
    "TETRA emergency 380 to 400", 380_000_000, 400_000_000, 25_000,
    "UHF whip",
    "Emergency service TETRA in most CEPT administrations.",
)
EU_TETRA_COMMERCIAL = Band(
    "TETRA commercial 410 to 430", 410_000_000, 430_000_000, 25_000,
    "UHF whip",
    "Commercial and utility TETRA.",
)
EU_LMR_UHF = Band(
    "LMR UHF 450 to 470", 450_000_000, 470_000_000, 12_500,
    "UHF whip",
    "Business land mobile. National sub allocations vary widely.",
)
EU_LMR_VHF = Band(
    "LMR VHF 165 to 175", 165_000_000, 175_000_000, 12_500,
    "VHF whip",
    "Business land mobile. National sub allocations vary widely.",
)
EU_HAM_2M = Band(
    "Amateur 2 m", 144_000_000, 146_000_000, 12_500,
    "VHF whip",
    "Region 1 amateur allocation, narrower than Region 2.",
)
EU_HAM_70CM = Band(
    "Amateur 70 cm", 430_000_000, 440_000_000, 12_500,
    "UHF whip",
    "Region 1 amateur allocation, narrower than Region 2.",
)

# South America, predominantly ITU Region 2 with significant national variation.
SA_HANDHELD_UHF = Band(
    "Handheld UHF 462 to 468", 462_000_000, 468_000_000, 12_500,
    "UHF whip",
    "Region 2 style consumer handheld allocation. Verify per country.",
)
SA_LMR_VHF = Band(
    "LMR VHF 148 to 174", 148_000_000, 174_000_000, 12_500,
    "VHF whip",
    "Land mobile. Allocation split differs by administration.",
)
SA_LMR_UHF = Band(
    "LMR UHF 450 to 470", 450_000_000, 470_000_000, 12_500,
    "UHF whip",
    "Land mobile. Allocation split differs by administration.",
)
SA_PX_27 = Band(
    "Citizen band 27 MHz", 26_950_000, 27_450_000, 10_000,
    "HF whip or long wire, expect poor sensitivity without preselection",
    "Widely used across the region. Brazil designates this the PX service.",
)
SA_HAM_2M = Band(
    "Amateur 2 m", 144_000_000, 148_000_000, 12_500,
    "VHF whip",
    "Region 2 amateur allocation.",
)
SA_HAM_70CM = Band(
    "Amateur 70 cm", 430_000_000, 440_000_000, 12_500,
    "UHF whip",
    "Most administrations in the region use the narrower 430 to 440 sub band.",
)
SA_ISM_915_LOWER = Band(
    "ISM 902 to 907.5", 902_000_000, 907_500_000, 200_000,
    "900 MHz whip",
    "Lower half of the Region 2 ISM band. Brazil reserves the middle for cellular.",
)
SA_ISM_915_UPPER = Band(
    "ISM 915 to 928", 915_000_000, 928_000_000, 200_000,
    "900 MHz whip",
    "Upper half of the Region 2 ISM band.",
)

# Region independent bands.
ISM_2G4 = Band(
    "ISM 2.4 GHz", 2_400_000_000, 2_483_500_000, 1_000_000,
    "2.4 GHz stub or patch, a VHF whip is effectively deaf here",
    "WiFi, Bluetooth, drone control and video, proprietary hopping links.",
)
WIFI_5G = Band(
    "WiFi 5 GHz", 5_150_000_000, 5_875_000_000, 5_000_000,
    "5 GHz stub or patch",
    "Wide channels. Coarse resolution bandwidth is appropriate here.",
)
FM_BROADCAST = Band(
    "FM broadcast", 88_000_000, 108_000_000, 200_000,
    "VHF whip",
    "Strong reliable carriers. Preferred known good source for validation.",
)
AIRBAND = Band(
    "Airband AM", 108_000_000, 137_000_000, 25_000,
    "VHF whip",
    "AM voice, bursty by nature, useful as a natural burst test source.",
)
ADSB = Band(
    "ADS-B 1090", 1_089_000_000, 1_091_000_000, 1_000_000,
    "1090 MHz whip or collinear",
    "Dense short pulses. Stresses the detector at the fast end.",
)
SURVEY_VHF_UHF = Band(
    "Survey 30 to 1000", 30_000_000, 1_000_000_000, None,
    "No single antenna covers this span, expect level to reflect antenna mismatch",
    "Discovery sweep. Finds persistent occupancy, will miss short bursts.",
)
FULL_DEVICE = Band(
    "Full device range", HACKRF_MIN_HZ, HACKRF_MAX_HZ, None,
    "No single antenna covers this span, expect level to reflect antenna mismatch",
    "Maximum span. Revisit interval makes burst detection unreliable.",
)


PRESETS: Dict[str, Preset] = {}


def _register(preset: Preset) -> Preset:
    PRESETS[preset.key] = preset
    return preset


DEFAULT_PRESET_KEY = "us_handheld"

_register(Preset(
    "us_handheld", "US Handheld", "US",
    "Default. MURS plus FRS and GMRS. Two segments, fastest revisit of any preset.",
    (US_MURS, US_FRS_GMRS),
))
_register(Preset(
    "us_handheld_wide", "US Handheld Wide", "US",
    "Handheld allocations plus the surrounding business land mobile bands.",
    (US_LMR_VHF, US_LMR_UHF),
))
_register(Preset(
    "us_public_safety", "US Public Safety", "US",
    "700 and 800 MHz narrowband and trunked public safety allocations.",
    (US_PS_700, US_PS_800),
))
_register(Preset(
    "us_amateur", "US Amateur", "US",
    "Region 2 amateur 2 m and 70 cm allocations.",
    (US_HAM_2M, US_HAM_70CM),
))
_register(Preset(
    "us_ism", "US ISM and Unlicensed", "US",
    "902 to 928 and 2.4 GHz. Requires an antenna change between the two bands.",
    (US_ISM_902, ISM_2G4),
))
_register(Preset(
    "us_full_lmr", "US Land Mobile Full", "US",
    "VHF and UHF land mobile plus public safety. Four to five segments.",
    (US_LMR_VHF, US_LMR_UHF, US_PS_700, US_PS_800),
))

_register(Preset(
    "eu_handheld", "EU Handheld", "EU",
    "PMR446 plus LPD433. The Region 1 equivalent of the US handheld default.",
    (EU_PMR446, EU_LPD433),
))
_register(Preset(
    "eu_handheld_wide", "EU Handheld Wide", "EU",
    "License free handheld plus business land mobile. National splits vary.",
    (EU_PMR446, EU_LPD433, EU_LMR_VHF, EU_LMR_UHF),
    verify_locally=True,
))
_register(Preset(
    "eu_tetra", "EU TETRA", "EU",
    "Emergency and commercial TETRA allocations.",
    (EU_TETRA_EMERGENCY, EU_TETRA_COMMERCIAL),
    verify_locally=True,
))
_register(Preset(
    "eu_amateur", "EU Amateur", "EU",
    "Region 1 amateur 2 m and 70 cm allocations.",
    (EU_HAM_2M, EU_HAM_70CM),
))
_register(Preset(
    "eu_ism", "EU ISM and Unlicensed", "EU",
    "433 and 868 short range device bands plus 2.4 GHz.",
    (EU_LPD433, EU_SRD_868, ISM_2G4),
))

_register(Preset(
    "sa_handheld", "South America Handheld", "SA",
    "Region 2 style handheld UHF plus citizen band. Verify per country.",
    (SA_HANDHELD_UHF, SA_PX_27),
    verify_locally=True,
))
_register(Preset(
    "sa_handheld_wide", "South America Handheld Wide", "SA",
    "Handheld UHF plus VHF and UHF land mobile.",
    (SA_LMR_VHF, SA_LMR_UHF),
    verify_locally=True,
))
_register(Preset(
    "sa_amateur", "South America Amateur", "SA",
    "Region 2 amateur 2 m with the 430 to 440 sub band used regionally.",
    (SA_HAM_2M, SA_HAM_70CM),
))
_register(Preset(
    "sa_ism", "South America ISM", "SA",
    "Split 900 MHz ISM allocation plus 2.4 GHz. Reflects the Brazilian split.",
    (SA_ISM_915_LOWER, SA_ISM_915_UPPER, ISM_2G4),
    verify_locally=True,
))

_register(Preset(
    "wifi_24", "WiFi and Bluetooth 2.4 GHz", "GLOBAL",
    "2.4 GHz ISM only. Requires a 2.4 GHz antenna.",
    (ISM_2G4,),
))
_register(Preset(
    "wifi_5", "WiFi 5 GHz", "GLOBAL",
    "5 GHz unlicensed. Requires a 5 GHz antenna.",
    (WIFI_5G,),
))
_register(Preset(
    "validation_fm", "Validation, FM Broadcast", "GLOBAL",
    "Known good strong carriers. Use to confirm the capture and display chain.",
    (FM_BROADCAST,),
))
_register(Preset(
    "validation_airband", "Validation, Airband", "GLOBAL",
    "Naturally bursty AM voice. Use to confirm the burst detector fires.",
    (AIRBAND,),
))
_register(Preset(
    "validation_adsb", "Validation, ADS-B", "GLOBAL",
    "Dense short pulses. Stresses the detector at the fast end.",
    (ADSB,),
))
_register(Preset(
    "survey_vhf_uhf", "Survey 30 to 1000 MHz", "GLOBAL",
    "Discovery sweep. Finds persistent occupancy, will miss short bursts.",
    (SURVEY_VHF_UHF,),
))
_register(Preset(
    "full_device", "Full Device Range", "GLOBAL",
    "1 MHz to 6 GHz. Revisit interval makes burst detection unreliable.",
    (FULL_DEVICE,),
))


def list_presets(region: Optional[str] = None) -> List[Preset]:
    """Return presets, optionally filtered to one region, ordered for the UI."""
    items = list(PRESETS.values())
    if region is not None:
        wanted = region.upper()
        items = [p for p in items if p.region == wanted]
    order = {"US": 0, "EU": 1, "SA": 2, "GLOBAL": 3}
    return sorted(items, key=lambda p: (order.get(p.region, 9), p.name))


def get_preset(key: str) -> Preset:
    """Look up a preset by key, raising a clear error for an unknown key."""
    try:
        return PRESETS[key]
    except KeyError:
        raise KeyError(
            "unknown preset '{0}', known keys are {1}".format(
                key, ", ".join(sorted(PRESETS))
            )
        )


def validate_range(start_hz: int, stop_hz: int) -> None:
    """Reject ranges the hardware cannot tune before any device work happens."""
    if stop_hz <= start_hz:
        raise ValueError("stop frequency must exceed start frequency")
    if start_hz < HACKRF_MIN_HZ:
        raise ValueError(
            "start {0} Hz is below the HackRF lower limit of {1} Hz".format(
                start_hz, HACKRF_MIN_HZ
            )
        )
    if stop_hz > HACKRF_MAX_HZ:
        raise ValueError(
            "stop {0} Hz is above the HackRF upper limit of {1} Hz".format(
                stop_hz, HACKRF_MAX_HZ
            )
        )


def choose_sample_rate(band: Band, fft_size: int = DEFAULT_FFT_SIZE) -> int:
    """Pick the sample rate that covers a band in fewest segments, then finest.

    Two competing goals. A higher sample rate covers more spectrum per dwell and
    therefore needs fewer segments, which shortens the revisit interval. A lower
    sample rate produces a finer resolution bandwidth for a fixed FFT size, which
    is what separates adjacent narrowband channels. Segment count wins first
    because a missed burst cannot be recovered by better resolution, then among
    rates that tie on segment count the lowest is taken for the best resolution.
    """
    best_rate = HACKRF_SAMPLE_RATES_HZ[-1]
    best_segments = None
    for rate in HACKRF_SAMPLE_RATES_HZ:
        usable = rate * USABLE_FRACTION
        segments = max(1, int(-(-band.width_hz // int(usable))))
        # Reject any rate whose resolution bandwidth cannot separate the channel
        # spacing declared for this band. A resolution bandwidth wider than a
        # quarter of the spacing merges neighbouring channels into one return.
        if band.channel_spacing_hz is not None:
            rbw = rate / float(fft_size)
            if rbw > band.channel_spacing_hz / 4.0 and segments >= (best_segments or segments):
                if best_segments is not None:
                    continue
        if best_segments is None or segments < best_segments:
            best_segments = segments
            best_rate = rate
    return best_rate


def plan_segments(
    bands: List[Band],
    fft_size: int = DEFAULT_FFT_SIZE,
    averages: int = DEFAULT_AVERAGES,
) -> List[Segment]:
    """Expand a list of bands into the ordered tuner positions the sweeper walks.

    Segments are laid out so that their usable portions abut without gaps. The
    tuner center is offset from the usable window center by nothing, because the
    discarded filter skirt is symmetric, but the step between centers is the
    usable width rather than the full sample rate. That overlap is what prevents
    a signal sitting on a segment boundary from being attenuated by the filter
    skirt in both neighbouring segments and therefore missed in both.
    """
    segments: List[Segment] = []
    segment_id = 0
    for band in bands:
        validate_range(band.start_hz, band.stop_hz)
        rate = choose_sample_rate(band, fft_size)
        usable_width = int(rate * USABLE_FRACTION)
        cursor = band.start_hz
        while cursor < band.stop_hz:
            usable_stop = min(cursor + usable_width, band.stop_hz)
            center = (cursor + usable_stop) // 2
            # Clamp the tuner center so that the full sample rate window stays
            # inside the hardware range even when the usable window sits at the
            # very edge of the band.
            half_rate = rate // 2
            center = max(HACKRF_MIN_HZ + half_rate, min(center, HACKRF_MAX_HZ - half_rate))
            segments.append(Segment(
                segment_id=segment_id,
                band_name=band.name,
                center_hz=center,
                sample_rate_hz=rate,
                usable_start_hz=cursor,
                usable_stop_hz=usable_stop,
                fft_size=fft_size,
                averages=averages,
            ))
            segment_id += 1
            cursor = usable_stop
    return segments


def sweep_metrics(
    segments: List[Segment],
    detect_dwell_frames: int = DEFAULT_DETECT_DWELL_FRAMES,
) -> SweepMetrics:
    """Compute what a given segment plan can and cannot actually observe.

    Revisit interval is the sum of every segment dwell, since the sweeper returns
    to a given segment only after walking all the others. The minimum reliably
    detectable burst is longer still, because the detector requires a signal to
    be present on several consecutive visits before it opens an event. A burst
    shorter than that either never coincides with a visit, or coincides with too
    few visits to clear the dwell requirement.
    """
    if not segments:
        raise ValueError("segment plan is empty, no bands selected")

    revisit_ms = sum(seg.dwell_ms for seg in segments)
    total_span = sum(seg.usable_stop_hz - seg.usable_start_hz for seg in segments)
    coarsest_rbw = max(seg.rbw_hz for seg in segments)
    min_burst_ms = revisit_ms * detect_dwell_frames

    warnings: List[str] = []
    if revisit_ms > 500.0:
        warnings.append(
            "Revisit interval is {0:.0f} ms. Short transmissions will be missed. "
            "Treat this as a discovery survey, not burst capture.".format(revisit_ms)
        )
    if min_burst_ms > 2000.0:
        warnings.append(
            "Shortest reliably detected burst is about {0:.1f} s. Handheld voice "
            "traffic will be missed. Narrow the span to catch it.".format(min_burst_ms / 1000.0)
        )
    band_names = {seg.band_name for seg in segments}
    centers = [seg.center_hz for seg in segments]
    if centers and (max(centers) / float(min(centers))) > 4.0:
        warnings.append(
            "Selected bands span more than two octaves. No single antenna covers "
            "this range, so level differences between bands reflect antenna "
            "mismatch rather than signal strength. Compare within a band only."
        )
    if len(band_names) > 1 and coarsest_rbw > 5000.0:
        warnings.append(
            "Coarsest resolution bandwidth is {0:.0f} Hz. Narrowband channels "
            "spaced 12.5 kHz apart may not separate.".format(coarsest_rbw)
        )

    return SweepMetrics(
        segment_count=len(segments),
        total_span_hz=total_span,
        revisit_ms=revisit_ms,
        min_reliable_burst_ms=min_burst_ms,
        coarsest_rbw_hz=coarsest_rbw,
        warnings=warnings,
    )


def plan_from_preset(
    key: str,
    fft_size: int = DEFAULT_FFT_SIZE,
    averages: int = DEFAULT_AVERAGES,
) -> Tuple[List[Segment], SweepMetrics]:
    """Convenience path from a preset key to segments plus operator metrics."""
    preset = get_preset(key)
    segments = plan_segments(list(preset.bands), fft_size, averages)
    metrics = sweep_metrics(segments)
    if preset.verify_locally:
        metrics.warnings.append(
            "Allocations for this preset vary by national administration. Verify "
            "against the regulator table for the operating country."
        )
    return segments, metrics


def plan_from_custom_range(
    start_hz: int,
    stop_hz: int,
    channel_spacing_hz: Optional[int] = None,
    fft_size: int = DEFAULT_FFT_SIZE,
    averages: int = DEFAULT_AVERAGES,
) -> Tuple[List[Segment], SweepMetrics]:
    """Build a plan from an operator entered range rather than a preset."""
    validate_range(start_hz, stop_hz)
    band = Band("Custom", start_hz, stop_hz, channel_spacing_hz)
    segments = plan_segments([band], fft_size, averages)
    return segments, sweep_metrics(segments)


if __name__ == "__main__":
    # Self check. Prints the operator facing consequences of every preset so the
    # revisit math can be sanity checked without hardware attached.
    header = "{0:<34} {1:>5} {2:>11} {3:>10} {4:>11}".format(
        "Preset", "Segs", "Span", "Revisit", "Min burst"
    )
    print(header)
    print("-" * len(header))
    for preset in list_presets():
        try:
            segs, met = plan_from_preset(preset.key)
        except ValueError as exc:
            print("{0:<34} error {1}".format(preset.name, exc))
            continue
        print("{0:<34} {1:>5} {2:>9.1f} M {3:>8.0f} ms {4:>9.0f} ms".format(
            preset.name,
            met.segment_count,
            met.total_span_hz / 1e6,
            met.revisit_ms,
            met.min_reliable_burst_ms,
        ))
