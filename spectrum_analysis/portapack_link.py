#!/usr/bin/env python3
# =============================================================================
# Location: portapack_link.py
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
#   Control link to a second receiver carrying a PortaPack running Mayhem firmware,
#   used as the listening radio while the primary HackRF sweeps.
#
#   The split is forced by hardware. A PortaPack exposes its serial console only in
#   normal Mayhem mode, and the mode that presents it to a host as an ordinary
#   HackRF is the one mode where that console is gone. So the PortaPack unit cannot
#   sweep; it runs its own receiver app, demodulates, and produces audio at its own
#   headphone jack while this module only tells it where to tune.
#
#   Frequencies handed across are true frequencies. The sweeper's oscillator error
#   is already removed; the listener's is its own and is corrected on the device.
#   Capabilities are probed at connect and every tune is read back, since a command
#   the firmware silently ignores otherwise leaves the operator on the old
#   frequency while the interface claims otherwise.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software.
# =============================================================================

"""Serial control of a Mayhem PortaPack used as the listening receiver."""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

LOG = logging.getLogger(__name__)

try:
    import serial
    from serial.tools import list_ports
    SERIAL_AVAILABLE = True
except ImportError:
    serial = None
    list_ports = None
    SERIAL_AVAILABLE = False

# The console is a ChibiOS shell. Its prompt is what marks the end of a reply,
# since replies are variable length and carry no terminator of their own.
PROMPT = "ch>"

# Mayhem presents a CDC serial device. The identifiers are not relied upon for
# discovery, because a HackRF changes what it enumerates as depending on mode and
# a USB to serial adapter may sit in the way, but they order the candidates so the
# likely port is probed first.
PROBE_VID_PID = ((0x1D50, 0x6018), (0x1D50, 0x6089), (0x1FC9, 0x000C))

DEFAULT_BAUD = 115200
DEFAULT_TIMEOUT_S = 2.0

# Commands this module needs. Absence of any of these means the firmware predates
# host controlled tuning and the operator has to flash before the handoff works.
REQUIRED_COMMANDS = ("setfreq", "appstart", "applist", "radioinfo")

# Receiver applications that accept setfreq, in preference order. The firmware
# documents setfreq as effective only in a subset of receive applications, so
# starting one outside that subset produces a link that appears healthy and
# silently ignores every retune.
TUNABLE_APPS = ("audio", "capture", "level", "looking glass", "weather")


class PortaPackError(Exception):
    """Raised for any failure of the listener control link."""


@dataclass
class ListenerState:
    """What the link currently believes about the attached device."""

    connected: bool = False
    port: Optional[str] = None
    firmware: str = ""
    commands: frozenset = frozenset()
    app_short: Optional[str] = None
    app_name: str = ""
    frequency_hz: int = 0
    modulation: str = ""
    missing: tuple = ()
    message: str = ""

    def to_dict(self) -> Dict:
        return {
            "connected": self.connected,
            "port": self.port,
            "firmware": self.firmware,
            "app": self.app_name,
            "frequency_hz": self.frequency_hz,
            "modulation": self.modulation,
            "missing": list(self.missing),
            "message": self.message,
        }


# Reported by radioinfo as an integer. Named here purely for display, since this
# module never sets it. Mayhem's setfreq changes frequency only, so the
# demodulation mode is whatever the operator last selected on the device itself.
MODULATION_NAMES = {0: "AM", 1: "NBFM", 2: "WFM", 3: "SPEC"}


def available_ports() -> List[Dict]:
    """Serial ports on this host, likely PortaPack candidates first."""
    if not SERIAL_AVAILABLE:
        return []
    entries = []
    for info in list_ports.comports():
        pair = (info.vid, info.pid)
        entries.append({
            "device": info.device,
            "description": info.description or "",
            "vid": info.vid,
            "pid": info.pid,
            "likely": pair in PROBE_VID_PID,
        })
    entries.sort(key=lambda e: (not e["likely"], e["device"]))
    return entries


class PortaPackLink:
    """Serial console client for a PortaPack running Mayhem.

    All access is serialized behind a lock. The console is a single command and
    response shell with no multiplexing, so two callers interleaving writes would
    each read part of the other's reply.
    """

    def __init__(self, port: Optional[str] = None, baudrate: int = DEFAULT_BAUD,
                 timeout: float = DEFAULT_TIMEOUT_S):
        self.port = port
        self.baudrate = int(baudrate)
        self.timeout = float(timeout)
        self._serial = None
        self._lock = threading.RLock()
        self.state = ListenerState()

    # -- connection ----------------------------------------------------------

    def connect(self, port: Optional[str] = None) -> ListenerState:
        """Open the console, identify the firmware, and start a tunable app."""
        if not SERIAL_AVAILABLE:
            raise PortaPackError(
                "pyserial is not installed, the listener link is unavailable")

        target = port or self.port
        candidates = [target] if target else [e["device"] for e in available_ports()]
        if not candidates:
            raise PortaPackError("no serial ports found")

        last_error = "no PortaPack console responded"
        for device in candidates:
            try:
                if self._try_port(device):
                    return self.state
            except PortaPackError as exc:
                last_error = str(exc)
                self.disconnect()
            except Exception as exc:
                last_error = "{0}: {1}".format(device, exc)
                self.disconnect()

        raise PortaPackError(last_error)

    def _try_port(self, device: str) -> bool:
        """Open one port and decide whether a Mayhem console is behind it."""
        with self._lock:
            self._serial = serial.Serial(device, self.baudrate, timeout=self.timeout)
            # Discard whatever the device emitted before the port was opened, so
            # the first reply read is a reply to a command of ours.
            time.sleep(0.2)
            self._serial.reset_input_buffer()

            reply = self._raw_command("help", timeout=3.0)
            if not reply:
                raise PortaPackError("{0}: no response to help".format(device))

            commands = self._parse_commands(reply)
            if "setfreq" not in commands and "reboot" not in commands:
                raise PortaPackError("{0}: not a Mayhem console".format(device))

            self.port = device
            self.state = ListenerState(
                connected=True,
                port=device,
                commands=frozenset(commands),
                missing=tuple(c for c in REQUIRED_COMMANDS if c not in commands),
            )

            if self.state.missing:
                # Connected but not useful. Reported plainly rather than left to
                # surface as a silent failure on the first retune.
                self.state.message = (
                    "firmware predates host tuning, missing: {0}. "
                    "Update Mayhem to use the listener.".format(
                        ", ".join(self.state.missing))
                )
                LOG.warning("%s", self.state.message)
                return True

            self.state.firmware = self._read_firmware()
            self._select_app()
            self.refresh()
            return True

    def disconnect(self) -> None:
        """Close the port. The device keeps running whatever it was running."""
        with self._lock:
            if self._serial is not None:
                try:
                    self._serial.close()
                except Exception as exc:
                    LOG.debug("closing listener port raised: %s", exc)
            self._serial = None
            self.state = ListenerState(port=self.port)

    @property
    def connected(self) -> bool:
        return self._serial is not None and self.state.connected

    # -- console primitives --------------------------------------------------

    def _raw_command(self, text: str, timeout: Optional[float] = None) -> List[str]:
        """Send one command and collect lines until the prompt returns.

        Reading to the prompt rather than to a line count is what makes this
        robust across firmware versions, since the same command returns different
        numbers of lines as the firmware grows.
        """
        if self._serial is None:
            raise PortaPackError("not connected")

        deadline = time.monotonic() + (timeout or self.timeout)
        self._serial.reset_input_buffer()
        self._serial.write((text + "\r\n").encode("ascii", "ignore"))
        self._serial.flush()

        lines: List[str] = []
        buffer = ""
        while time.monotonic() < deadline:
            chunk = self._serial.read(256)
            if chunk:
                buffer += chunk.decode("utf-8", "replace")
                if PROMPT in buffer:
                    break
            elif buffer:
                break

        for line in buffer.replace("\r", "").split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith(PROMPT):
                continue
            # The shell echoes the command back before replying.
            if stripped == text:
                continue
            lines.append(stripped)
        return lines

    def command(self, text: str, timeout: Optional[float] = None) -> List[str]:
        """Public command entry point, serialized against other callers."""
        with self._lock:
            return self._raw_command(text, timeout)

    @staticmethod
    def _parse_commands(reply: List[str]) -> set:
        """Extract command names from the help listing.

        The listing has changed format across releases, appearing as a single
        space separated line in some and one entry per line in others, so both are
        accepted rather than matching an exact shape.
        """
        commands = set()
        for line in reply:
            body = line.split(":", 1)[0]
            for token in body.replace(",", " ").split():
                token = token.strip("-*[]()")
                if token and all(c.isalnum() or c == "_" for c in token):
                    commands.add(token.lower())
        return commands

    def _read_firmware(self) -> str:
        """Best effort firmware identification, for the operator display."""
        for probe in ("sysinfo", "info"):
            try:
                reply = self._raw_command(probe)
            except PortaPackError:
                continue
            for line in reply:
                lowered = line.lower()
                if "version" in lowered or "mayhem" in lowered:
                    return line
        return "unknown"

    # -- application and tuning ---------------------------------------------

    def app_list(self) -> Dict[str, str]:
        """Applications the device can start, as short name to full name."""
        apps: Dict[str, str] = {}
        for line in self._raw_command("applist", timeout=4.0):
            parts = [p.strip() for p in line.split(" ") if p.strip()]
            if len(parts) < 2:
                continue
            apps[parts[0].lower()] = " ".join(parts[1:])
        return apps

    def _select_app(self) -> None:
        """Start a receiver application that honours setfreq.

        The firmware accepts setfreq only within a subset of receive
        applications. Starting anything outside that subset yields a link that
        connects cleanly and then ignores every retune, which is a considerably
        worse failure than refusing to start.
        """
        apps = self.app_list()
        if not apps:
            self.state.message = "device returned no application list"
            return

        chosen = None
        for wanted in TUNABLE_APPS:
            for short, full in apps.items():
                haystack = "{0} {1}".format(short, full).lower()
                if wanted in haystack:
                    chosen = (short, full)
                    break
            if chosen:
                break

        if chosen is None:
            self.state.message = (
                "no application accepting setfreq was found on the device")
            return

        short, full = chosen
        self._raw_command("appstart {0}".format(short), timeout=4.0)
        self.state.app_short = short
        self.state.app_name = full
        LOG.info("listener running %s (%s)", full, short)

    def set_frequency(self, frequency_hz: float) -> int:
        """Tune the listener and confirm the device took the value.

        The reported frequency is read back rather than trusted. A command that
        the firmware silently rejects, because the running application does not
        accept setfreq or the value is outside its range, otherwise leaves the
        operator listening to the previous frequency while the interface claims
        otherwise.
        """
        with self._lock:
            if not self.connected:
                raise PortaPackError("listener is not connected")
            if self.state.missing:
                raise PortaPackError(self.state.message)

            target = int(round(float(frequency_hz)))
            if not 1_000_000 <= target <= 6_000_000_000:
                raise PortaPackError("{0} Hz is outside the tuning range".format(target))

            if self.state.app_short is None:
                self._select_app()

            self._raw_command("setfreq {0}".format(target), timeout=3.0)
            self.refresh()

            # A kilohertz of tolerance. The device reports what its synthesizer
            # actually resolved to, which need not equal the requested value.
            if abs(self.state.frequency_hz - target) > 1_000:
                raise PortaPackError(
                    "device reports {0:.6f} MHz after being asked for {1:.6f} MHz. "
                    "The running application may not accept setfreq.".format(
                        self.state.frequency_hz / 1e6, target / 1e6))
            return self.state.frequency_hz

    def refresh(self) -> ListenerState:
        """Read back the device's current receive settings."""
        with self._lock:
            if not self.connected:
                return self.state
            for line in self._raw_command("radioinfo", timeout=3.0):
                if ":" not in line:
                    continue
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                if key == "receiver_model.target_frequency":
                    try:
                        self.state.frequency_hz = int(value)
                    except ValueError:
                        pass
                elif key == "receiver_model.modulation":
                    try:
                        self.state.modulation = MODULATION_NAMES.get(
                            int(value), "mode {0}".format(value))
                    except ValueError:
                        self.state.modulation = value
            return self.state
