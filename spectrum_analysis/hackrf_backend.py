#!/usr/bin/env python3
# =============================================================================
# Location: hackrf_backend.py
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
#   Direct ctypes binding to libhackrf. Loads the shared library already present
#   on the host and calls it, with no compilation step of any kind.
#
#   This exists because the compiled bindings available from the package index
#   declare the entire modern libhackrf API, including Opera Cake control, LED
#   override, board revision, and M0 core state. Any host whose libhackrf predates
#   those additions fails to compile the binding, and the failure is a wall of
#   C++ errors about functions this analyzer never calls. The library header says
#   as much itself, that an outdated host library leaves the new functions absent
#   and produces linking errors.
#
#   Binding at runtime inverts that. Symbols are resolved individually and only
#   when first used, so a function absent from an older library costs nothing
#   unless something actually calls it. The twenty functions bound here have all
#   existed since the first public libhackrf release, which makes this work
#   against essentially any version a host might carry, old distribution packages
#   included.
#
#   The transfer structure is defined explicitly rather than inferred. Its layout,
#   a device pointer followed by a buffer pointer, two integer lengths, and two
#   context pointers, has been unchanged across every release of the library, and
#   only the buffer pointer and the valid length are read here.
#
#   Callbacks are stored on the instance rather than passed transiently. A ctypes
#   callback object that is not referenced from Python is eligible for collection
#   while the library still holds its address, and the resulting call into freed
#   memory is a hard crash rather than an exception.
#
# SECURITY NOTICE:
#   This module is part of an RF spectrum analysis platform intended for
#   authorized red team engagements and defensive spectrum monitoring conducted
#   within a documented scope of engagement. Only receive side functions are
#   bound. No transmit entry point of the underlying library is declared here, so
#   transmission cannot be initiated through this module even by mistake. The
#   antenna port bias tee is bound solely so that it can be explicitly disabled,
#   since it feeds 3.3 V into whatever is attached to the antenna connector.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""Runtime ctypes binding to libhackrf, receive side only, no build step."""

import ctypes
import ctypes.util
import logging
import sys
import threading
from ctypes import (
    CFUNCTYPE, POINTER, Structure, c_char_p, c_double, c_int, c_uint8,
    c_uint32, c_uint64, c_void_p,
)
from typing import Callable, Dict, List, Optional

import numpy as np

LOG = logging.getLogger(__name__)

# Candidate shared library names by platform, most specific first. The versioned
# soname is preferred because it is what a distribution package installs, whereas
# the bare name is a development symlink that is often absent on a host carrying
# only the runtime package.
_LIBRARY_NAMES = {
    "linux": ("libhackrf.so.0", "libhackrf.so"),
    "darwin": ("libhackrf.0.dylib", "libhackrf.dylib"),
    "win32": ("hackrf.dll", "libhackrf.dll"),
}

HACKRF_SUCCESS = 0
HACKRF_TRUE = 1

# Returned when the device firmware is older than the called function requires.
HACKRF_ERROR_USB_API_VERSION = -1005

_ERROR_NAMES = {
    0: "success",
    -2: "invalid parameter",
    -5: "device not found",
    -6: "device busy, already open",
    -11: "out of memory",
    -1000: "libusb error",
    -1001: "transfer thread error",
    -1002: "streaming thread could not start",
    -1003: "streaming stopped due to an error",
    -1004: "streaming exited normally",
    HACKRF_ERROR_USB_API_VERSION: "device firmware is too old for this function",
    -2000: "device still in use, cannot exit library",
    -9999: "unspecified error",
}


class HackRFError(Exception):
    """Raised for any libhackrf call that does not return success."""


class HackRFTransfer(Structure):
    """Mirror of hackrf_transfer.

    Layout is fixed by the library and has not changed across releases. Only
    buffer and valid_length are read, but every field is declared so that the
    structure size and the offsets of the fields that matter are correct.
    """

    _fields_ = [
        ("device", c_void_p),
        ("buffer", POINTER(c_uint8)),
        ("buffer_length", c_int),
        ("valid_length", c_int),
        ("rx_ctx", c_void_p),
        ("tx_ctx", c_void_p),
    ]


class HackRFDeviceList(Structure):
    """Mirror of hackrf_device_list_t, used only for enumeration."""

    _fields_ = [
        ("serial_numbers", POINTER(c_char_p)),
        ("usb_board_ids", POINTER(c_int)),
        ("usb_device_index", POINTER(c_int)),
        ("devicecount", c_int),
        ("usb_devices", POINTER(c_void_p)),
        ("usb_devicecount", c_int),
    ]


# Signature of the sample block callback the library invokes from its transfer
# thread. ctypes acquires the interpreter lock before entering Python here.
SAMPLE_BLOCK_CALLBACK = CFUNCTYPE(c_int, POINTER(HackRFTransfer))


def _load_library():
    """Locate and load libhackrf, returning None when it is not installed."""
    names = _LIBRARY_NAMES.get(sys.platform, _LIBRARY_NAMES["linux"])
    for name in names:
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue

    # Fall back to the platform's own library search, which handles prefixes the
    # names above do not anticipate, such as a Homebrew or /usr/local install.
    found = ctypes.util.find_library("hackrf")
    if found:
        try:
            return ctypes.CDLL(found)
        except OSError:
            pass
    return None


_lib = _load_library()
LIBRARY_AVAILABLE = _lib is not None


def _bind(name: str, restype, argtypes, required: bool = True):
    """Resolve one symbol, tolerating absence for functions added later.

    Resolving individually is what makes this work against old libraries. A
    binding that declares the whole modern API fails wholesale on a host missing
    any part of it, whereas an absent symbol here simply yields None and only
    matters if something calls it.
    """
    if _lib is None:
        return None
    try:
        function = getattr(_lib, name)
    except AttributeError:
        if required:
            LOG.warning("libhackrf is missing %s, which this application needs", name)
        return None
    function.restype = restype
    function.argtypes = argtypes
    return function


if LIBRARY_AVAILABLE:
    _init = _bind("hackrf_init", c_int, [])
    _exit = _bind("hackrf_exit", c_int, [])
    _library_version = _bind("hackrf_library_version", c_char_p, [], required=False)
    _library_release = _bind("hackrf_library_release", c_char_p, [], required=False)
    _error_name = _bind("hackrf_error_name", c_char_p, [c_int], required=False)

    _device_list = _bind("hackrf_device_list", POINTER(HackRFDeviceList), [])
    _device_list_open = _bind("hackrf_device_list_open", c_int,
                              [POINTER(HackRFDeviceList), c_int, POINTER(c_void_p)])
    _device_list_free = _bind("hackrf_device_list_free", None, [POINTER(HackRFDeviceList)])
    _board_id_name = _bind("hackrf_usb_board_id_name", c_char_p, [c_int], required=False)

    _open = _bind("hackrf_open", c_int, [POINTER(c_void_p)])
    _open_by_serial = _bind("hackrf_open_by_serial", c_int, [c_char_p, POINTER(c_void_p)])
    _close = _bind("hackrf_close", c_int, [c_void_p])

    _set_freq = _bind("hackrf_set_freq", c_int, [c_void_p, c_uint64])
    _set_sample_rate = _bind("hackrf_set_sample_rate", c_int, [c_void_p, c_double])
    _set_baseband_filter = _bind("hackrf_set_baseband_filter_bandwidth", c_int,
                                 [c_void_p, c_uint32])
    _compute_filter_bw = _bind("hackrf_compute_baseband_filter_bw", c_uint32,
                               [c_uint32], required=False)

    _set_amp = _bind("hackrf_set_amp_enable", c_int, [c_void_p, c_uint8])
    _set_lna = _bind("hackrf_set_lna_gain", c_int, [c_void_p, c_uint32])
    _set_vga = _bind("hackrf_set_vga_gain", c_int, [c_void_p, c_uint32])
    _set_antenna = _bind("hackrf_set_antenna_enable", c_int, [c_void_p, c_uint8])

    _start_rx = _bind("hackrf_start_rx", c_int, [c_void_p, SAMPLE_BLOCK_CALLBACK, c_void_p])
    _stop_rx = _bind("hackrf_stop_rx", c_int, [c_void_p])
    _is_streaming = _bind("hackrf_is_streaming", c_int, [c_void_p])

    # Present only on newer libraries. Absence is expected and handled, since
    # neither is needed for single radio operation.
    _get_clkin_status = _bind("hackrf_get_clkin_status", c_int,
                              [c_void_p, POINTER(c_uint8)], required=False)
    _set_clkout_enable = _bind("hackrf_set_clkout_enable", c_int,
                               [c_void_p, c_uint8], required=False)


# The library init and exit calls are global rather than per device and must not
# be re-entered concurrently.
_LIB_LOCK = threading.Lock()
_LIB_REFCOUNT = 0


def _check(result: int, operation: str) -> None:
    """Raise with a readable message when a library call fails."""
    if result == HACKRF_SUCCESS:
        return
    detail = _ERROR_NAMES.get(result)
    if detail is None and _error_name is not None:
        try:
            detail = _error_name(result).decode("utf-8", "replace")
        except Exception:
            detail = None
    raise HackRFError("{0} failed: {1} ({2})".format(
        operation, detail or "unknown error", result))


def library_version() -> str:
    """Human readable libhackrf version, for logs and diagnostics."""
    if not LIBRARY_AVAILABLE:
        return "not installed"
    parts = []
    for getter in (_library_release, _library_version):
        if getter is None:
            continue
        try:
            value = getter()
            if value:
                parts.append(value.decode("utf-8", "replace"))
        except Exception:
            continue
    return " ".join(parts) if parts else "unknown"


def library_acquire() -> None:
    """Initialize the library on first use, reference counted."""
    global _LIB_REFCOUNT
    if not LIBRARY_AVAILABLE:
        raise HackRFError("libhackrf is not installed on this host")
    with _LIB_LOCK:
        if _LIB_REFCOUNT == 0:
            _check(_init(), "hackrf_init")
        _LIB_REFCOUNT += 1


def library_release() -> None:
    """Shut the library down once the last user has finished."""
    global _LIB_REFCOUNT
    if not LIBRARY_AVAILABLE:
        return
    with _LIB_LOCK:
        _LIB_REFCOUNT = max(0, _LIB_REFCOUNT - 1)
        if _LIB_REFCOUNT == 0:
            try:
                _exit()
            except Exception as exc:
                LOG.debug("library exit raised: %s", exc)


def list_devices() -> List[Dict]:
    """Enumerate attached HackRFs without opening any of them."""
    if not LIBRARY_AVAILABLE:
        return []

    library_acquire()
    try:
        listing = _device_list()
        if not listing:
            return []
        try:
            devices = []
            for index in range(listing.contents.devicecount):
                serial = listing.contents.serial_numbers[index]
                board_id = listing.contents.usb_board_ids[index]
                name = "HackRF"
                if _board_id_name is not None:
                    try:
                        name = _board_id_name(board_id).decode("utf-8", "replace")
                    except Exception:
                        pass
                devices.append({
                    "index": index,
                    "driver": "hackrf",
                    "serial": serial.decode("utf-8", "replace") if serial else "",
                    "board": name,
                })
            return devices
        finally:
            _device_list_free(listing)
    finally:
        library_release()


class HackRFDevice:
    """One open HackRF, receive side only.

    Holds the library reference count and the callback reference for its own
    lifetime, so that closing is sufficient to release everything.
    """

    def __init__(self, serial: Optional[str] = None):
        self.serial = serial
        self._handle = c_void_p()
        self._callback_ref = None
        self._acquired = False
        self._streaming = False

    def open(self) -> None:
        """Open the device, by serial when one is given."""
        library_acquire()
        self._acquired = True
        try:
            if self.serial:
                encoded = self.serial.encode("utf-8")
                _check(_open_by_serial(encoded, ctypes.byref(self._handle)),
                       "hackrf_open_by_serial")
            else:
                _check(_open(ctypes.byref(self._handle)), "hackrf_open")
        except Exception:
            self._handle = c_void_p()
            library_release()
            self._acquired = False
            raise

    def close(self) -> None:
        """Stop streaming and release the device, tolerating a partial open."""
        if self._handle:
            if self._streaming:
                try:
                    _stop_rx(self._handle)
                except Exception as exc:
                    LOG.debug("stop_rx raised during close: %s", exc)
            try:
                _close(self._handle)
            except Exception as exc:
                LOG.debug("close raised during close: %s", exc)

        self._handle = c_void_p()
        self._streaming = False
        # Released only after the library is done with it, since the library
        # calls into this object from its transfer thread until stop returns.
        self._callback_ref = None

        if self._acquired:
            library_release()
            self._acquired = False

    def _require_open(self) -> None:
        if not self._handle:
            raise HackRFError("device is not open")

    def set_freq(self, freq_hz: int) -> None:
        self._require_open()
        _check(_set_freq(self._handle, c_uint64(int(freq_hz))), "hackrf_set_freq")

    def set_sample_rate(self, rate_hz: float) -> None:
        """Set the sample rate.

        The library resets the baseband filter to a default derived from the rate
        as a side effect of this call, so any explicit filter setting has to come
        afterwards.
        """
        self._require_open()
        _check(_set_sample_rate(self._handle, c_double(float(rate_hz))),
               "hackrf_set_sample_rate")

    def set_baseband_filter_bandwidth(self, bandwidth_hz: int) -> None:
        self._require_open()
        _check(_set_baseband_filter(self._handle, c_uint32(int(bandwidth_hz))),
               "hackrf_set_baseband_filter_bandwidth")

    def set_amp_enable(self, enabled: bool) -> None:
        self._require_open()
        _check(_set_amp(self._handle, c_uint8(1 if enabled else 0)),
               "hackrf_set_amp_enable")

    def set_lna_gain(self, gain_db: int) -> None:
        self._require_open()
        _check(_set_lna(self._handle, c_uint32(int(gain_db))), "hackrf_set_lna_gain")

    def set_vga_gain(self, gain_db: int) -> None:
        self._require_open()
        _check(_set_vga(self._handle, c_uint32(int(gain_db))), "hackrf_set_vga_gain")

    def set_antenna_enable(self, enabled: bool) -> None:
        """Control the antenna port bias tee.

        Bound so that it can be turned off deliberately. It supplies 3.3 V to
        whatever is connected to the antenna port, which will damage a passive
        antenna or a splitter that is not expecting it.
        """
        self._require_open()
        _check(_set_antenna(self._handle, c_uint8(1 if enabled else 0)),
               "hackrf_set_antenna_enable")

    def start_rx(self, callback: Callable[[np.ndarray], None]) -> None:
        """Begin streaming, delivering each transfer to a Python callable.

        The supplied callable receives a numpy int8 array holding the valid part
        of the transfer, already copied out of the library's buffer. The library
        reuses that buffer immediately on return, so handing out a view would
        expose data that changes underneath the consumer.
        """
        self._require_open()

        def _trampoline(transfer_ptr) -> int:
            try:
                transfer = transfer_ptr.contents
                valid = int(transfer.valid_length)
                if valid > 0:
                    raw = ctypes.string_at(transfer.buffer, valid)
                    callback(np.frombuffer(raw, dtype=np.int8))
            except Exception as exc:
                LOG.error("receive callback raised: %s", exc)
            # Zero asks the library to keep calling. Returning anything else
            # stops the stream, so every path here has to return zero including
            # the error path.
            return 0

        # Retained for the lifetime of the stream. A callback object collected
        # while the library still holds its address produces a call into freed
        # memory, which crashes the interpreter rather than raising.
        self._callback_ref = SAMPLE_BLOCK_CALLBACK(_trampoline)

        _check(_start_rx(self._handle, self._callback_ref, None), "hackrf_start_rx")
        self._streaming = True

    def stop_rx(self) -> None:
        self._require_open()
        _check(_stop_rx(self._handle), "hackrf_stop_rx")
        self._streaming = False

    def is_streaming(self) -> bool:
        if not self._handle:
            return False
        return _is_streaming(self._handle) == HACKRF_TRUE

    def clkin_detected(self) -> Optional[bool]:
        """Whether an external reference is present on the clock input.

        Returns None where the library or the device firmware predates this
        query. Unused by the single radio analyzer, and present for the dual
        radio configuration where the second receiver is slaved to this one's
        clock output and confirming the reference is the difference between a
        shared timebase and silent drift.
        """
        if _get_clkin_status is None or not self._handle:
            return None
        status = c_uint8(0)
        result = _get_clkin_status(self._handle, ctypes.byref(status))
        if result != HACKRF_SUCCESS:
            return None
        return bool(status.value)

    def set_clkout_enable(self, enabled: bool) -> bool:
        """Enable the clock output. Returns False where it is unsupported."""
        if _set_clkout_enable is None or not self._handle:
            return False
        return _set_clkout_enable(self._handle, c_uint8(1 if enabled else 0)) == HACKRF_SUCCESS
