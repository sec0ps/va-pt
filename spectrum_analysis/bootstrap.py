#!/usr/bin/env python3
# =============================================================================
# Location: bootstrap.py
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
#   Brings the host from nothing to a running analyzer. Creates the virtual
#   environment, installs the Python dependencies, resolves the system libraries
#   the HackRF driver builds against, and re-enters the environment. Every launch
#   after the first is a fast no operation.
#
#   This module imports nothing outside the standard library and must be imported
#   before any third party package anywhere in the application. If numpy or Qt
#   were imported first, the process would fail on a missing dependency before any
#   code capable of installing that dependency had run.
#
#   The environment is created with system site packages visible so that a HackRF
#   driver already provided by the distribution is usable without reinstalling it,
#   while packages installed into the environment still take precedence.
#
#   Three layers of dependency are handled differently and deliberately:
#
#   Core Python packages are mandatory. Without numpy or Qt there is no
#   application, so a failure here aborts.
#
#   The HackRF driver is optional. It is a source distribution that links against
#   the installed HackRF host software, so on a machine without build tooling it
#   cannot be built. That degrades the application to the synthetic and replay
#   sources rather than stopping it, which is correct, since neither needs a radio.
#
#   System libraries are optional and privileged. Resolving them means installing
#   distribution packages, which requires root. Elevation is never silent. If
#   passwordless sudo is configured the command runs directly, otherwise the exact
#   command is displayed and consent is requested once. With no terminal available
#   to ask on, the instructions are printed and the application continues without
#   hardware support rather than blocking on a prompt nobody can see.
#
# SECURITY NOTICE:
#   This module installs packages from the configured Python package index and,
#   with consent, from the distribution package repository using elevated
#   privileges. Both pull and execute third party code. On an engagement host with
#   restricted or monitored egress, provision the environment ahead of deployment
#   and launch with bootstrapping disabled rather than allowing an unplanned
#   outbound connection or a privileged package transaction during an operation.
#   Dependencies are version floored rather than pinned to an exact hash, so an
#   upstream supply chain compromise is not detected here. Elevation is requested
#   only to install the named build libraries, the command is shown before it
#   runs, and it can be refused without preventing the application from starting.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""Environment creation, dependency provisioning, and application re-entry."""

import importlib.util
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

# Directory name for the environment, created beside this file so that each
# checkout carries its own and several nodes on one host do not collide.
VENV_DIR_NAME = ".venv"

# Set once re-entry has happened. Its presence stops a failed environment from
# re-executing itself forever, which would otherwise fork bomb the host on any
# condition leaving a dependency unimportable after installation.
GUARD_ENV = "RCS_SPECTRUM_BOOTSTRAPPED"

# Import name mapped to pip requirement. The two differ often enough that
# checking for the pip name would report a satisfied dependency as missing.
REQUIREMENTS = {
    "numpy": "numpy>=1.24",
    "scipy": "scipy>=1.10",
    "PySide6": "PySide6>=6.5",
    "pyqtgraph": "pyqtgraph>=0.13",
}

# Hardware support. Installed from pip like the others, but a failure is not fatal
# because the synthetic and replay sources remain usable without a radio.
OPTIONAL_REQUIREMENTS = {
    "python_hackrf": "python-hackrf>=1.5",
}

# Libraries the HackRF driver compiles against, as a pkg-config name paired with
# the headers that prove the library present when pkg-config is unavailable.
#
# Several header candidates are listed per library because distributions do not
# agree on the layout. Debian and Ubuntu place the HackRF header inside a
# libhackrf subdirectory while several source builds drop it directly into the
# include root, and checking only one location reports an installed library as
# missing, which would trigger a pointless privileged package install on every
# single launch.
NATIVE_LIBRARIES = (
    ("libhackrf", ("libhackrf/hackrf.h", "hackrf.h")),
    ("libusb-1.0", ("libusb-1.0/libusb.h", "libusb.h")),
)

# Directories searched for headers when pkg-config cannot answer.
HEADER_SEARCH_PATHS = (
    "/usr/include",
    "/usr/local/include",
    "/opt/homebrew/include",
    "/opt/local/include",
)

# Distribution package managers in preference order, with the packages that
# supply the HackRF and USB development files plus the toolchain needed to build
# a Cython extension. The driver is a source distribution, so a compiler and the
# Python development headers are as necessary as the radio libraries themselves.
PACKAGE_MANAGERS = (
    {
        "binary": "apt-get",
        "packages": ["libhackrf-dev", "libusb-1.0-0-dev", "pkg-config",
                     "python3-dev", "build-essential"],
        "refresh": ["apt-get", "update"],
        "install": ["apt-get", "install", "-y"],
        "needs_root": True,
    },
    {
        "binary": "dnf",
        "packages": ["hackrf-devel", "libusb1-devel", "pkgconf-pkg-config",
                     "python3-devel", "gcc"],
        "refresh": None,
        "install": ["dnf", "install", "-y"],
        "needs_root": True,
    },
    {
        "binary": "pacman",
        "packages": ["hackrf", "libusb", "pkgconf", "base-devel"],
        "refresh": None,
        "install": ["pacman", "-S", "--needed", "--noconfirm"],
        "needs_root": True,
    },
    {
        "binary": "zypper",
        "packages": ["hackrf-devel", "libusb-1_0-devel", "pkg-config",
                     "python3-devel", "gcc"],
        "refresh": None,
        "install": ["zypper", "--non-interactive", "install"],
        "needs_root": True,
    },
    {
        # Homebrew refuses to run as root and manages its own prefix, so it is
        # invoked as the current user with no elevation at all.
        "binary": "brew",
        "packages": ["hackrf", "libusb", "pkg-config"],
        "refresh": None,
        "install": ["brew", "install"],
        "needs_root": False,
    },
)

WINDOWS_HINT = (
    "install the HackRF host tools, for example through PothosSDR, then set "
    "PYTHON_HACKRF_INCLUDE_PATH to the directory holding hackrf.h and "
    "PYTHON_HACKRF_LIB_PATH to the directory holding libhackrf.dll"
)


def project_root() -> Path:
    """Directory holding the application, and therefore the environment."""
    return Path(__file__).resolve().parent


def venv_path() -> Path:
    return project_root() / VENV_DIR_NAME


def venv_python(base: Path = None) -> Path:
    """Interpreter path inside the environment, which differs by platform."""
    base = base or venv_path()
    if os.name == "nt":
        return base / "Scripts" / "python.exe"
    return base / "bin" / "python"


def in_target_venv() -> bool:
    """True when the running interpreter is the one inside the environment.

    Compares resolved prefixes rather than checking for any active environment,
    because a developer sitting in an unrelated environment would otherwise be
    treated as provisioned and would fail later on a missing dependency.
    """
    try:
        return Path(sys.prefix).resolve() == venv_path().resolve()
    except OSError:
        return False


def module_present(import_name: str) -> bool:
    """Whether a module can be resolved without importing it."""
    try:
        return importlib.util.find_spec(import_name) is not None
    except (ImportError, ValueError):
        return False


def missing_requirements() -> list:
    """Pip requirements whose import name cannot be resolved."""
    return [req for name, req in REQUIREMENTS.items() if not module_present(name)]


def install_requirements(python: Path, requirements: list, fatal: bool = True) -> bool:
    """Install the given requirements into the environment.

    Optional requirements pass fatal as False so that a build failure on a host
    without the HackRF development headers produces a warning rather than an
    abort. Output is captured in that case and replayed only on failure, so a
    successful optional install stays quiet while a failed one is still
    diagnosable.
    """
    if not requirements:
        return True
    print("[bootstrap] installing: {0}".format(", ".join(requirements)))
    command = [str(python), "-m", "pip", "install", "--upgrade"] + requirements
    try:
        result = subprocess.run(command, check=False,
                                capture_output=not fatal, text=not fatal)
    except OSError as exc:
        print("[bootstrap] pip could not be launched: {0}".format(exc))
        return False

    if result.returncode == 0:
        return True

    output = "{0}\n{1}".format(result.stdout or "", result.stderr or "") if not fatal else ""

    # A system Python managed by the distribution refuses installation outright.
    # Reported specifically, because the generic failure message sends the
    # operator hunting for a build problem that does not exist.
    if "externally-managed-environment" in output:
        print("[bootstrap] this interpreter is managed by the distribution and "
              "refuses package installation.")
        print("[bootstrap] run without --no-bootstrap so the virtual environment "
              "is used, or install the package yourself.")
        return False

    print("[bootstrap] installation of {0} failed with code {1}".format(
        ", ".join(requirements), result.returncode))
    if output.strip():
        tail = [line for line in output.splitlines() if line.strip()][-8:]
        for line in tail:
            print("[bootstrap]   {0}".format(line))
    return False


# -----------------------------------------------------------------------------
# Native library resolution
# -----------------------------------------------------------------------------

def _pkgconfig_has(name: str) -> bool:
    """Ask pkg-config whether a library is installed and discoverable."""
    if shutil.which("pkg-config") is None:
        return False
    try:
        result = subprocess.run(["pkg-config", "--exists", name],
                                check=False, capture_output=True)
        return result.returncode == 0
    except OSError:
        return False


def _header_present(relative_headers) -> bool:
    """Search the usual include directories for any of a header's known layouts.

    Fallback for hosts without pkg-config, and for prefixes it does not know
    about. Environment supplied include paths are searched first, since a non
    standard HackRF install is exactly the case this has to cover.
    """
    directories = list(HEADER_SEARCH_PATHS)
    for variable in ("PYTHON_HACKRF_INCLUDE_PATH", "CPATH", "C_INCLUDE_PATH"):
        value = os.environ.get(variable)
        if value:
            directories = value.split(os.pathsep) + directories

    return any(
        Path(directory, header).exists()
        for directory in directories if directory
        for header in relative_headers
    )


def missing_native_libraries() -> list:
    """Native libraries the driver needs that cannot be found on this host."""
    missing = []
    for pkgconfig_name, headers in NATIVE_LIBRARIES:
        if _pkgconfig_has(pkgconfig_name) or _header_present(headers):
            continue
        missing.append(pkgconfig_name)
    return missing


def _compiler_present() -> bool:
    """Whether anything capable of building a C extension is on the path."""
    return any(shutil.which(name) for name in ("cc", "gcc", "clang"))


def detect_package_manager() -> dict:
    """First supported package manager available on this host."""
    for manager in PACKAGE_MANAGERS:
        if shutil.which(manager["binary"]):
            return manager
    return None


def _elevation_prefix(manager: dict, assume_yes: bool) -> list:
    """Decide how, or whether, to elevate for a package transaction.

    Returns the command prefix to use, an empty list when no elevation is needed,
    or None when elevation is impossible or refused. Nothing here runs a command,
    so the caller can display exactly what will execute before it does.
    """
    if not manager["needs_root"]:
        return []

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []

    if shutil.which("sudo") is None:
        print("[bootstrap] root privileges are required and sudo is not available")
        return None

    # A passwordless sudo rule means the operator has already granted this and no
    # prompt is warranted.
    try:
        probe = subprocess.run(["sudo", "-n", "true"], check=False, capture_output=True)
        if probe.returncode == 0:
            return ["sudo", "-n"]
    except OSError:
        return None

    if assume_yes:
        return ["sudo"]

    if not sys.stdin.isatty():
        # No terminal to prompt on. Blocking here would hang with an invisible
        # password prompt, which is worse than starting without hardware support.
        print("[bootstrap] elevation needed but no terminal is available to ask on")
        return None

    return ["sudo"]


def install_native_libraries(assume_yes: bool = False, verbose: bool = True) -> bool:
    """Resolve the native build dependencies, asking before elevating.

    Returns True when the libraries are present afterwards. A refusal or a failure
    returns False and is not treated as fatal by the caller.
    """
    manager = detect_package_manager()
    if manager is None:
        if sys.platform == "win32":
            print("[bootstrap] {0}".format(WINDOWS_HINT))
        else:
            print("[bootstrap] no supported package manager found, install "
                  "libhackrf and libusb development packages manually")
        return False

    prefix = _elevation_prefix(manager, assume_yes)
    if prefix is None:
        print("[bootstrap] install manually with: {0} {1}".format(
            " ".join(manager["install"]), " ".join(manager["packages"])))
        return False

    install_command = prefix + manager["install"] + manager["packages"]

    if prefix and not assume_yes:
        # Shown in full before anything runs. An operator asked for a password
        # should be able to see precisely what it will be spent on.
        print("[bootstrap] the HackRF driver builds against system libraries that "
              "are not installed.")
        print("[bootstrap] this will run, and will ask for your password:")
        print("[bootstrap]   {0}".format(" ".join(install_command)))
        try:
            answer = input("[bootstrap] proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            answer = "n"
        if answer not in ("y", "yes"):
            print("[bootstrap] declined, continuing without hardware support")
            return False

    if manager["refresh"]:
        try:
            subprocess.run(prefix + manager["refresh"], check=False,
                           capture_output=not verbose)
        except OSError as exc:
            print("[bootstrap] package index refresh failed: {0}".format(exc))

    try:
        result = subprocess.run(install_command, check=False)
    except OSError as exc:
        print("[bootstrap] package installation could not be launched: {0}".format(exc))
        return False

    if result.returncode != 0:
        print("[bootstrap] package installation failed with code {0}".format(result.returncode))
        return False

    remaining = missing_native_libraries()
    if remaining:
        print("[bootstrap] still missing after installation: {0}".format(", ".join(remaining)))
        return False

    print("[bootstrap] native libraries resolved")
    return True


def ensure_hardware_support(python: Path = None, assume_yes: bool = False,
                            allow_system: bool = True, verbose: bool = True) -> bool:
    """Make the HackRF driver importable, resolving what it needs to build.

    Ordered cheapest first. An already importable driver costs one spec lookup and
    touches nothing else, which is the case on every launch after the first.
    """
    python = python or Path(sys.executable)

    if module_present("python_hackrf"):
        return True

    requirement = OPTIONAL_REQUIREMENTS["python_hackrf"]

    # Resolve the build prerequisites first, then build once. An earlier revision
    # attempted the build before checking, on the theory that the libraries might
    # sit somewhere the checks do not know about, but that costs a full failed
    # compile on every launch of a host that genuinely lacks them and then repeats
    # the same install afterwards. One check and one build is both faster and
    # easier to reason about.
    missing = missing_native_libraries()
    if missing or not _compiler_present():
        if not allow_system:
            if verbose:
                print("[bootstrap] system dependency installation is disabled, "
                      "hardware capture unavailable")
            _print_degraded_notice()
            return False
        if verbose:
            if missing:
                print("[bootstrap] missing native libraries: {0}".format(", ".join(missing)))
            if not _compiler_present():
                print("[bootstrap] no C compiler found, the driver cannot be built")
        if not install_native_libraries(assume_yes=assume_yes, verbose=verbose):
            _print_degraded_notice()
            return False

    if not install_requirements(python, [requirement], fatal=False):
        _print_degraded_notice()
        return False

    importlib.invalidate_caches()
    if not module_present("python_hackrf"):
        print("[bootstrap] the HackRF driver installed but cannot be imported")
        _print_degraded_notice()
        return False

    print("[bootstrap] hardware support ready")
    return True


def _print_degraded_notice() -> None:
    """State plainly what still works, so a failure here is not read as fatal."""
    print("[bootstrap] hardware capture is unavailable. The analyzer will still "
          "run with --synthetic or --replay.")


# -----------------------------------------------------------------------------
# Environment creation and re-entry
# -----------------------------------------------------------------------------

def create_venv() -> None:
    """Build the environment with pip and with system packages visible."""
    target = venv_path()
    print("[bootstrap] creating virtual environment at {0}".format(target))
    builder = venv.EnvBuilder(
        system_site_packages=True,
        with_pip=True,
        upgrade_deps=False,
        clear=False,
    )
    builder.create(str(target))


def reenter(python: Path) -> None:
    """Restart under the environment interpreter, preserving arguments.

    Never returns on POSIX, where the current process is replaced. On Windows a
    child process is run to completion and its exit code propagated, since the
    Windows exec emulation would otherwise return control here immediately and
    leave two processes competing for the console.
    """
    script = str(Path(sys.argv[0]).resolve())
    argv = [str(python), script] + sys.argv[1:]

    environment = dict(os.environ)
    environment[GUARD_ENV] = "1"

    print("[bootstrap] entering environment and restarting")
    sys.stdout.flush()

    if os.name == "nt":
        result = subprocess.run(argv, env=environment)
        sys.exit(result.returncode)

    os.environ[GUARD_ENV] = "1"
    os.execv(str(python), argv)


def ensure_environment(skip: bool = False, assume_yes: bool = False,
                       allow_system: bool = True, verbose: bool = True) -> None:
    """Entry point. Provisions and re-enters the environment as required.

    Called before any third party import. Either returns with every mandatory
    dependency importable in the current process, replaces the process with one
    where that is true, or exits with a diagnostic. Optional hardware support may
    be absent on return, which callers handle by falling back to the synthetic and
    replay sources.
    """
    if skip or os.environ.get("RCS_SPECTRUM_NO_BOOTSTRAP"):
        if verbose:
            print("[bootstrap] disabled, using the current interpreter")
        ensure_hardware_support(assume_yes=assume_yes, allow_system=allow_system,
                                verbose=verbose)
        return

    already_reentered = os.environ.get(GUARD_ENV) == "1"

    if in_target_venv() or already_reentered:
        # Inside the environment. Install anything still missing, then continue in
        # this process, since a second re-entry would loop.
        missing = missing_requirements()
        if missing:
            if not install_requirements(Path(sys.executable), missing):
                sys.exit(1)
            importlib.invalidate_caches()
            still_missing = missing_requirements()
            if still_missing:
                print("[bootstrap] still unresolved after installation: {0}".format(
                    ", ".join(still_missing)))
                print("[bootstrap] delete {0} and retry".format(venv_path()))
                sys.exit(1)
        ensure_hardware_support(assume_yes=assume_yes, allow_system=allow_system,
                                verbose=verbose)
        return

    target = venv_path()
    python = venv_python(target)

    if not python.exists():
        try:
            create_venv()
        except Exception as exc:
            print("[bootstrap] could not create the environment: {0}".format(exc))
            print("[bootstrap] on Debian and Ubuntu this usually means python3-venv is absent")
            sys.exit(1)

    if not python.exists():
        print("[bootstrap] environment created but no interpreter at {0}".format(python))
        sys.exit(1)

    # Resolve requirements against the environment rather than the current
    # interpreter, since the two have different search paths and a package present
    # here may well be absent there.
    probe = subprocess.run(
        [str(python), "-c",
         "import importlib.util as u,sys;"
         "print(','.join(n for n in sys.argv[1:] if u.find_spec(n) is None))"] +
        list(REQUIREMENTS),
        capture_output=True, text=True, check=False,
    )
    absent_names = [n for n in probe.stdout.strip().split(",") if n]
    needed = [REQUIREMENTS[n] for n in absent_names if n in REQUIREMENTS]

    if needed and not install_requirements(python, needed):
        sys.exit(1)

    reenter(python)
