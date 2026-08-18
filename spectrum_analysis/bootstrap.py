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
#   Guarantees the application runs inside its own virtual environment with every
#   dependency present, creating and populating that environment on first launch
#   and re-entering it automatically on every launch thereafter.
#
#   This module imports nothing outside the standard library and must be imported
#   before any third party package anywhere in the application. If numpy or Qt
#   were imported first, the process would fail on a missing dependency before
#   any code capable of installing that dependency had a chance to run.
#
#   The environment is created with system site packages visible. SoapySDR is not
#   installable from pip and is delivered as a system package with a compiled
#   extension, so an isolated environment would be unable to see the radio at all.
#   Packages installed into the environment still take precedence over their
#   system counterparts, so this exposes the SDR runtime without surrendering
#   control of the pinned dependencies.
#
#   Radio support is installed from pip alongside everything else, but is treated
#   as optional. A host with no HackRF development headers cannot build the
#   driver, and refusing to start over that would block the synthetic and replay
#   sources which need no hardware at all.
#
#   Re-entry uses process replacement on POSIX and a child process on Windows.
#   Windows lacks a true exec, and its emulation returns control to the parent
#   immediately, which detaches a console application from its terminal and
#   orphans the exit code.
#
# SECURITY NOTICE:
#   This module installs packages from the configured Python package index at
#   first launch, which is a network operation that pulls and executes third
#   party code. On an engagement host with restricted or monitored egress,
#   provision the environment ahead of deployment and launch with the bootstrap
#   disabled rather than allowing an unplanned outbound connection during an
#   operation. Dependencies are version floored rather than pinned to an exact
#   hash, so a supply chain compromise upstream is not detected here.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software, whether
#   authorized or otherwise.
# =============================================================================

"""Virtual environment creation, dependency provisioning, and re-entry."""

import importlib.util
import os
import subprocess
import sys
import venv
from pathlib import Path

# Directory name for the environment, created beside this file so that each
# checkout carries its own and several nodes on one host do not collide.
VENV_DIR_NAME = ".venv"

# Set once re-entry has happened. Its presence is what stops a failed environment
# from re-executing itself forever, which would otherwise fork bomb the host on
# any condition that leaves a dependency unimportable after installation.
GUARD_ENV = "RCS_SPECTRUM_BOOTSTRAPPED"

# Import name mapped to pip requirement. The two differ often enough that
# checking for the pip name would report a satisfied dependency as missing.
REQUIREMENTS = {
    "numpy": "numpy>=1.24",
    "scipy": "scipy>=1.10",
    "PySide6": "PySide6>=6.5",
    "pyqtgraph": "pyqtgraph>=0.13",
}

# Hardware support. Installed from pip like the others, but a failure here is not
# fatal, because the synthetic and replay sources remain usable without a radio
# and blocking the whole application over an absent driver would be wrong.
#
# python_hackrf is a source distribution that links against the installed HackRF
# host software rather than bundling it, so the build needs hackrf.h and the
# libusb headers present. Those come from the development packages, which a host
# with only the runtime HackRF tools installed will not have.
OPTIONAL_REQUIREMENTS = {
    "python_hackrf": "python-hackrf>=1.5",
}

BUILD_PREREQUISITES = {
    "linux": "sudo apt install libhackrf-dev libusb-1.0-0-dev",
    "darwin": "brew install hackrf libusb",
    "win32": "install the HackRF host tools, then set PYTHON_HACKRF_INCLUDE_PATH "
             "and PYTHON_HACKRF_LIB_PATH to their locations",
}


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


def missing_requirements() -> list:
    """Pip requirements whose import name cannot be resolved."""
    missing = []
    for import_name, requirement in REQUIREMENTS.items():
        try:
            found = importlib.util.find_spec(import_name) is not None
        except (ImportError, ValueError):
            found = False
        if not found:
            missing.append(requirement)
    return missing


def check_hardware_support(python: Path = None, verbose: bool = True) -> list:
    """Install hardware support if absent, warning rather than failing.

    A missing radio driver degrades the application to the synthetic and replay
    sources instead of stopping it, so the operator can still work on a machine
    with no HackRF attached or no build toolchain present.
    """
    python = python or Path(sys.executable)
    absent = []

    for import_name, requirement in OPTIONAL_REQUIREMENTS.items():
        try:
            present = importlib.util.find_spec(import_name) is not None
        except (ImportError, ValueError):
            present = False
        if present:
            continue

        if verbose:
            print("[bootstrap] {0} not present, attempting installation".format(import_name))
        if install_requirements(python, [requirement], fatal=False):
            try:
                importlib.invalidate_caches()
                if importlib.util.find_spec(import_name) is not None:
                    continue
            except (ImportError, ValueError):
                pass

        absent.append(import_name)
        if verbose:
            hint = BUILD_PREREQUISITES.get(sys.platform) or BUILD_PREREQUISITES["linux"]
            print("[bootstrap] {0} unavailable. Hardware capture is disabled.".format(import_name))
            print("[bootstrap]   this package builds against the installed HackRF "
                  "host software, so it needs the development headers:")
            print("[bootstrap]   {0}".format(hint))
            print("[bootstrap]   run with --synthetic or --replay to work without a radio.")
    return absent


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


def install_requirements(python: Path, requirements: list, fatal: bool = True) -> bool:
    """Install the given requirements into the environment.

    Optional requirements pass fatal as False so a build failure on a host without
    the HackRF development headers produces a warning rather than an abort.
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
    if result.returncode != 0:
        if fatal:
            print("[bootstrap] dependency installation failed with code {0}".format(
                result.returncode))
        return False
    return True


def reenter(python: Path) -> None:
    """Restart under the environment interpreter, preserving arguments.

    Never returns on POSIX, where the current process is replaced. On Windows a
    child process is run to completion and its exit code is propagated, since the
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


def ensure_environment(skip: bool = False, verbose: bool = True) -> None:
    """Entry point. Provisions and re-enters the environment as required.

    Called before any third party import. Either returns with every dependency
    importable in the current process, replaces the process with one where that
    is true, or exits with a diagnostic.
    """
    if skip or os.environ.get("RCS_SPECTRUM_NO_BOOTSTRAP"):
        if verbose:
            print("[bootstrap] disabled, using the current interpreter")
        check_hardware_support(verbose=verbose)
        return

    already_reentered = os.environ.get(GUARD_ENV) == "1"

    if in_target_venv() or already_reentered:
        # Inside the environment. Install anything still missing, then continue in
        # this process, since a second re-entry would loop.
        missing = missing_requirements()
        if missing:
            if not already_reentered and not install_requirements(Path(sys.executable), missing):
                sys.exit(1)
            elif already_reentered:
                if not install_requirements(Path(sys.executable), missing):
                    sys.exit(1)
            still_missing = missing_requirements()
            if still_missing:
                print("[bootstrap] still unresolved after installation: {0}".format(
                    ", ".join(still_missing)))
                print("[bootstrap] delete {0} and retry".format(venv_path()))
                sys.exit(1)
        check_hardware_support(verbose=verbose)
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
    # interpreter, since the two have different search paths and a package
    # present here may well be absent there.
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
