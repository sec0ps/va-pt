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
#   environment, installs Python dependencies, and re-enters it. Every launch after
#   the first is a fast no operation.
#
#   Imports only the standard library and must run before any third party import,
#   or the process dies on a missing dependency before the code that installs it
#   has run. The environment is isolated from host site packages. Radio access is a
#   ctypes binding over an existing shared library, so nothing here needs root or a
#   compiler.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software.
# =============================================================================

"""Environment creation, dependency provisioning, and application re-entry."""

import importlib.util
import os
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

# Optional. Absence disables the listener control link and nothing else, so a
# failure here degrades one feature rather than preventing startup.
OPTIONAL_REQUIREMENTS = {
    "serial": "pyserial>=3.5",
}

# Refreshed inside the environment before anything else is installed. The pip
# shipped by ensurepip on a distribution Python is often old enough to mishandle
# modern build backends, which surfaces as a confusing metadata error rather than
# as an obvious version problem.
BUILD_TOOLING = ["pip", "setuptools", "wheel"]

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


def _install_optional(python: Path, verbose: bool = True) -> None:
    """Install optional packages, reporting rather than failing when they resist."""
    for name, requirement in OPTIONAL_REQUIREMENTS.items():
        if module_present(name):
            continue
        if not install_requirements(python, [requirement], fatal=False) and verbose:
            print("[bootstrap] {0} unavailable, the listener link is disabled".format(
                requirement))


def check_hardware_support(verbose: bool = True) -> bool:
    """Report whether libhackrf can be loaded, installing nothing.

    Radio access is a ctypes binding over the shared library the host already
    provides, so there is nothing to build and nothing to install. Either the
    HackRF host software is present or it is not, and its absence is a warning
    rather than a failure because the synthetic and replay sources need no radio.
    """
    try:
        import hackrf_backend
    except Exception as exc:
        if verbose:
            print("[bootstrap] radio backend unavailable: {0}".format(exc))
        return False

    if hackrf_backend.LIBRARY_AVAILABLE:
        if verbose:
            print("[bootstrap] libhackrf {0}".format(hackrf_backend.library_version()))
        return True

    if verbose:
        hint = LIBHACKRF_HINTS.get(sys.platform) or LIBHACKRF_HINTS["linux"]
        print("[bootstrap] libhackrf not found, hardware capture is unavailable")
        print("[bootstrap]   install it with: {0}".format(hint))
        print("[bootstrap]   the analyzer still runs with --synthetic or --replay")
    return False


# -----------------------------------------------------------------------------
# Environment creation and re-entry
# -----------------------------------------------------------------------------

def venv_is_stale(base: Path = None) -> bool:
    """Whether an existing environment was built with the wrong isolation setting.

    An environment created by an earlier revision inherited the host site
    packages, which is the defect this replaces. Isolation cannot be changed in
    place, so such an environment has to be rebuilt rather than reused, and
    silently reusing it would reproduce the original import failure on every
    launch.
    """
    config = (base or venv_path()) / "pyvenv.cfg"
    if not config.exists():
        return False
    try:
        text = config.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "include-system-site-packages":
            return value.strip().lower() == "true"
    return False


def create_venv(clear: bool = False) -> None:
    """Build an isolated environment with pip available.

    Isolation is the point. Nothing this application needs from Python comes from
    the distribution, and exposing the host packages means inheriting whatever
    inconsistent set of versions happens to be installed there.
    """
    target = venv_path()
    print("[bootstrap] creating virtual environment at {0}".format(target))
    builder = venv.EnvBuilder(
        system_site_packages=False,
        with_pip=True,
        upgrade_deps=False,
        clear=clear,
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


def ensure_environment(skip: bool = False, verbose: bool = True) -> None:
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
        check_hardware_support(verbose=verbose)
        _install_optional(Path(sys.executable), verbose)
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
        check_hardware_support(verbose=verbose)
        _install_optional(Path(sys.executable), verbose)
        return

    target = venv_path()
    python = venv_python(target)

    rebuild = False
    if python.exists() and venv_is_stale(target):
        print("[bootstrap] existing environment inherits host packages, rebuilding it")
        rebuild = True

    created = not python.exists() or rebuild
    if created:
        try:
            create_venv(clear=rebuild)
        except Exception as exc:
            print("[bootstrap] could not create the environment: {0}".format(exc))
            print("[bootstrap] on Debian and Ubuntu this usually means python3-venv is absent")
            sys.exit(1)

    if not python.exists():
        print("[bootstrap] environment created but no interpreter at {0}".format(python))
        sys.exit(1)

    # Refreshed once, when the environment is first built, since an old pip is
    # exactly what turns an installable package into an inscrutable metadata
    # error. Repeating it on every launch would add seconds of network round
    # trips to a startup that otherwise touches nothing.
    if created:
        install_requirements(python, BUILD_TOOLING, fatal=False)

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

    # Optional packages are installed without being allowed to block startup.
    probe_optional = subprocess.run(
        [str(python), "-c",
         "import importlib.util as u,sys;"
         "print(','.join(n for n in sys.argv[1:] if u.find_spec(n) is None))"] +
        list(OPTIONAL_REQUIREMENTS),
        capture_output=True, text=True, check=False,
    )
    missing_optional = [n for n in probe_optional.stdout.strip().split(",") if n]
    if missing_optional:
        install_requirements(
            python, [OPTIONAL_REQUIREMENTS[n] for n in missing_optional], fatal=False)

    reenter(python)
