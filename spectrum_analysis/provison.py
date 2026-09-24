#!/usr/bin/env python3
# =============================================================================
# Location: provision.py
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
#   One time host provisioning for kit deployment. Installs the HackRF host
#   tools, grants the operator access to the radio and to the PortaPack serial
#   console, and installs a udev rule so that access survives reboots.
#
#   Kept separate from bootstrap.py on purpose. Bootstrap runs on every launch,
#   needs no privilege, and must stay that way. Everything here needs root and is
#   invoked deliberately once per machine, so mixing the two would put a
#   privileged transaction in the path of every start.
#
#   Group membership is the part that cannot be made transparent. A group added
#   with usermod does not apply to sessions that are already open, so the account
#   looks correct while the running process still cannot open the port. The udev
#   rule is installed alongside precisely to narrow that window, since it grants
#   access by device rather than by group.
#
# DISCLAIMER:
#   This software is provided for lawful, authorized use only. The author and Red
#   Cell Security LLC accept no liability for any use of this software.
# =============================================================================

"""One time host provisioning for HackRF and PortaPack device access."""

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Groups the operator needs. dialout owns serial devices, which is how a
# PortaPack in Mayhem mode appears. plugdev is what the HackRF udev rule
# shipped with the host tools assigns the radio to on Debian derivatives.
REQUIRED_GROUPS = ("dialout", "plugdev")

# Installed so PortaPack access does not depend on group membership, which needs
# a re-login to take effect. Named with a high number so it is applied after the
# distribution defaults it overrides.
UDEV_RULE_PATH = "/etc/udev/rules.d/99-redcell-portapack.rules"

# Vendor and product of the HackRF family. A PortaPack running Mayhem presents a
# CDC serial interface under the same vendor, so matching the vendor and the tty
# subsystem covers it whichever product identifier the firmware reports.
HACKRF_VENDOR = "1d50"

PACKAGE_MANAGERS = (
    {"binary": "apt-get", "packages": ["hackrf"],
     "refresh": ["apt-get", "update"], "install": ["apt-get", "install", "-y"]},
    {"binary": "dnf", "packages": ["hackrf"],
     "refresh": None, "install": ["dnf", "install", "-y"]},
    {"binary": "pacman", "packages": ["hackrf"],
     "refresh": None, "install": ["pacman", "-S", "--needed", "--noconfirm"]},
    {"binary": "zypper", "packages": ["hackrf"],
     "refresh": None, "install": ["zypper", "--non-interactive", "install"]},
)


@dataclass
class Result:
    """What provisioning did, and what the operator still has to do."""

    actions: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    failures: List[str] = field(default_factory=list)
    relogin_required: bool = False

    def report(self) -> str:
        lines = []
        for item in self.actions:
            lines.append("  done     {0}".format(item))
        for item in self.skipped:
            lines.append("  already  {0}".format(item))
        for item in self.failures:
            lines.append("  FAILED   {0}".format(item))
        if self.relogin_required:
            lines.append("")
            lines.append("  Group membership was changed. Log out and back in, or")
            lines.append("  start a session with 'newgrp dialout' for a one off.")
        return "\n".join(lines)

    @property
    def ok(self) -> bool:
        return not self.failures


def target_user() -> str:
    """The operator to provision for, not the account running the command.

    Under sudo the effective user is root, and adding root to dialout leaves the
    operator exactly as unable to open the port as before while appearing to have
    succeeded. SUDO_USER is the account that invoked the escalation and is the one
    that needs the membership.
    """
    for variable in ("SUDO_USER", "PKEXEC_UID", "LOGNAME", "USER"):
        value = os.environ.get(variable)
        if variable == "PKEXEC_UID" and value:
            try:
                import pwd
                return pwd.getpwuid(int(value)).pw_name
            except Exception:
                continue
        if value and value != "root":
            return value

    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return "root"


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def group_exists(group: str) -> bool:
    try:
        import grp
        grp.getgrnam(group)
        return True
    except Exception:
        return False


def user_in_group(user: str, group: str) -> bool:
    """Account level membership, which is what usermod changes."""
    try:
        import grp
        import pwd
        entry = grp.getgrnam(group)
        if user in entry.gr_mem:
            return True
        # The primary group does not appear in gr_mem.
        return pwd.getpwnam(user).pw_gid == entry.gr_gid
    except Exception:
        return False


def add_to_group(user: str, group: str) -> Tuple[bool, str]:
    """Add an account to a group. Returns success and a description."""
    if not group_exists(group):
        return False, "group {0} does not exist on this host".format(group)
    if user_in_group(user, group):
        return True, "{0} already in {1}".format(user, group)

    usermod = shutil.which("usermod")
    if usermod is None:
        return False, "usermod not found"

    try:
        result = subprocess.run([usermod, "-aG", group, user],
                                check=False, capture_output=True, text=True)
    except OSError as exc:
        return False, "usermod failed: {0}".format(exc)

    if result.returncode != 0:
        return False, "usermod -aG {0} {1}: {2}".format(
            group, user, (result.stderr or "").strip())
    return True, "added {0} to {1}".format(user, group)


def udev_rule_text(group: str = "dialout") -> str:
    """Rule granting the operator access to HackRF and PortaPack nodes.

    Two rules rather than one. The radio enumerates as a USB device and is
    reached through libusb, while a PortaPack running Mayhem presents a CDC
    serial interface that appears as a tty. They are different subsystems and a
    single match will not cover both.
    """
    return (
        "# Red Cell Security RF spectrum analyzer\n"
        "# HackRF family, reached through libusb.\n"
        'SUBSYSTEM=="usb", ATTRS{{idVendor}}=="{vendor}", '
        'MODE="0660", GROUP="{group}", TAG+="uaccess"\n'
        "# PortaPack running Mayhem, which presents a CDC serial interface.\n"
        'SUBSYSTEM=="tty", ATTRS{{idVendor}}=="{vendor}", '
        'MODE="0660", GROUP="{group}", TAG+="uaccess"\n'
    ).format(vendor=HACKRF_VENDOR, group=group)


def install_udev_rule(group: str = "dialout") -> Tuple[bool, str]:
    """Write the rule and reload udev, leaving an identical rule untouched."""
    text = udev_rule_text(group)

    if os.path.exists(UDEV_RULE_PATH):
        try:
            if open(UDEV_RULE_PATH).read() == text:
                return True, "udev rule already current at {0}".format(UDEV_RULE_PATH)
        except OSError:
            pass

    directory = os.path.dirname(UDEV_RULE_PATH)
    if not os.path.isdir(directory):
        # A host running udev but without the local rules directory is a minimal
        # install rather than a host that does not use udev, so the directory is
        # created. Absence of udevadm as well means rules would never be read and
        # writing one would be misleading.
        if shutil.which("udevadm") is None:
            return False, ("{0} is absent and udevadm is not installed, "
                           "this host does not appear to use udev".format(directory))
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            return False, "creating {0}: {1}".format(directory, exc)

    try:
        with open(UDEV_RULE_PATH, "w") as handle:
            handle.write(text)
        os.chmod(UDEV_RULE_PATH, 0o644)
    except OSError as exc:
        return False, "writing {0}: {1}".format(UDEV_RULE_PATH, exc)

    udevadm = shutil.which("udevadm")
    if udevadm:
        subprocess.run([udevadm, "control", "--reload-rules"],
                       check=False, capture_output=True)
        subprocess.run([udevadm, "trigger", "--subsystem-match=usb",
                        "--subsystem-match=tty"], check=False, capture_output=True)

    return True, "installed udev rule at {0}".format(UDEV_RULE_PATH)


def hackrf_tools_present() -> bool:
    """Whether libhackrf is reachable, which is all the analyzer needs."""
    if shutil.which("hackrf_info"):
        return True
    for name in ("libhackrf.so.0", "libhackrf.so", "libhackrf.0.dylib"):
        try:
            import ctypes
            ctypes.CDLL(name)
            return True
        except OSError:
            continue
    return False


def install_hackrf_tools() -> Tuple[bool, str]:
    """Install the HackRF host tools through the distribution package manager."""
    if hackrf_tools_present():
        return True, "HackRF host tools already present"

    manager = None
    for candidate in PACKAGE_MANAGERS:
        if shutil.which(candidate["binary"]):
            manager = candidate
            break
    if manager is None:
        return False, "no supported package manager, install the hackrf package manually"

    if manager["refresh"]:
        subprocess.run(manager["refresh"], check=False, capture_output=True)
    result = subprocess.run(manager["install"] + manager["packages"],
                            check=False, capture_output=True, text=True)
    if result.returncode != 0:
        return False, "installing {0}: {1}".format(
            " ".join(manager["packages"]), (result.stderr or "").strip()[:200])

    if not hackrf_tools_present():
        return False, "hackrf package installed but libhackrf is still not loadable"
    return True, "installed HackRF host tools"


def provision(user: Optional[str] = None, groups: Tuple[str, ...] = REQUIRED_GROUPS,
              install_tools: bool = True, install_rule: bool = True) -> Result:
    """Provision this host. Requires root.

    Safe to run repeatedly. Every step checks its own current state first and
    reports as already satisfied rather than reapplying, so this can sit in a kit
    build script without accumulating duplicate rules or group entries.
    """
    result = Result()

    if not is_root():
        result.failures.append(
            "provisioning requires root. Rerun with: sudo {0} --provision".format(
                " ".join([sys.executable, os.path.abspath(sys.argv[0])])))
        return result

    account = user or target_user()

    if install_tools:
        ok, message = install_hackrf_tools()
        (result.actions if ok and "installed" in message else
         result.skipped if ok else result.failures).append(message)

    for group in groups:
        ok, message = add_to_group(account, group)
        if not ok:
            # A host without plugdev is normal on some distributions and is not a
            # failure, since the udev rule covers the same access.
            (result.skipped if "does not exist" in message
             else result.failures).append(message)
            continue
        if message.startswith("added"):
            result.actions.append(message)
            result.relogin_required = True
        else:
            result.skipped.append(message)

    if install_rule:
        rule_group = groups[0] if groups and group_exists(groups[0]) else "root"
        ok, message = install_udev_rule(rule_group)
        (result.actions if ok and "installed" in message else
         result.skipped if ok else result.failures).append(message)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="One time host provisioning for the RF spectrum analyzer.")
    parser.add_argument("--user", default=None,
                        help="account to grant device access, defaults to the "
                             "account that invoked sudo")
    parser.add_argument("--no-tools", action="store_true",
                        help="skip installing the HackRF host tools")
    parser.add_argument("--no-udev", action="store_true",
                        help="skip installing the udev rule")
    parser.add_argument("--check", action="store_true",
                        help="report current state without changing anything")
    args = parser.parse_args()

    account = args.user or target_user()

    if args.check:
        print("provisioning state for {0}".format(account))
        print("  HackRF host tools : {0}".format(
            "present" if hackrf_tools_present() else "MISSING"))
        for group in REQUIRED_GROUPS:
            if not group_exists(group):
                state = "group absent on this host"
            elif user_in_group(account, group):
                state = "member"
            else:
                state = "NOT a member"
            print("  {0:<18}: {1}".format(group, state))
        print("  udev rule         : {0}".format(
            "present" if os.path.exists(UDEV_RULE_PATH) else "MISSING"))
        return 0

    result = provision(user=account, install_tools=not args.no_tools,
                       install_rule=not args.no_udev)
    print("provisioning {0}".format(account))
    print(result.report())
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
