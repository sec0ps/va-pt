#!/usr/bin/env python3
# =============================================================================
# kismet_gps.py - Site-Scoped Kismet Capture with GPS + KML Export
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
# Purpose: Site-scoped Kismet capture with gpsd and post-capture KML export.
#          Bootstraps a local venv and installs missing pip deps on first run;
#          prompts for the site/location being assessed and names all output
#          from that slug; ensures gpsd is up and holding a fix (starting it
#          against the u-blox if needed); launches Kismet headless with GPS and
#          logging wired through a per-run --override config (no global
#          /etc/kismet changes); and on Ctrl-C stops Kismet cleanly and parses
#          the .kismet sqlite log into a KML of every geolocated access point,
#          foldered and colored by encryption, for Google Earth / My Maps.
#
#          Re-runnable pieces:
#            --kml-only <file.kismet>  regenerate KML from an existing log
#            --site / --client / --interface / --outdir / --fix-timeout / --no-wait-fix
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# NOTICE: This tool is intended for authorized security testing only.
#         Users are responsible for ensuring compliance with all applicable laws
#         and regulations. Unauthorized use of these tools may violate local,
#         state, federal, and international laws.
#
# =============================================================================

import argparse
import glob
import gzip
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ------------------------------------------------------------------ venv bootstrap
APP_DIR = Path(__file__).resolve().parent
VENV_DIR = APP_DIR / ".kismet-venv"
PIP_DEPS = {"simplekml": "simplekml"}  # pip name -> import name


def _bootstrap_venv():
    """Create the venv if absent, install any missing deps, then re-exec under it.
    Runs under the system interpreter, so it imports nothing from PIP_DEPS itself."""
    if os.environ.get("KISMET_GPS_VENV") == "1":
        return  # already re-exec'd into the venv

    venv_py = VENV_DIR / "bin" / "python3"
    if not venv_py.exists():
        print(f"[*] Creating venv: {VENV_DIR}")
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        subprocess.run([str(venv_py), "-m", "pip", "install", "-q", "--upgrade", "pip"],
                       check=True)

    missing = []
    for pip_name, import_name in PIP_DEPS.items():
        if subprocess.run([str(venv_py), "-c", f"import {import_name}"],
                          capture_output=True).returncode != 0:
            missing.append(pip_name)
    if missing:
        print(f"[*] Installing deps into venv: {', '.join(missing)}")
        subprocess.run([str(venv_py), "-m", "pip", "install", "-q", *missing], check=True)

    env = {**os.environ, "KISMET_GPS_VENV": "1"}
    os.execve(str(venv_py), [str(venv_py), str(Path(__file__).resolve()), *sys.argv[1:]], env)


_bootstrap_venv()

# ------------------------------------------------------------------ small helpers
ENC_STYLE = {  # group -> (simplekml color attr name, human label)
    "open":    ("red",    "Open"),
    "wep":     ("orange", "WEP"),
    "wpa2":    ("yellow", "WPA / WPA2"),
    "wpa3":    ("green",  "WPA3 / SAE"),
    "unknown": ("white",  "Unknown / Other"),
}


def sudo(cmd):
    """Prefix a command list with sudo unless we are already root."""
    return (["sudo"] + cmd) if os.geteuid() != 0 else cmd


def run(cmd, check=False, capture=False):
    return subprocess.run(cmd, check=check,
                          capture_output=capture, text=True)


def slugify(text):
    s = re.sub(r"[^A-Za-z0-9]+", "-", text.strip()).strip("-").lower()
    return s or "site"


def detect_wireless_ifaces():
    """Wireless interfaces = those with a /sys/class/net/<if>/wireless directory."""
    ifaces = []
    for path in sorted(glob.glob("/sys/class/net/*/wireless")):
        ifaces.append(Path(path).parent.name)
    return ifaces


# ------------------------------------------------------------------ gpsd
def gpsd_listening():
    try:
        with socket.create_connection(("127.0.0.1", 2947), timeout=3):
            return True
    except OSError:
        return False


def find_gps_device():
    for pattern in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        hits = sorted(glob.glob(pattern))
        if hits:
            return hits[0]
    return None


def start_gpsd():
    """Bind gpsd to the detected GPS in the foreground-daemon mode kismet expects.
    Clears socket-activation and ModemManager, both of which fight for ttyACM*."""
    dev = find_gps_device()
    if not dev:
        print("[!] No GPS device found at /dev/ttyACM* or /dev/ttyUSB*. Plug it in.")
        return False
    print(f"[*] Starting gpsd on {dev}")
    run(sudo(["systemctl", "stop", "gpsd.socket", "gpsd.service"]))
    run(sudo(["systemctl", "stop", "ModemManager"]))       # frees the u-blox serial port
    run(sudo(["killall", "gpsd"]))
    run(sudo(["gpsd", "-n", dev]), check=True)              # -n: read immediately, no client wait
    time.sleep(2)
    return gpsd_listening()


def wait_for_fix(timeout):
    """Poll gpsd's JSON socket until a >=2D fix appears or timeout elapses.
    Returns (mode, lat, lon); mode 0 means no fix."""
    deadline = time.time() + timeout
    try:
        s = socket.create_connection(("127.0.0.1", 2947), timeout=5)
    except OSError as e:
        print(f"[!] Cannot reach gpsd on 2947: {e}")
        return 0, None, None
    s.sendall(b'?WATCH={"enable":true,"json":true}\n')
    s.settimeout(3)
    buf = b""
    print(f"[*] Waiting up to {timeout}s for a GPS fix (Ctrl-C to skip)...")
    try:
        while time.time() < deadline:
            try:
                data = s.recv(4096)
            except socket.timeout:
                continue
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                cls = obj.get("class")
                if cls == "SKY":
                    used = sum(1 for sat in obj.get("satellites", []) if sat.get("used"))
                    print(f"    satellites used: {used}   ", end="\r")
                elif cls == "TPV" and obj.get("mode", 0) >= 2:
                    print()
                    return obj["mode"], obj.get("lat"), obj.get("lon")
    except KeyboardInterrupt:
        print("\n[*] Skipping fix wait.")
    finally:
        s.close()
    print()
    return 0, None, None


def ensure_gps(fix_timeout, wait_fix):
    if not gpsd_listening():
        if not start_gpsd():
            return False
    else:
        print("[*] gpsd already listening on 2947")
    if not wait_fix:
        return True
    mode, lat, lon = wait_for_fix(fix_timeout)
    if mode >= 2:
        print(f"[+] GPS fix: {mode}D at {lat:.6f}, {lon:.6f}")
        return True
    ans = input("[?] No fix yet. Start capture anyway (fix may acquire outdoors)? [y/N] ")
    return ans.strip().lower().startswith("y")


# ------------------------------------------------------------------ kismet capture
def write_override(rundir, slug, iface):
    """Per-run override.conf: last-loaded, wins over all base config, touches nothing global."""
    conf = rundir / "kismet_override.conf"
    conf.write_text(
        f"log_title={slug}\n"
        f"log_prefix={rundir}\n"
        "log_types=kismet\n"
        "gps=gpsd:host=localhost,port=2947\n"
        f"source={iface}:name={slug}\n"
    )
    return conf


def run_kismet(rundir, override_conf):
    if not shutil.which("kismet"):
        print("[!] kismet not found on PATH. Install it (vapt-installer.py) first.")
        return False
    run(sudo(["rfkill", "unblock", "wifi"]))
    cmd = ["kismet", f"--override={override_conf}", "--no-ncurses", "--no-line-wrap"]
    print(f"[*] Launching: {' '.join(cmd)}")
    print("[*] Capturing. Press Ctrl-C to stop and export KML.\n")
    proc = subprocess.Popen(cmd, cwd=str(rundir))
    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Stopping kismet (flushing log)...")
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    return True


def newest_kismetdb(rundir):
    logs = sorted(glob.glob(str(rundir / "*.kismet")), key=os.path.getmtime)
    return Path(logs[-1]) if logs else None


# ------------------------------------------------------------------ kismetdb -> KML
def _maybe_gunzip(blob):
    if isinstance(blob, (bytes, bytearray)) and blob[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(blob)
        except OSError:
            return blob
    return blob


def _norm_coord(v):
    """Kismetdb stores lat/lon as REAL degrees (v6) or fixed-point *1e5 (older).
    Normalize either into degrees; return None if implausible."""
    if v is None:
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if abs(v) > 360.0:          # fixed-point integer form
        v = v / 1e5
    return v


def _classify_crypt(crypt):
    c = (crypt or "").upper()
    if "WPA3" in c or "SAE" in c:
        return "wpa3"
    if "WPA" in c:
        return "wpa2"
    if "WEP" in c:
        return "wep"
    if not c or "OPEN" in c or c == "NONE":
        return "open"
    return "unknown"


def read_kismetdb_aps(dbpath):
    """Yield dicts for every Wi-Fi AP in the log that has a usable GPS position.
    Reads the dedicated devices columns; parses the (possibly gzipped) device JSON
    only for SSID/crypt/channel/manuf, with defensive fallbacks."""
    con = sqlite3.connect(f"file:{dbpath}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    cols = {r[1] for r in con.execute("PRAGMA table_info(devices)")}
    wanted = [c for c in ("devmac", "type", "phyname", "avg_lat", "avg_lon",
                          "strongest_signal", "first_time", "last_time", "device")
              if c in cols]
    q = f"SELECT {', '.join(wanted)} FROM devices"
    if "type" in cols:
        q += " WHERE type LIKE '%AP%'"

    for row in con.execute(q):
        r = dict(row)
        lat = _norm_coord(r.get("avg_lat"))
        lon = _norm_coord(r.get("avg_lon"))

        base = {}
        if r.get("device") is not None:
            try:
                base = json.loads(_maybe_gunzip(r["device"]))
            except (ValueError, TypeError):
                base = {}
        b = base.get("kismet.device.base", {}) if isinstance(base, dict) else {}

        # Fall back to the JSON geopoint if the columns were empty
        if lat is None or lon is None or (lat == 0.0 and lon == 0.0):
            loc = (b.get("kismet.device.base.location", {})
                    .get("kismet.common.location.avg_loc", {})
                    .get("kismet.common.location.geopoint"))
            if isinstance(loc, list) and len(loc) == 2:
                lon, lat = _norm_coord(loc[0]), _norm_coord(loc[1])

        if lat is None or lon is None or (lat == 0.0 and lon == 0.0):
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue

        mac = r.get("devmac") or b.get("kismet.device.base.macaddr") or "??:??:??:??:??:??"
        name = b.get("kismet.device.base.commonname") or b.get("kismet.device.base.name") or ""
        if not name or name.replace(":", "").upper() == mac.replace(":", "").upper():
            name = "(hidden / unnamed)"
        crypt = b.get("kismet.device.base.crypt", "")
        sig = r.get("strongest_signal")
        if sig in (None, 0):
            sig = (b.get("kismet.device.base.signal", {})
                    .get("kismet.common.signal.max_signal"))
        yield {
            "mac": mac,
            "ssid": name,
            "crypt": crypt or "Unknown",
            "group": _classify_crypt(crypt),
            "channel": b.get("kismet.device.base.channel", ""),
            "freq": b.get("kismet.device.base.frequency", ""),
            "manuf": b.get("kismet.device.base.manuf", ""),
            "signal": sig,
            "first": r.get("first_time") or b.get("kismet.device.base.first_time"),
            "last": r.get("last_time") or b.get("kismet.device.base.last_time"),
            "lat": lat, "lon": lon,
        }
    con.close()


def _fmt_epoch(ts):
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except (TypeError, ValueError):
        return "n/a"


def generate_kml(aps, out_path, doc_name):
    import simplekml
    kml = simplekml.Kml(name=doc_name)

    folders, styles = {}, {}
    for group, (color_attr, label) in ENC_STYLE.items():
        folders[group] = kml.newfolder(name=label)
        st = simplekml.Style()
        st.iconstyle.color = getattr(simplekml.Color, color_attr)
        st.iconstyle.icon.href = "http://maps.google.com/mapfiles/kml/pushpin/wht-pushpin.png"
        st.labelstyle.scale = 0.8
        styles[group] = st

    counts = {g: 0 for g in ENC_STYLE}
    for ap in aps:
        g = ap["group"]
        counts[g] += 1
        p = folders[g].newpoint(name=ap["ssid"], coords=[(ap["lon"], ap["lat"])])
        p.style = styles[g]
        p.description = (
            f"BSSID: {ap['mac']}\n"
            f"Encryption: {ap['crypt']}\n"
            f"Channel: {ap['channel']}   Freq: {ap['freq']}\n"
            f"Manufacturer: {ap['manuf'] or 'n/a'}\n"
            f"Strongest signal: {ap['signal'] if ap['signal'] is not None else 'n/a'} dBm\n"
            f"First seen: {_fmt_epoch(ap['first'])}\n"
            f"Last seen:  {_fmt_epoch(ap['last'])}\n"
            f"Position: {ap['lat']:.6f}, {ap['lon']:.6f}"
        )

    kml.save(str(out_path))
    return counts


# ------------------------------------------------------------------ orchestration
def choose_interface(cli_iface):
    if cli_iface:
        return cli_iface
    ifaces = detect_wireless_ifaces()
    if not ifaces:
        print("[!] No wireless interfaces detected.")
        sys.exit(1)
    if len(ifaces) == 1:
        print(f"[*] Using wireless interface: {ifaces[0]}")
        return ifaces[0]
    print("[*] Wireless interfaces:")
    for i, name in enumerate(ifaces):
        print(f"    [{i}] {name}")
    while True:
        sel = input("[?] Select interface number: ").strip()
        if sel.isdigit() and int(sel) < len(ifaces):
            return ifaces[int(sel)]


def export(dbpath, out_path, doc_name):
    print(f"[*] Parsing {dbpath}")
    aps = list(read_kismetdb_aps(dbpath))
    if not aps:
        print("[!] No geolocated APs in the log (no fix during capture, or no APs seen).")
        return
    counts = generate_kml(aps, out_path, doc_name)
    print(f"[+] KML written: {out_path}")
    total = sum(counts.values())
    print(f"[+] {total} geolocated APs: " +
          ", ".join(f"{ENC_STYLE[g][1]}={counts[g]}" for g in ENC_STYLE if counts[g]))
    print("[*] Import into Google My Maps: mymaps.google.com -> Create new map -> "
          "Import -> upload this .kml (one layer per encryption folder).")


def main():
    ap = argparse.ArgumentParser(description="Kismet capture + KML export")
    ap.add_argument("--site", help="Site / location name (skips prompt)")
    ap.add_argument("--client", help="Client name (optional, for labeling)")
    ap.add_argument("--interface", help="Wireless interface (skips prompt/detection)")
    ap.add_argument("--outdir",
                    help="Base directory for capture data (prompted if omitted)")
    ap.add_argument("--fix-timeout", type=int, default=120,
                    help="Seconds to wait for a GPS fix before prompting (default: 120)")
    ap.add_argument("--no-wait-fix", action="store_true",
                    help="Start capture without waiting for a GPS fix")
    ap.add_argument("--kml-only", metavar="FILE.kismet",
                    help="Regenerate KML from an existing .kismet log; no capture")
    args = ap.parse_args()

    # Regenerate-only path
    if args.kml_only:
        db = Path(args.kml_only).resolve()
        if not db.exists():
            print(f"[!] No such file: {db}")
            sys.exit(1)
        out = db.with_suffix(".kml")
        export(db, out, db.stem)
        return

    site = args.site or input("[?] Site / location being assessed: ").strip()
    client = args.client or input("[?] Client name (optional): ").strip()
    slug = slugify(f"{client}-{site}" if client else site)
    iface = choose_interface(args.interface)

    outbase = args.outdir
    if not outbase:
        default_base = str(Path.home() / "kismet-captures")
        entered = input(f"[?] Directory to store capture data [{default_base}]: ").strip()
        outbase = entered or default_base

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    rundir = Path(outbase).expanduser() / f"{slug}_{stamp}"
    rundir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Run directory: {rundir}")

    if not ensure_gps(args.fix_timeout, not args.no_wait_fix):
        print("[!] Aborting: no GPS.")
        sys.exit(1)

    override_conf = write_override(rundir, slug, iface)
    if not run_kismet(rundir, override_conf):
        sys.exit(1)

    db = newest_kismetdb(rundir)
    if not db:
        print("[!] No .kismet log produced.")
        sys.exit(1)
    doc = f"{client + ' - ' if client else ''}{site} ({stamp})"
    export(db, rundir / f"{slug}.kml", doc)


if __name__ == "__main__":
    main()
