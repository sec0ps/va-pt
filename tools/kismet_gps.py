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


def ensure_deps(mapping):
    """Lazily pip-install missing packages into the running venv, then leave them
    importable. Used so the heavy heatmap deps (numpy/matplotlib) are only pulled
    when a heatmap is actually built, keeping plain capture lightweight."""
    import importlib
    for pip_name, import_name in mapping.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            print(f"[*] Installing {pip_name} into venv...")
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", pip_name],
                           check=True)


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


def _base_view(d):
    """Return the object holding the kismet.device.base.* fields regardless of log
    layout. db_version 9+ (kismet 2025.x) flattens them to top-level dotted keys;
    older logs nest them under a 'kismet.device.base' sub-dict. Either way the
    caller looks them up by their full dotted name (e.g. kismet.device.base.crypt)."""
    if not isinstance(d, dict):
        return {}
    nested = d.get("kismet.device.base")
    return nested if isinstance(nested, dict) else d


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
        b = _base_view(base)

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


def _declutter(aps):
    """Spiral-offset APs that share identical coordinates (a stationary capture
    stacks every AP on the receiver position) so each pin is individually
    clickable. Offsets are a few meters - display only, documented as such."""
    from math import cos, sin, radians, sqrt, pi
    groups = {}
    for ap in aps:
        groups.setdefault((round(ap["lat"], 6), round(ap["lon"], 6)), []).append(ap)
    golden = pi * (3 - sqrt(5))
    out = []
    for (lat0, lon0), members in groups.items():
        if len(members) == 1:
            out.append(members[0])
            continue
        for i, ap in enumerate(members):
            if i == 0:
                out.append(ap)
                continue
            r = 3.0 * sqrt(i)  # meters
            ang = i * golden
            nap = dict(ap)
            nap["lat"] = lat0 + (r * cos(ang)) / 111320.0
            nap["lon"] = lon0 + (r * sin(ang)) / (111320.0 * max(0.1, cos(radians(lat0))))
            out.append(nap)
    return out


def generate_kml(aps, out_path, doc_name, declutter=False):
    """Point KML with two independent filter trees so Google Earth Pro can filter
    by either attribute via folder checkboxes (GE Pro has no attribute query):
      * 'Filter: by encryption' (visible) - one folder per encryption class
      * 'Filter: by SSID' (hidden by default) - one folder per SSID
    Pins are colored by encryption in both trees. Toggle one tree off and the
    other on to switch which attribute you're filtering."""
    import simplekml
    if declutter:
        aps = _declutter(aps)
    kml = simplekml.Kml(name=doc_name)

    styles = {}
    for group, (color_attr, _label) in ENC_STYLE.items():
        st = simplekml.Style()
        st.iconstyle.color = getattr(simplekml.Color, color_attr)
        st.iconstyle.icon.href = "http://maps.google.com/mapfiles/kml/pushpin/wht-pushpin.png"
        st.labelstyle.scale = 0.8
        styles[group] = st

    def add_point(folder, ap):
        enc, cipher, auth = _enc_auth(ap["crypt"])
        p = folder.newpoint(name=ap["ssid"] or "(hidden)", coords=[(ap["lon"], ap["lat"])])
        p.style = styles[ap["group"]]
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
        p.extendeddata.newdata("ssid", ap["ssid"] or "(hidden)", "SSID")
        p.extendeddata.newdata("bssid", ap["mac"], "BSSID")
        p.extendeddata.newdata("encryption", ap["crypt"], "Encryption")
        p.extendeddata.newdata("enc", enc, "ENC")
        p.extendeddata.newdata("cipher", cipher, "Cipher")
        p.extendeddata.newdata("auth", auth, "Auth")
        p.extendeddata.newdata("channel", str(ap["channel"] or ""), "Channel")
        p.extendeddata.newdata(
            "signal", str(ap["signal"]) if ap["signal"] is not None else "n/a", "Signal dBm")
        return p

    # Tree 1: by encryption (shown by default)
    enc_root = kml.newfolder(name="Filter: by encryption")
    enc_folders = {}
    for group, (_c, label) in ENC_STYLE.items():
        enc_folders[group] = enc_root.newfolder(name=label)

    counts = {g: 0 for g in ENC_STYLE}
    for ap in aps:
        counts[ap["group"]] += 1
        add_point(enc_folders[ap["group"]], ap)

    # Tree 2: by SSID (hidden by default; check it and uncheck tree 1 to filter by SSID)
    ssid_root = kml.newfolder(name="Filter: by SSID")
    ssid_root.visibility = 0
    ssid_folders = {}
    for ap in sorted(aps, key=lambda a: (a["ssid"] or "\uffff").lower()):
        name = ap["ssid"] or "(hidden)"
        f = ssid_folders.get(name)
        if f is None:
            f = ssid_root.newfolder(name=name)
            f.visibility = 0
            ssid_folders[name] = f
        add_point(f, ap)

    kml.save(str(out_path))
    return counts


# ------------------------------------------------------------------ SSID detection heatmap
def _extract_ssid(b, base):
    """Best-effort SSID: beaconed SSID record, else the device common name."""
    name = b.get("kismet.device.base.commonname") or b.get("kismet.device.base.name") or ""
    dot11 = base.get("dot11.device", {}) if isinstance(base, dict) else {}
    rec = dot11.get("dot11.device.last_beaconed_ssid_record") or {}
    ssid = rec.get("dot11.advertisedssid.ssid") if isinstance(rec, dict) else None
    return ssid or name


def resolve_targets(dbpath, ssids, bssids):
    """Map the requested SSID(s) to the set of BSSIDs advertising them (an ESS can
    span several radios), unioned with any explicitly given BSSIDs. Returns
    (bssid_set, [(bssid, ssid, lat, lon)] for reference markers)."""
    want = {x.lower() for x in ssids}
    bset = {x.upper() for x in bssids}
    aps = []
    con = sqlite3.connect(f"file:{dbpath}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    cols = {r[1] for r in con.execute("PRAGMA table_info(devices)")}
    wanted = [c for c in ("devmac", "type", "avg_lat", "avg_lon", "device") if c in cols]
    q = f"SELECT {', '.join(wanted)} FROM devices"
    if "type" in cols:
        q += " WHERE type LIKE '%AP%'"
    for row in con.execute(q):
        r = dict(row)
        mac = (r.get("devmac") or "").upper()
        base = {}
        if r.get("device") is not None:
            try:
                base = json.loads(_maybe_gunzip(r["device"]))
            except (ValueError, TypeError):
                base = {}
        b = _base_view(base)
        ssid = _extract_ssid(b, base)
        if mac in bset or (want and ssid and ssid.lower() in want):
            bset.add(mac)
            aps.append((mac, ssid or "(hidden)",
                        _norm_coord(r.get("avg_lat")), _norm_coord(r.get("avg_lon"))))
    con.close()
    return bset, aps


def _weight(sig, density_mode):
    """Signal-weighted (default): -90 dBm -> ~0, -30 dBm -> 1, so the hot zone pulls
    toward the AP. Density mode weights every detection equally."""
    if density_mode:
        return 1.0
    if sig is None:
        return 0.35
    return max(0.03, min(1.0, (sig + 90) / 60.0))


def collect_detections(dbpath, bssids, density_mode):
    """Every geolocated packet whose sourcemac is one of the target BSSIDs, as
    (lat, lon, weight). packets.lat/lon are fixed-point *1e5; _norm_coord rescales."""
    con = sqlite3.connect(f"file:{dbpath}?mode=ro", uri=True)
    cols = {r[1] for r in con.execute("PRAGMA table_info(packets)")}
    if not {"lat", "lon", "sourcemac"} <= cols:
        con.close()
        return []
    have_sig = "signal" in cols
    macs = sorted(bssids)
    if not macs:
        con.close()
        return []
    qmarks = ",".join("?" * len(macs))
    sel = "lat, lon" + (", signal" if have_sig else "")
    q = (f"SELECT {sel} FROM packets "
         f"WHERE sourcemac IN ({qmarks}) AND lat != 0 AND lon != 0")
    samples = []
    for row in con.execute(q, macs):
        lat = _norm_coord(row[0])
        lon = _norm_coord(row[1])
        if lat is None or lon is None:
            continue
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            continue
        sig = row[2] if (have_sig and len(row) > 2) else None
        samples.append((lat, lon, _weight(sig, density_mode)))
    con.close()
    return samples


def _render_heat_png(samples, out_png):
    """KDE the weighted samples onto a grid, colorize with alpha, write an RGBA PNG.
    Returns (south, north, west, east) bounds for the GroundOverlay LatLonBox."""
    import numpy as np
    try:
        from matplotlib import colormaps
        cmap = colormaps["turbo"]
    except Exception:  # older matplotlib
        import matplotlib.cm as cm
        cmap = cm.get_cmap("turbo")
    import matplotlib.pyplot as plt

    lats = np.array([s[0] for s in samples], dtype=float)
    lons = np.array([s[1] for s in samples], dtype=float)
    wts = np.array([s[2] for s in samples], dtype=float)

    def bounds(v):
        lo, hi = float(v.min()), float(v.max())
        span = hi - lo
        pad = span * 0.15 if span > 0 else 0.0008  # ~90m fallback for a tight cluster
        return lo - pad, hi + pad

    south, north = bounds(lats)
    west, east = bounds(lons)

    GRID = 512
    H, _, _ = np.histogram2d(lons, lats, bins=GRID,
                             range=[[west, east], [south, north]], weights=wts)
    img = np.flipud(H.T)  # rows: north -> south, cols: west -> east

    # separable gaussian blur (numpy only, no scipy)
    sigma = GRID / 96.0
    radius = max(1, int(3 * sigma))
    x = np.arange(-radius, radius + 1)
    k = np.exp(-(x ** 2) / (2 * sigma ** 2))
    k /= k.sum()
    img = np.apply_along_axis(lambda m: np.convolve(m, k, mode="same"), 1, img)
    img = np.apply_along_axis(lambda m: np.convolve(m, k, mode="same"), 0, img)

    if img.max() > 0:
        img = img / img.max()

    rgba = cmap(img)
    rgba[..., 3] = np.clip(img ** 0.55, 0, 1) * 0.78  # transparent where cold
    plt.imsave(str(out_png), rgba)
    return south, north, west, east


def render_heatmap_kml(samples, aps, out_kml, out_png, doc_name, density_mode):
    import simplekml
    south, north, west, east = _render_heat_png(samples, out_png)

    kml = simplekml.Kml(name=doc_name)
    ground = kml.newgroundoverlay(name=doc_name)
    ground.icon.href = out_png.name          # relative; PNG must sit beside the KML
    ground.latlonbox.north = north
    ground.latlonbox.south = south
    ground.latlonbox.east = east
    ground.latlonbox.west = west
    ground.draworder = 1

    # Reference markers for the averaged AP position(s)
    fol = kml.newfolder(name="Access points")
    for mac, ssid, lat, lon in aps:
        if lat is None or lon is None or (lat == 0.0 and lon == 0.0):
            continue
        pt = fol.newpoint(name=ssid, coords=[(lon, lat)])
        pt.description = f"BSSID: {mac}"
        pt.style.iconstyle.icon.href = \
            "http://maps.google.com/mapfiles/kml/shapes/target.png"
    kml.save(str(out_kml))


def load_ssid_file(path):
    return [ln.strip() for ln in Path(path).read_text().splitlines() if ln.strip()]


def build_heatmap(dbpath, ssids, bssids, out_dir, slug, density_mode, fmt):
    if fmt == "folium":
        print("[!] Folium HTML output is not implemented yet; use --format kml.")
        return
    ensure_deps({"numpy": "numpy", "matplotlib": "matplotlib"})
    bset, aps = resolve_targets(dbpath, ssids, bssids)
    if not bset:
        print("[!] No AP in the log matched the requested SSID/BSSID.")
        return
    label = ", ".join(sorted({a[1] for a in aps}) or bset)
    mode = "detection-density" if density_mode else "signal-weighted"
    print(f"[*] Heatmap target(s): {label}  ({len(bset)} BSSID(s), {mode})")
    samples = collect_detections(dbpath, bset, density_mode)
    if len(samples) < 3:
        print(f"[!] Only {len(samples)} geolocated detections - not enough for a heatmap "
              "(GPS may not have had a fix while these frames were seen).")
        return
    print(f"[*] {len(samples)} geolocated detections")
    out_png = out_dir / f"{slug}_heatmap.png"
    out_kml = out_dir / f"{slug}_heatmap.kml"
    render_heatmap_kml(samples, aps, out_kml, out_png, f"{label} - detection heatmap",
                       density_mode)
    print(f"[+] Heatmap KML: {out_kml}")
    print(f"[+] Overlay PNG: {out_png}")
    print("[*] Open the .kml in Google Earth Pro; keep the .png beside it.")


# ------------------------------------------------------------------ AP detection report
def read_aps_for_report(dbpath):
    """Every Wi-Fi AP in the log (GPS optional, unlike the KML reader) with the
    fields an inventory/rogue report needs, plus per-BSSID frame counts."""
    con = sqlite3.connect(f"file:{dbpath}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    dcols = {r[1] for r in con.execute("PRAGMA table_info(devices)")}
    frames = {}
    pcols = {r[1] for r in con.execute("PRAGMA table_info(packets)")}
    if "sourcemac" in pcols:
        for mac, n in con.execute("SELECT sourcemac, COUNT(*) FROM packets GROUP BY sourcemac"):
            if mac:
                frames[mac.upper()] = n
    wanted = [c for c in ("devmac", "type", "avg_lat", "avg_lon", "strongest_signal",
                          "first_time", "last_time", "device") if c in dcols]
    q = f"SELECT {', '.join(wanted)} FROM devices"
    if "type" in dcols:
        q += " WHERE type LIKE '%AP%'"
    out = []
    for row in con.execute(q):
        r = dict(row)
        base = {}
        if r.get("device") is not None:
            try:
                base = json.loads(_maybe_gunzip(r["device"]))
            except (ValueError, TypeError):
                base = {}
        b = _base_view(base)
        mac = (r.get("devmac") or b.get("kismet.device.base.macaddr") or "").upper()
        sig = r.get("strongest_signal")
        if sig in (None, 0):
            sig = (b.get("kismet.device.base.signal", {})
                    .get("kismet.common.signal.max_signal"))
        lat = _norm_coord(r.get("avg_lat"))
        lon = _norm_coord(r.get("avg_lon"))
        lat = lat if (lat is not None and -90 <= lat <= 90 and lat != 0.0) else None
        lon = lon if (lon is not None and -180 <= lon <= 180 and lon != 0.0) else None
        out.append({
            "mac": mac,
            "ssid": _extract_ssid(b, base) or "",
            "crypt": b.get("kismet.device.base.crypt", "") or "Unknown",
            "channel": b.get("kismet.device.base.channel", ""),
            "signal": sig,
            "frames": frames.get(mac, 0),
            "first": r.get("first_time") or b.get("kismet.device.base.first_time"),
            "last": r.get("last_time") or b.get("kismet.device.base.last_time"),
            "lat": lat, "lon": lon,
        })
    con.close()
    return out


def _enc_auth(crypt):
    """Parse a kismet crypt_string like 'WPA3 WPA3-SAE AES-CCMP' into
    (ENC, CIPHER, AUTH), airodump-style."""
    c = (crypt or "").upper()
    if not c or c in ("OPEN", "NONE"):
        return ("OPEN", "", "")
    enc = ("WPA3" if "WPA3" in c else "WPA2" if "WPA2" in c else
           "WPA" if "WPA" in c else "WEP" if "WEP" in c else "OPEN")
    cipher = ("CCMP" if "CCMP" in c else "GCMP" if "GCMP" in c else
              "TKIP" if "TKIP" in c else "WEP" if "WEP" in c else "")
    auth = ("SAE" if "SAE" in c else
            "MGT" if ("EAP" in c or "MGT" in c or "802.1X" in c or "1X" in c) else
            "PSK" if "PSK" in c else "")
    return (enc, cipher, auth)


def _rogue_severity(sig, baseline, margin):
    """HIGH: candidate as strong as/stronger than the legit AP (out-powering it).
    MEDIUM: within `margin` dB below it. LOW: weaker. INFO: signal unknown."""
    if sig is None or baseline is None:
        return "INFO"
    if sig >= baseline:
        return "HIGH"
    if sig >= baseline - margin:
        return "MEDIUM"
    return "LOW"


def build_ap_report(dbpath, in_scope, known_bssids, out_txt, doc_name, margin):
    aps = read_aps_for_report(dbpath)
    if not aps:
        print("[!] No APs in the log to report.")
        return
    scope = {x.lower() for x in in_scope}
    known = {x.upper() for x in known_bssids}
    for ap in aps:
        ap["in_scope"] = bool(scope) and ap["ssid"].lower() in scope
    aps.sort(key=lambda a: (a["signal"] is None, -(a["signal"] or -999)))

    W = 92
    L = ["=" * W,
         f" WIRELESS AP DETECTION REPORT - {doc_name}",
         f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
         f"    APs detected: {len(aps)}"]
    if in_scope:
        L.append(f" In-scope SSID(s): {', '.join(in_scope)}")
    if known:
        L.append(f" Known-good BSSID(s): {', '.join(sorted(known))}")
    L += ["=" * W, "", " AP INVENTORY (sorted by signal)", " " + "-" * (W - 1),
          f" {'PWR':>4} {'BSSID':<17} {'CH':>3} {'ENC':<5} {'CIPHER':<6} {'AUTH':<4}"
          f" {'FRAMES':>7} {'SC':<2} ESSID", " " + "-" * (W - 1)]
    for ap in aps:
        enc, cipher, auth = _enc_auth(ap["crypt"])
        pwr = f"{ap['signal']}" if ap["signal"] is not None else "--"
        sc = "*" if ap["in_scope"] else ""
        L.append(f" {pwr:>4} {ap['mac']:<17} {str(ap['channel'] or ''):>3} {enc:<5}"
                 f" {cipher:<6} {auth:<4} {ap['frames']:>7} {sc:<2}"
                 f" {ap['ssid'] or '(hidden)'}")
    L.append("")

    if scope:
        L += [" ROGUE / EVIL-TWIN ANALYSIS", " " + "-" * (W - 1)]
        for ssid in in_scope:
            adv = [a for a in aps if a["ssid"].lower() == ssid.lower()]
            if not adv:
                L.append(f" [{ssid}] not observed in capture.")
                continue
            if known:
                legit = [a for a in adv if a["mac"] in known]
                baseline = max((a["signal"] for a in legit if a["signal"] is not None),
                               default=None)
                candidates = [a for a in adv if a["mac"] not in known]
                seen = ", ".join(a["mac"] for a in legit) or "none seen"
                L.append(f" [{ssid}] known-good: {seen}    baseline PWR: "
                         f"{baseline if baseline is not None else 'n/a'} dBm")
            else:
                order = sorted(adv, key=lambda a: (a["signal"] is None,
                                                   -(a["signal"] or -999)))
                baseline = order[0]["signal"]
                candidates = order[1:]
                L.append(f" [{ssid}] {len(adv)} BSSID(s) advertising this SSID; "
                         f"strongest {order[0]['mac']} @ {baseline} dBm used as reference "
                         "(supply --known-bssid for precise detection)")
            if not candidates:
                L.append("   No additional BSSIDs advertising this SSID.")
            for c in candidates:
                sev = _rogue_severity(c["signal"], baseline, margin)
                if c["signal"] is not None and baseline is not None:
                    delta = f"{c['signal'] - baseline:+d} dB vs ref"
                else:
                    delta = "signal n/a"
                pwr = c["signal"] if c["signal"] is not None else "--"
                L.append(f"   [{sev:<6}] {c['mac']}  PWR {pwr} dBm  ({delta})"
                         f"  CH {c['channel']}")
            L.append("")

    L += [" APPENDIX - FIRST/LAST SEEN & POSITION", " " + "-" * (W - 1)]
    for ap in aps:
        gps = (f"{ap['lat']:.6f},{ap['lon']:.6f}"
               if ap["lat"] is not None and ap["lon"] is not None else "no-fix")
        L.append(f" {ap['mac']:<17} first {_fmt_epoch(ap['first'])}"
                 f"  last {_fmt_epoch(ap['last'])}  {gps}  {ap['ssid'] or '(hidden)'}")
    L += ["", "=" * W]

    out_txt.write_text("\n".join(L) + "\n")
    rogue = sum(1 for ap in aps if ap["in_scope"])
    print(f"[+] AP report: {out_txt}  ({len(aps)} APs, {rogue} in-scope)")


# ------------------------------------------------------------------ orchestration
def _prompt_list(msg):
    """Read a comma/space-separated list from the user; empty input -> []."""
    raw = input(msg).strip()
    return [x for x in re.split(r"[,\s]+", raw) if x] if raw else []


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


def export(dbpath, out_path, doc_name, declutter=False):
    print(f"[*] Parsing {dbpath}")
    aps = list(read_kismetdb_aps(dbpath))
    if not aps:
        print("[!] No geolocated APs in the log (no fix during capture, or no APs seen).")
        return
    counts = generate_kml(aps, out_path, doc_name, declutter=declutter)
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
    ap.add_argument("--ssid", action="append", default=[],
                    help="Target SSID for the detection heatmap (repeatable)")
    ap.add_argument("--bssid", action="append", default=[],
                    help="Target BSSID for the heatmap (repeatable; use for hidden SSIDs)")
    ap.add_argument("--ssid-file", help="File of target SSIDs, one per line")
    ap.add_argument("--heatmap-only", metavar="FILE.kismet",
                    help="Build an SSID detection heatmap from an existing log; no capture")
    ap.add_argument("--heatmap-density", action="store_true",
                    help="Weight the heatmap by detection count instead of signal strength")
    ap.add_argument("--format", choices=["kml", "folium"], default="kml",
                    help="Heatmap output format (folium reserved for a later build)")
    ap.add_argument("--report-only", metavar="FILE.kismet",
                    help="Build the AP detection report from an existing log; no capture")
    ap.add_argument("--known-bssid", action="append", default=[],
                    help="Known-good BSSID for an in-scope SSID (repeatable); "
                         "enables precise evil-twin detection")
    ap.add_argument("--rogue-margin", type=int, default=15,
                    help="dB below the in-scope AP within which a same-SSID BSSID is "
                         "flagged MEDIUM (default: 15)")
    # The full pipeline (point KML + heatmap + report, decluttered) is the DEFAULT
    # on a bare run; the flags below only opt OUT of pieces.
    ap.add_argument("--no-heatmap", action="store_true",
                    help="Skip the per-SSID detection heatmap")
    ap.add_argument("--no-report", action="store_true",
                    help="Skip the AP detection / rogue-AP report")
    ap.add_argument("--no-declutter", action="store_true",
                    help="Do not spiral-offset APs that share identical coordinates")
    args = ap.parse_args()

    ssids = list(args.ssid)
    if args.ssid_file:
        ssids += load_ssid_file(args.ssid_file)
    known_bssids = list(args.known_bssid)
    declutter = not args.no_declutter

    # Regenerate-only path
    if args.kml_only:
        db = Path(args.kml_only).resolve()
        if not db.exists():
            print(f"[!] No such file: {db}")
            sys.exit(1)
        out = db.with_suffix(".kml")
        export(db, out, db.stem, declutter=declutter)
        return

    # Heatmap-only path
    if args.heatmap_only:
        db = Path(args.heatmap_only).resolve()
        if not db.exists():
            print(f"[!] No such file: {db}")
            sys.exit(1)
        if not ssids and not args.bssid:
            print("[!] --heatmap-only needs at least one --ssid or --bssid.")
            sys.exit(1)
        build_heatmap(db, ssids, args.bssid, db.parent, db.stem,
                      args.heatmap_density, args.format)
        return

    # Report-only path
    if args.report_only:
        db = Path(args.report_only).resolve()
        if not db.exists():
            print(f"[!] No such file: {db}")
            sys.exit(1)
        build_ap_report(db, ssids, known_bssids,
                        db.with_name(db.stem + "_ap_report.txt"), db.stem, args.rogue_margin)
        return

    site = args.site or input("[?] Site / location being assessed: ").strip()
    client = args.client or input("[?] Client name (optional): ").strip()
    slug = slugify(f"{client}-{site}" if client else site)
    iface = choose_interface(args.interface)

    if not ssids:
        ssids = _prompt_list(
            "[?] In-scope SSID(s), comma-separated (blank to skip heatmap/scope): ")
    if ssids and not known_bssids:
        known_bssids = _prompt_list(
            "[?] Known-good BSSID(s) for those SSIDs (blank if unknown): ")

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
    export(db, rundir / f"{slug}.kml", doc, declutter=declutter)

    if (ssids or args.bssid) and not args.no_heatmap:
        build_heatmap(db, ssids, args.bssid, rundir, slug,
                      args.heatmap_density, args.format)

    if not args.no_report:
        build_ap_report(db, ssids, known_bssids,
                        rundir / f"{slug}_ap_report.txt", doc, args.rogue_margin)


if __name__ == "__main__":
    main()
