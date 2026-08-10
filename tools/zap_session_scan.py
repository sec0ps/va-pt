#!/usr/bin/env python3
# =============================================================================
# Location    tools/zap_session_scan.py
# Author      Keith Pachulski
# Company     Red Cell Security LLC
# Email       keith@redcellsecurity.org
# Website     www.redcellsecurity.org
#
# License     MIT License
#
# Purpose     Batch web scanner that drives a self-managed headless ZAP daemon
#             over a flat target list or a single target. Per target it opens a
#             fresh ZAP session named for the target, restricts scope to that
#             target only, spiders, ajax spiders, runs the active scan with the
#             Pen Test policy, saves the session immediately, and closes it
#             before the next target. The daemon is torn down when the run ends.
#
# SECURITY NOTICE
#             This software is intended for authorized security assessment and
#             defensive operations only. Use it exclusively on systems you own or
#             are explicitly permitted to test. Unauthorized use may violate law.
#
# DISCLAIMER
#             This software is provided "as is" without warranty of any kind. The
#             author and Red Cell Security LLC accept no liability for damage or
#             misuse arising from its operation.
# =============================================================================
"""zap_session_scan.py - batch ZAP web scanner writing one saved session per target."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlsplit


# -- console output ----------------------------------------------------------

def say(msg):
    print(msg, flush=True)


# -- zap rest client ---------------------------------------------------------

class ZapError(Exception):
    pass


class ZapClient:
    def __init__(self, host, port, api_key, timeout=60):
        self.host = host
        self.port = int(port)
        self.api_key = api_key or ""
        self.timeout = timeout

    @property
    def base(self):
        return f"http://{self.host}:{self.port}"

    def _call(self, path, **params):
        params["apikey"] = self.api_key
        url = f"{self.base}{path}?{urllib.parse.urlencode(params)}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            raise ZapError(_http_detail(e))
        except urllib.error.URLError as e:
            raise ZapError(f"cannot reach ZAP at {self.host}:{self.port} "
                           f"({e.reason})")
        except (ValueError, OSError) as e:
            raise ZapError(str(e))
        if isinstance(data, dict) and data.get("code") and not data.get("version"):
            if data.get("message"):
                raise ZapError(data["message"])
        return data

    # meta
    def version(self):
        return self._call("/JSON/core/view/version/").get("version")

    def shutdown(self):
        return self._call("/JSON/core/action/shutdown/")

    # session lifecycle
    def new_session(self, name="", overwrite=True):
        params = {"overwrite": "true" if overwrite else "false"}
        if name:
            params["name"] = name
        return self._call("/JSON/core/action/newSession/", **params)

    def save_session(self, name, overwrite=True):
        return self._call("/JSON/core/action/saveSession/",
                          name=name, overwrite="true" if overwrite else "false")

    # context and scope
    def new_context(self, name):
        return self._call("/JSON/context/action/newContext/",
                          contextName=name).get("contextId")

    def include_in_context(self, name, url):
        regex = re.escape(url) + ".*"
        return self._call("/JSON/context/action/includeInContext/",
                          contextName=name, regex=regex)

    # spider (subtree only keeps the crawl on the target)
    def spider(self, url, context_name=None):
        params = {"url": url, "recurse": "true", "maxChildren": "0",
                  "subtreeOnly": "true"}
        if context_name:
            params["contextName"] = context_name
        return self._call("/JSON/spider/action/scan/", **params).get("scan")

    def spider_status(self, scan_id):
        return int(self._call("/JSON/spider/view/status/",
                              scanId=scan_id).get("status", "0"))

    # ajax spider (subtree only keeps the crawl on the target)
    def ajax_spider(self, url, context_name=None):
        params = {"url": url, "inScope": "false", "subtreeOnly": "true"}
        if context_name:
            params["contextName"] = context_name
        return self._call("/JSON/ajaxSpider/action/scan/", **params)

    def ajax_status(self):
        return self._call("/JSON/ajaxSpider/view/status/").get("status",
                                                               "stopped")

    def ajax_stop(self):
        return self._call("/JSON/ajaxSpider/action/stop/")

    # active scan
    def active_scan(self, url, policy, context_id=None):
        params = {"url": url, "recurse": "true", "scanPolicyName": policy}
        if context_id is not None:
            params["contextId"] = str(context_id)
        return self._call("/JSON/ascan/action/scan/", **params).get("scan")

    def ascan_status(self, scan_id):
        return int(self._call("/JSON/ascan/view/status/",
                              scanId=scan_id).get("status", "0"))

    # policy check
    def policy_names(self):
        return self._call(
            "/JSON/ascan/view/scanPolicyNames/").get("scanPolicyNames", [])

    # console readout only, no export
    def alerts_summary(self, baseurl):
        d = self._call("/JSON/alert/view/alertsSummary/", baseurl=baseurl)
        return d.get("alertsSummary", d)


def _http_detail(e):
    try:
        body = json.loads(e.read().decode("utf-8", "replace"))
        if isinstance(body, dict) and (body.get("message") or body.get("code")):
            return body.get("message") or body.get("code")
    except (ValueError, OSError):
        pass
    if e.code == 403:
        return "rejected by ZAP, check the api key"
    return f"HTTP {e.code} from ZAP"


# -- target handling ---------------------------------------------------------

def normalize_target(line):
    """Trim a raw list line, drop blanks and comments, ensure a scheme."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "://" not in line:
        line = "http://" + line
    return line


def read_targets(source):
    """A file path yields its lines. Anything else is a single target."""
    if os.path.isfile(source):
        out, seen = [], set()
        with open(source, encoding="utf-8", errors="replace") as f:
            for raw in f:
                t = normalize_target(raw)
                if t and t not in seen:
                    seen.add(t)
                    out.append(t)
        return out
    t = normalize_target(source)
    return [t] if t else []


def _is_ipv4(host):
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def session_name_for(url):
    """IPv4 dots become underscores, IPv6 colons become underscores, hostnames
    keep their dots. Matches the naming shown in the request."""
    host = urlsplit(url).hostname or ""
    if not host:
        return re.sub(r"[^A-Za-z0-9._-]", "_", url)
    if _is_ipv4(host):
        return host.replace(".", "_")
    if ":" in host:
        return host.replace(":", "_")
    return host


def host_port(url):
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return host, port


def target_up(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# -- polling waiters ---------------------------------------------------------

def wait_scan(status_fn, poll, timeout, label):
    """Poll an integer percent to 100. Prints at each 20 percent bucket."""
    waited, last_bucket = 0, -1
    while waited < timeout:
        try:
            pct = status_fn()
        except ZapError as e:
            say(f"    [!] {label} poll error ({e})")
            return False
        bucket = pct // 20
        if bucket != last_bucket:
            say(f"    {label} {pct}%")
            last_bucket = bucket
        if pct >= 100:
            return True
        time.sleep(poll)
        waited += poll
    say(f"    [!] {label} timed out after {timeout}s")
    return False


def wait_ajax(status_fn, poll, timeout):
    waited = 0
    while waited < timeout:
        try:
            if status_fn() != "running":
                return True
        except ZapError as e:
            say(f"    [!] ajax poll error ({e})")
            return False
        time.sleep(poll)
        waited += poll
    say(f"    [!] ajax spider timed out after {timeout}s")
    return False


# -- daemon lifecycle --------------------------------------------------------

def _locate_zap():
    """Query the locate database for zap.sh. Returns existing files whose base
    name is exactly zap.sh, deduped by real path. Empty when locate is absent,
    its database is stale, or nothing matches."""
    tool = shutil.which("locate") or shutil.which("plocate")
    if not tool:
        return []
    try:
        out = subprocess.run([tool, "zap.sh"], capture_output=True,
                             text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return []
    found, seen_real = [], set()
    for line in out.stdout.splitlines():
        p = line.strip()
        if not p or os.path.basename(p) != "zap.sh" or not os.path.isfile(p):
            continue
        rp = os.path.realpath(p)
        if rp in seen_real:
            continue
        seen_real.add(rp)
        found.append(p)
    return sorted(found)


def _choose_zap(paths):
    """Ask the operator to pick one of several zap.sh paths. Returns the chosen
    path or None if the operator gives no valid answer."""
    say("[*] multiple zap.sh found, choose one")
    for i, p in enumerate(paths, 1):
        say(f"    {i}) {p}")
    while True:
        try:
            raw = input("    selection number, or blank to abort ").strip()
        except EOFError:
            return None
        if not raw:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(paths):
            return paths[int(raw) - 1]
        say("    invalid, enter a listed number")


def find_zap(explicit):
    if explicit:
        return explicit
    env = os.environ.get("CONSOLE_ZAP_PATH")
    if env:
        return env
    hits = _locate_zap()
    if len(hits) == 1:
        say(f"[*] located ZAP at {hits[0]}")
        return hits[0]
    if len(hits) > 1:
        if sys.stdin.isatty():
            chosen = _choose_zap(hits)
            if chosen:
                say(f"[*] using {chosen}")
                return chosen
        else:
            say("[!] multiple zap.sh found and no terminal to choose from, "
                "pass --zap-path")
            for p in hits:
                say(f"    {p}")
            return None
    for name in ("zap.sh", "zap", "zaproxy", "owasp-zap"):
        found = shutil.which(name)
        if found:
            return found
    return None


def start_zap(zap_path, host, port, api_key, zap_dir):
    argv = [zap_path, "-daemon",
            "-host", host, "-port", str(port),
            "-config", f"api.key={api_key}",
            "-config", "api.disablekey=false"]
    if zap_dir:
        argv += ["-dir", zap_dir]
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)


def wait_up(zc, host, port, timeout=180, interval=3):
    waited = 0
    while waited < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                pass
            v = zc.version()
            if v:
                return v
        except (OSError, ZapError):
            pass
        time.sleep(interval)
        waited += interval
    return None


def stop_zap(zc, proc):
    try:
        zc.shutdown()
    except ZapError:
        pass
    if proc is None:
        return
    try:
        proc.wait(timeout=20)
        return
    except subprocess.TimeoutExpired:
        pass
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


# -- per target scan ---------------------------------------------------------

def scan_one(zc, url, out_dir, policy, use_ajax, poll,
             spider_timeout, ajax_timeout, ascan_timeout, reach_timeout):
    name = session_name_for(url)
    host, port = host_port(url)
    session_path = os.path.join(out_dir, name)
    say("")
    say(f"[*] target {url}  session {name}")

    if not target_up(host, port, reach_timeout):
        say(f"[-] UNREACHABLE {host}:{port}  skipping, no session written")
        return "unreachable"

    # a fresh session both starts clean and closes the previous target's session
    zc.new_session()
    ctx = "ctx_" + name
    ctx_id = zc.new_context(ctx)
    zc.include_in_context(ctx, url)

    say("    [*] spider")
    sid = zc.spider(url, ctx)
    wait_scan(lambda: zc.spider_status(sid), poll, spider_timeout, "spider")

    if use_ajax:
        say("    [*] ajax spider")
        zc.ajax_spider(url, ctx)
        wait_ajax(lambda: zc.ajax_status(), poll, ajax_timeout)
        try:
            zc.ajax_stop()
        except ZapError:
            pass

    say(f"    [*] active scan ({policy})")
    aid = zc.active_scan(url, policy, ctx_id)
    wait_scan(lambda: zc.ascan_status(aid), poll, ascan_timeout, "active scan")

    try:
        s = zc.alerts_summary(url)
        say(f"    [+] alerts High {s.get('High', 0)} "
            f"Medium {s.get('Medium', 0)} "
            f"Low {s.get('Low', 0)} "
            f"Info {s.get('Informational', 0)}")
    except ZapError:
        pass

    zc.save_session(session_path, overwrite=True)
    say(f"[+] saved {session_path}.session")
    return "scanned"


# -- entry point -------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Batch ZAP web scanner, one saved session per target")
    p.add_argument("targets",
                   help="path to a flat target list or a single target url/host")
    p.add_argument("-o", "--output-dir", default=".",
                   help="directory where the per target sessions are written, "
                        "defaults to the current working directory")
    p.add_argument("--policy", default="Pen Test",
                   help="ZAP scan policy name to run for the active scan")
    p.add_argument("--zap-path",
                   help="path to zap.sh, else CONSOLE_ZAP_PATH or PATH lookup")
    p.add_argument("--zap-host", default="127.0.0.1")
    p.add_argument("--zap-port", type=int, default=8090)
    p.add_argument("--zap-dir",
                   help="ZAP home directory that holds the Pen Test policy")
    p.add_argument("--api-key",
                   help="ZAP api key, generated when managing our own daemon")
    p.add_argument("--attach", action="store_true",
                   help="attach to a running ZAP, do not start or tear it down")
    p.add_argument("--no-ajax", action="store_true",
                   help="skip the ajax spider phase")
    p.add_argument("--poll", type=int, default=3)
    p.add_argument("--spider-timeout", type=int, default=900)
    p.add_argument("--ajax-timeout", type=int, default=600)
    p.add_argument("--ascan-timeout", type=int, default=3600)
    p.add_argument("--reach-timeout", type=int, default=5)
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    targets = read_targets(args.targets)
    if not targets:
        say("[!] no targets found")
        return 2

    out_dir = os.path.abspath(args.output_dir)
    os.makedirs(out_dir, exist_ok=True)

    proc = None
    managing = not args.attach

    if managing:
        api_key = args.api_key or secrets.token_urlsafe(24)
        zap_path = find_zap(args.zap_path)
        if not zap_path:
            say("[!] no ZAP binary found, pass --zap-path or set CONSOLE_ZAP_PATH")
            return 3
        say(f"[*] starting ZAP daemon at {args.zap_host}:{args.zap_port}")
        try:
            proc = start_zap(zap_path, args.zap_host, args.zap_port,
                             api_key, args.zap_dir)
        except (OSError, ValueError) as e:
            say(f"[!] could not launch ZAP ({e})")
            return 3
    else:
        api_key = args.api_key or ""
        say(f"[*] attaching to ZAP at {args.zap_host}:{args.zap_port}")

    zc = ZapClient(args.zap_host, args.zap_port, api_key)

    if managing:
        version = wait_up(zc, args.zap_host, args.zap_port)
        if not version:
            say("[!] ZAP did not come up in time")
            stop_zap(zc, proc)
            return 3
        say(f"[+] ZAP {version} up")
    else:
        try:
            version = zc.version()
        except ZapError as e:
            say(f"[!] cannot reach the attached ZAP ({e})")
            return 3
        if not version:
            say("[!] attached ZAP did not answer with a version")
            return 3
        say(f"[+] ZAP {version} reachable")

    try:
        if args.policy not in zc.policy_names():
            say(f"[!] scan policy '{args.policy}' not present in this ZAP")
            say("    load the policy into the ZAP home before scanning "
                "(see --zap-dir)")
            if managing:
                stop_zap(zc, proc)
            return 4
    except ZapError as e:
        say(f"[!] could not read scan policies ({e})")
        if managing:
            stop_zap(zc, proc)
        return 4

    use_ajax = not args.no_ajax
    results = {"scanned": [], "unreachable": [], "failed": []}

    def teardown(*_):
        if managing:
            say("")
            say("[*] tearing down ZAP daemon")
            stop_zap(zc, proc)

    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit))

    try:
        for url in targets:
            try:
                outcome = scan_one(
                    zc, url, out_dir, args.policy, use_ajax, args.poll,
                    args.spider_timeout, args.ajax_timeout,
                    args.ascan_timeout, args.reach_timeout)
                results[outcome].append(url)
            except ZapError as e:
                say(f"[!] scan error on {url} ({e})")
                results["failed"].append(url)
    except (KeyboardInterrupt, SystemExit):
        say("")
        say("[!] interrupted, stopping")
    finally:
        teardown()

    say("")
    say(f"[=] scanned {len(results['scanned'])}  "
        f"unreachable {len(results['unreachable'])}  "
        f"failed {len(results['failed'])}")
    for u in results["unreachable"]:
        say(f"    unreachable {u}")
    for u in results["failed"]:
        say(f"    failed {u}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
