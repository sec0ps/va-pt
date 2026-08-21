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
# Purpose: Standalone diagnostic that searches a target phrase against each
#          configured onion search engine independently, over the subsystem's own
#          managed Tor, so a single engine can be tested in isolation. Runs a
#          staged probe per engine -- landing-page reachability, then the search
#          query -- and classifies the outcome (unreachable, reachable-but-empty,
#          markup-miss, or hits) so an operator can tell a dead or slow onion apart
#          from a zero-result query or a parser drift. Fail-soft across engines
#          with an end-of-run summary; does not touch the database or scheduler.
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
# Location: darkweb-recon/engine_probe.py

"""Standalone per-engine search tester for manual diagnosis over Tor.

Each configured search engine is probed on its own, in two stages. The first
stage times a fetch of the engine's landing page to isolate Tor-to-onion
reachability from anything query-specific; a SOCKS connect timeout or a
'Host unreachable' here means the onion is down or its descriptor/rendezvous is
failing, not that the search returned nothing. The second stage runs the real
search and reports hit count and timing. Outcomes are classified so the operator
can distinguish a dead or slow onion from a genuine zero-result query and from a
parser that no longer matches the engine's markup. Engines are independent:
one failing never aborts the others, and a summary prints at the end.
"""

from __future__ import annotations

import os
import sys

_venv_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv")
_venv_python = os.path.join(_venv_dir, "bin", "python")
if os.path.exists(_venv_python) and os.path.abspath(sys.prefix) != os.path.abspath(_venv_dir):
    os.execv(_venv_python, [_venv_python] + sys.argv)

import json
import time
import argparse
import logging

from config import Config
from torctl import TorController, AttachedTorController, TorError, _port_available
from fetch import TorFetcher, FetchError
from sources.ahmia import AhmiaSource
from sources.torch import TorchSource
from sources.excavator import ExcavatorSource
from sources.tor66 import Tor66Source
from sources.onionlive import OnionLiveSource

log = logging.getLogger("recon.probe")


def build_engines(config):
    """Map engine name -> source instance, using configured base urls."""
    return {
        "ahmia": AhmiaSource(config.ahmia_base_url),
        "torch": TorchSource(config.torch_base_url),
        "excavator": ExcavatorSource(config.excavator_base_url),
        "tor66": Tor66Source(config.tor66_base_url),
        "onionlive": OnionLiveSource(config.onionlive_base_url),
    }


def classify_error(exc):
    """Return a short human verdict for a fetch failure, from the error text."""
    text = str(exc).lower()
    if "host unreachable" in text or "0x04" in text:
        return "onion unreachable (service down, or descriptor/rendezvous failed)"
    if "timed out" in text or "timeout" in text:
        return "connect timed out (onion slow or unreachable; try --connect-timeout higher)"
    if "0x02" in text or "connection not allowed" in text:
        return "connection refused by exit/onion policy"
    if "nonce" in text or "markup may have changed" in text or "search form" in text:
        return "reached engine, but its page markup did not parse (parser drift)"
    return "request failed"


def probe_engine(name, source, fetcher, term, limit, isolation):
    """Two-stage probe for one engine. Returns a result dict, never raises."""
    home_url = source.base_url + "/"
    out = {"engine": name, "home_url": home_url, "term": term}

    # Stage 1: landing-page reachability (isolates tor->onion from the query).
    t0 = time.time()
    try:
        fetcher.get_with_retry(home_url, isolation=isolation)
        out["reachable"] = True
        out["reach_seconds"] = round(time.time() - t0, 1)
    except (FetchError, Exception) as exc:  # noqa: BLE001 - probe must never abort
        out["reachable"] = False
        out["reach_seconds"] = round(time.time() - t0, 1)
        out["error"] = str(exc)
        out["verdict"] = classify_error(exc)
        return out

    # Stage 2: the actual search.
    t1 = time.time()
    try:
        hits = source.search(term, fetcher, isolation=isolation, limit=limit)
        out["search_seconds"] = round(time.time() - t1, 1)
        out["hits"] = [h.as_dict() for h in hits]
        out["hit_count"] = len(hits)
        if hits:
            out["verdict"] = "ok, %d hit(s)" % len(hits)
        else:
            out["verdict"] = ("reachable but 0 results (empty query result, "
                              "or parser matched nothing)")
    except (FetchError, Exception) as exc:  # noqa: BLE001
        out["search_seconds"] = round(time.time() - t1, 1)
        out["error"] = str(exc)
        out["verdict"] = classify_error(exc)
    return out


def emit(results, as_json):
    if as_json:
        print(json.dumps(results, indent=2))
        return
    for r in results:
        print("\n== %s  [%s] ==" % (r["engine"], r["term"]))
        print("   home: %s" % r["home_url"])
        if not r.get("reachable"):
            print("   UNREACHABLE after %ss -> %s" % (r.get("reach_seconds"), r["verdict"]))
            print("   detail: %s" % r.get("error", ""))
            continue
        print("   reachable in %ss" % r.get("reach_seconds"))
        if "error" in r:
            print("   SEARCH FAILED after %ss -> %s" % (r.get("search_seconds"), r["verdict"]))
            print("   detail: %s" % r["error"])
            continue
        print("   search %ss -> %s" % (r.get("search_seconds"), r["verdict"]))
        for hit in r.get("hits", [])[:10]:
            print("     %s" % (hit["title"] or hit["url"]))
            print("       %s" % hit["url"])
            if hit["snippet"]:
                print("       %s" % hit["snippet"][:160])
        extra = r.get("hit_count", 0) - 10
        if extra > 0:
            print("     (+%d more)" % extra)


def summary(results):
    print("\n-- summary --")
    for r in results:
        print("   %-10s %s" % (r["engine"], r.get("verdict", "?")))


def build_parser():
    p = argparse.ArgumentParser(
        description="Search a phrase against each onion search engine independently, over Tor")
    p.add_argument("-t", "--term", required=True, action="append",
                   help="target phrase to search, may be repeated")
    p.add_argument("-e", "--engine", action="append",
                   help="engine to test (ahmia, torch, excavator, tor66, onionlive); repeatable; default all")
    p.add_argument("-l", "--limit", type=int, default=25, help="max results per term")
    p.add_argument("--engagement", default="probe",
                   help="engagement tag used for circuit isolation")
    p.add_argument("--tor-mode", choices=("auto", "attach", "launch"), default="auto",
                   help="auto: attach to a running tor (e.g. the console's), else launch "
                        "own; attach: require a running tor; launch: force own managed tor")
    p.add_argument("--connect-timeout", type=int,
                   help="override fetch connect timeout (s); raise for slow onions")
    p.add_argument("--read-timeout", type=int, help="override fetch read timeout (s)")
    p.add_argument("--json", action="store_true", help="emit json output")
    p.add_argument("--quiet", action="store_true", help="suppress tor bootstrap logs")
    return p


def acquire_tor(config, mode):
    """Return a started tor controller per mode. Never reaps the console's tor.

    auto:   attach to a tor already running on the configured ports (the console's);
            if none is attachable, launch our own only when the ports are free.
    attach: require an already-running tor; error if none.
    launch: force our own managed tor (this reaps our orphans and will collide with
            a running console -- use only when the console is stopped).
    """
    if mode in ("auto", "attach"):
        att = AttachedTorController(config)
        try:
            att.start()
            log.info("attached to running tor (control %d, socks %d)",
                     config.tor_control_port, config.tor_socks_port)
            return att
        except TorError as exc:
            if mode == "attach":
                raise SystemExit(
                    "attach failed: %s\nis the console (run.py) running? "
                    "or use --tor-mode launch with the console stopped" % exc)
            ports_busy = [p for p in (config.tor_socks_port, config.tor_control_port)
                          if not _port_available(p)]
            if ports_busy:
                raise SystemExit(
                    "a tor is on port %s but I could not attach to it (%s); refusing to "
                    "launch a second tor or disturb it. run with the console up so I can "
                    "attach, or stop it and use --tor-mode launch"
                    % (" and ".join(map(str, ports_busy)), exc))
            log.info("no running tor found; launching a managed tor")
    tor = TorController(config)
    tor.start()
    return tor


def run(args):
    config = Config()
    if args.quiet:
        config.tor_verbose = False
    if args.connect_timeout:
        config.fetch_connect_timeout = args.connect_timeout
    if args.read_timeout:
        config.fetch_read_timeout = args.read_timeout
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    engines = build_engines(config)
    selected = args.engine or list(engines.keys())
    unknown = [e for e in selected if e not in engines]
    if unknown:
        raise SystemExit("unknown engine(s): %s (known: %s)"
                         % (", ".join(unknown), ", ".join(engines)))

    results = []
    try:
        tor = acquire_tor(config, args.tor_mode)
    except TorError as exc:
        raise SystemExit("tor failed to start: %s" % exc)
    try:
        fetcher = TorFetcher(tor, config)
        for term in args.term:
            for name in selected:
                log.info("probing %s for %r", name, term)
                results.append(
                    probe_engine(name, engines[name], fetcher, term, args.limit,
                                 "%s-%s" % (args.engagement, name)))
    finally:
        tor.stop()  # attach: closes control conn only; launch: stops our own tor

    emit(results, args.json)
    if not args.json:
        summary(results)


def main():
    try:
        run(build_parser().parse_args())
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
