#!/usr/bin/env python3
"""Connect to the orchestrator's msfrpcd and interact with an open session.

The orchestrator opens sessions inside the msfrpcd daemon, not in the
orchestrator process. They stay reachable only while that daemon runs. If the
orchestrator autostarted msfrpcd (the default when none is already listening),
it kills the daemon -- and every session -- when the run exits. To keep sessions
alive past a run, start msfrpcd yourself first; the orchestrator then reuses it
and leaves it running.

Connection defaults match what the orchestrator launches:
    msfrpcd -f -a 127.0.0.1 -p 55553 -U msf -P <password>   (SSL on)
The password is read from .orchestration_config (key "msf_rpc_password") in the
current directory unless given via --password or the MSF_RPC_PASS env var.

Usage:
    python msf_session.py                 # list open sessions
    python msf_session.py -i 1            # interact with session id 1
"""

import argparse
import json
import os
import sys
import time

CONFIG_FILE = ".orchestration_config"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 55553
DEFAULT_USER = "msf"


def load_password(explicit):
    if explicit:
        return explicit
    env = os.environ.get("MSF_RPC_PASS")
    if env:
        return env
    try:
        with open(CONFIG_FILE) as f:
            pw = json.load(f).get("msf_rpc_password", "")
        if isinstance(pw, str) and pw:
            return pw
    except (OSError, ValueError):
        pass
    sys.exit("no password found: pass --password, set MSF_RPC_PASS, or run from "
             f"the directory holding {CONFIG_FILE}")


def connect(args):
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
    except ImportError:
        sys.exit("pymetasploit3 not installed: pip install pymetasploit3")
    pw = load_password(args.password)
    try:
        return MsfRpcClient(pw, server=args.host, port=args.port,
                            ssl=args.ssl, username=args.user)
    except Exception as e:
        sys.exit(f"could not connect to msfrpcd at {args.host}:{args.port}: {e}\n"
                 "is the daemon still running? check: pgrep -af msfrpcd")


def _session_table(sessions):
    if not sessions:
        print("no open sessions (daemon may have been restarted, or the run "
              "killed it on exit)")
        return
    print(f"{'id':<4} {'type':<12} {'peer':<22} info")
    print("-" * 60)
    for sid, meta in sessions.items():
        print(f"{str(sid):<4} {str(meta.get('type', '')):<12} "
              f"{str(meta.get('tunnel_peer', '')):<22} "
              f"{meta.get('info', '')}")


def list_sessions(client):
    _session_table(client.sessions.list)


def interact(client, sid):
    sessions = client.sessions.list
    key = next((k for k in sessions if str(k) == str(sid)), None)
    if key is None:
        print(f"session {sid} not found. open sessions:")
        _session_table(sessions)
        sys.exit(1)
    meta = sessions[key]
    stype = str(meta.get("type", ""))
    shell = client.sessions.session(key)
    print(f"attached to session {sid} ({stype}) on "
          f"{meta.get('tunnel_peer', '')}")
    print("enter commands; 'exit' or Ctrl-D detaches (the session stays open)\n")
    try:
        shell.read()                       # drain any pending banner
    except Exception:
        pass
    while True:
        try:
            cmd = input("session> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd.strip() in ("exit", "quit"):
            break
        if not cmd.strip():
            continue
        try:
            if stype == "meterpreter":
                sys.stdout.write(shell.run_with_output(cmd + "\n", ["\n"]))
            else:
                shell.write(cmd + "\n")
                time.sleep(0.4)
                sys.stdout.write(shell.read())
            sys.stdout.flush()
        except Exception as e:
            print(f"error: {e}")
    print("detached; session left open in msfrpcd")


def main():
    p = argparse.ArgumentParser(
        description="interact with sessions opened in the orchestrator's msfrpcd")
    p.add_argument("-i", "--interact", help="session id to attach to")
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--user", default=DEFAULT_USER)
    p.add_argument("--password", default=None,
                   help=f"else MSF_RPC_PASS env, else {CONFIG_FILE}")
    ssl = p.add_mutually_exclusive_group()
    ssl.add_argument("--ssl", dest="ssl", action="store_true", default=True)
    ssl.add_argument("--no-ssl", dest="ssl", action="store_false")
    args = p.parse_args()
    client = connect(args)
    if args.interact:
        interact(client, args.interact)
    else:
        list_sessions(client)


if __name__ == "__main__":
    main()
