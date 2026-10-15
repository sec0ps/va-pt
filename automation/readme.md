# Latchkey Engine Community

Automated network exploitation pipeline. It sweeps a scope for live hosts,
fingerprints their services with nmap and vulners, matches CVEs and products to
Metasploit modules, fires them, brute-forces credentials, and reports only proven
impact: sessions, recovered credentials, and confirmed unauthenticated access.

Pipeline: discovery -> per-host scan (`nmap -sV` + vulners) -> candidate analysis
-> exploit and auxiliary fire -> credential brute (Metasploit login scanners, then
NSE brute scripts) -> credentialed re-fire -> NSE verify -> teardown.

## Requirements

- Linux, run as root (`sudo`). Needed for the port scan, the firewall toggle, and
  reverse payload listeners.
- `nmap`, with the `vulners` NSE script and reachability to the vulners API.
- Metasploit Framework (`msfrpcd`). Started automatically unless
  `--no-msf-autostart` is given.
- Python 3. `rich` and `pymetasploit3` are installed automatically into a
  root-owned venv at `/opt/va-pt-venv` on first run, and the program re-execs
  under it. Use `--no-venv` to run under the current interpreter instead.

## Usage

```
# scan and exploit a subnet
sudo python3 orchestrator.py 10.0.0.0/24

# a single host, headless
sudo python3 orchestrator.py --no-tui 10.0.0.5

# resume an interrupted run
sudo python3 orchestrator.py --resume 10.0.0.0/24
```

Targets accept IPs, CIDRs, `a-b` ranges, hostnames, or `-iL file`. Exclude with
`--exclude` / `--exclude-file`. The first run generates an msfrpcd password into
`.orchestration_config` (mode 0600) in the working directory and reuses it after.

## Key flags

- `--mincvss FLOAT` CVE floor for vulners (default 7.0)
- `--top-ports N` / `--ports LIST` discovery surface
- `--workers N` / `--fire-workers N` scan and fire parallelism
- `--stop-at-first-session` stop exploit fires on a host once it holds an exploit
  session; default exploits every service
- `--release-msfrpcd` at teardown capture read-only proof of execution in each
  session, record it, kill the session, and stop a daemon the engine started
- `--lhost IP` pin the reverse-payload callback address
- `--no-msf-autostart` attach to an already-running msfrpcd
- `--no-tui` headless; `--yes` skip the large-scope prompt

Everything else: `--help`.

## Output

- `vapt_findings.json` proven findings: sessions, credentials, access, and any
  host that went unreachable during the run
- `verify_findings.json` NSE detections from the verify pass
- `vapt_run_checkpoint.json` resumable state, flushed during the run
- `vapt_run.log` run log (where logging goes while the dashboard is up)
- `--nmap-out-dir DIR` optional per-host `-sV`/vulners XML

## Behavior

The host firewall is snapshotted, disabled for the run so callbacks are not
blocked, and restored at teardown with an atexit backstop. One Ctrl-C drains
in-flight work, restores the firewall, and writes a final checkpoint; do not
SIGKILL it. Scopes over 4096 hosts prompt unless `--yes`; over 65536 hard-stop.

A host that stops answering mid-run is marked unreachable, skipped for every
remaining phase, and reported with the operation last started against it. By
default a daemon the engine started is left running when sessions are open so the
access survives the run; `--release-msfrpcd` proves and closes them instead.

## Files

- `orchestrator.py` entry point: CLI, pipeline, threading, config
- `state.py` data model, thread-safe run state, checkpoint and findings
- `scanner.py` nmap discovery, vulners scan, NSE verify and brute
- `msf.py` Metasploit RPC: candidate selection, fire, brute, proof capture
- `system.py` preflight, firewall save/restore, msfrpcd lifecycle
- `nse_catalog.py` builds the NSE script catalog the verify pass selects from
- `tui.py` rich live dashboard

## Professional Services

### Red Cell Security, LLC

For enterprise deployments, custom integrations, or professional security assessments:

- **Email**: <operations@redcellsecurity.org>
- **Website**: [www.redcellsecurity.org](http://www.redcellsecurity.org)
- **Services**: Custom RF security solutions, threat hunting, defensive countermeasures

## Authorization and Disclaimer

This toolkit is intended for authorized security testing only. Users are responsible for ensuring compliance with all applicable laws and regulations. Unauthorized use of these tools may violate local, state, federal, and international laws.

This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

## License and Copyright

**Company**: Red Cell Security, LLC
**Email**: <operations@redcellsecurity.org>
**Website**: [www.redcellsecurity.org](http://www.redcellsecurity.org)

© 2026 Red Cell Security, LLC. All rights reserved.

**License**: MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support Development

If you find this project valuable for your security operations:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)
