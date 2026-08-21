# darkweb-recon

Tor-based dark web reconnaissance for authorized OSINT and VAPT engagements. Run manual searches from the CLI, or scheduled and on-demand content searches from a multi-user web console. Every fetch goes through a managed Tor instance with per-engagement stream isolation, across five onion search engines.

## Warning

This tool fetches hostile content from onion services. Run it inside a dedicated research VM or a segmented network — the VM is the isolation boundary, not any wrapper around it. Do not run it on a host you care about. Deployment is `install.py` plus an optional systemd unit; there is no container image, by design (a container is packaging, not isolation).

## How it works

One console daemon starts Tor, a bounded worker pool, the APScheduler engine, and a waitress-served Flask console together. A search job queries the enabled engines over Tor, deduplicates hits per workspace on a content hash — collapsing the same URL across engines into a single finding — records which engine surfaced each result (provenance) separately from watch-term content matches, and files findings you triage as new, confirmed, or dismissed. A job that runs while Tor is down fails cleanly rather than hanging.

## Search sources

Five search engines, queried over Tor and deduplicated across engines:

- **ahmia** — Ahmia, routed through Tor
- **torch** — Torch onion (Ivory Search)
- **excavator** — Excavator onion
- **tor66** — Tor66 Deep Search
- **onionlive** — onion.live "Deep Search"

Admins enable, disable, or repoint any engine from the console. New engines are added as a plugin under `sources/`. Monitor sources (curated-source crawling) remain a plugin placeholder.

## Watch terms and matching

A workspace holds watch terms. Terms with a value drive the search queries; every enabled term is then matched against the title, snippet, and (budgeted) fetched page body of each result, and matches are recorded on the finding. Provenance and content matches are kept separate: a URL an engine returned for a query is not, by itself, evidence the term appears on the page.

Term types:

- **literal** — exact phrase, case-insensitive; sent to the engines quoted.
- **any** — each word in the term matched on its own word boundaries; use it to catch any of several keywords where `literal` wants the whole phrase intact. Sent to the engines unquoted for broad surfacing.
- **regex** — a regular expression.
- **domain, email, ipv4, ipv6, credential, card, btc, eth, hash** — entity extractors. With a value they match that value; left blank they extract every value of their type from results.

Credential and card matches are masked at rest by default (`CREDENTIAL_MASK=false` to unmask).

## Install

Requires Linux with Python 3.9+ and apt for the dependency step.

```
cd va-pt/darkweb-recon
python install.py
```

It checks for the tor binary and venv support, apt-installs `tor` and `python3-venv` with a single sudo prompt if either is missing, builds `.venv`, installs the Python requirements, and creates `data/` and `tordata/`. It refuses to run as root so the venv stays owned by you; only the apt step elevates. Tor runs as a managed process, launched and supervised by the app.

## Running

Create the first admin and start the console.

```
.venv/bin/python manage.py create-admin --username admin
.venv/bin/python run.py
```

The console listens on `0.0.0.0:8080`. Run an ephemeral manual search that does not persist:

```
.venv/bin/python search.py --term "acme corp" --engagement acme
```

Tor port note: installing the distro tor package starts a service on 9050 that collides with the managed instance. Free it with `sudo systemctl disable --now tor`, or set `TOR_SOCKS_PORT` / `TOR_CONTROL_PORT` to alternates.

## Diagnosing a source

`engine_probe.py` searches one or more engines in isolation over Tor and classifies each outcome — unreachable, reachable-but-empty, parser drift, or hits — so you can tell a dead onion apart from a zero-result query or a markup change. With the console up it attaches to the console's running Tor by default:

```
.venv/bin/python engine_probe.py --term "wiki" --engine tor66 --engine ahmia
```

Use `--tor-mode launch` to bring up its own Tor when the console is stopped, and `--connect-timeout` to give a slow onion more time before calling it dead.

## Console workflow

Admins manage users, workspaces, sources, terms, and schedules; operators are scoped to the workspaces they are assigned. Within a workspace you:

- add, toggle, and **edit** watch terms in place (change the type or value without deleting and re-adding),
- run a search on demand or on a schedule (hourly / daily / weekly / monthly, or a custom interval or cron),
- triage findings (confirm / dismiss / reset) and filter to matched-only,
- open a finding for its per-engine provenance, content matches, an on-demand same-onion analysis, and an inert HTML snapshot fetched server-side.

The danger zone offers **purge workspace** (delete all findings and their analyses while keeping terms and schedules) and **delete workspace**, each behind a confirmation prompt.

## Run as a service

Generate a systemd unit for this box and install it.

```
python install.py --service | sudo tee /etc/systemd/system/darkweb-recon.service
sudo systemctl daemon-reload
sudo systemctl enable --now darkweb-recon
```

The unit runs as your user, restarts on failure, and starts at boot. On stop it signals `run.py`, which tears down the scheduler, worker, and Tor. Watch it with `journalctl -u darkweb-recon -f`.

## Management CLI

```
.venv/bin/python manage.py create-admin --username admin
.venv/bin/python manage.py create-user --username analyst --role operator
.venv/bin/python manage.py list-users
.venv/bin/python manage.py create-workspace --name acme --client "Acme Corp"
.venv/bin/python manage.py assign --username analyst --workspace acme
```
