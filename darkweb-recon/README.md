# darkweb-recon

Tor-based dark web reconnaissance for authorized OSINT and VAPT engagements. Runs manual searches from the CLI and scheduled or on-demand content searches from a multi-user web console. All fetching goes through a managed Tor instance with per-engagement stream isolation.

## Warning

This tool fetches hostile content from onion services. A container is packaging, not an isolation boundary. Run it inside a dedicated research VM or a segmented network. Do not run it on a host you care about. This holds whether you run under a venv or under Docker.

## Components

The service runs one console daemon that starts Tor, a bounded worker pool, the APScheduler engine, and a waitress-served Flask console together. Tor bootstraps in the background so the console comes up immediately. A job that fires before Tor is ready fails cleanly rather than hanging.

- Search sources query Ahmia over Tor and return onion hits.
- Watch terms drive both the search queries and the match engine that scans returned titles and snippets.
- Findings are deduplicated per workspace on a content hash and carry a triage status of new, confirmed, or dismissed.
- Monitor sources are a plugin interface placeholder for curated source crawling and are not implemented yet.

## Match engine

Matching runs against Ahmia result titles and snippets only. Deep matching against fetched onion page bodies is tagged in the code and deferred to a later increment.

Watch term types are literal, regex, domain, email, ipv4, ipv6, credential, card, btc, eth, and hash. Entity types match a specific value when the term is set, or extract every value of that type when the term is left blank. Credential and card matches are masked at rest by default and can be unmasked with `CREDENTIAL_MASK=false`.

## Two ways to run

Both models run the same code and rely on the VM for isolation. Pick by phase.

- Venv is the leaner loop for a single research box and for active development. Code edits run in place with no rebuild. Tor runs as a process on the host.
- Docker packages one frozen artifact with the same Tor, Python, and dependencies for every host. Use it when you freeze a build for the team or standardize across many hosts. Tor lives inside the image and the host stays clean.

Develop in the venv, package with Docker for release.

## Install with a venv

Requires a Linux host with Python 3.9 or newer, and apt for the automatic dependency step.

```
cd va-pt/darkweb-recon
python install.py
```

The installer checks for the tor binary and venv support, installs tor and python3-venv through apt with a single sudo prompt if either is missing, then builds `.venv`, installs the Python requirements, and creates `data/` and `tordata/` inside the project. It refuses to run as root so the venv stays owned by your user. Only the apt step elevates.

Create the first admin and start the console.

```
.venv/bin/python manage.py create-admin --username admin
.venv/bin/python run.py
```

The console listens on `0.0.0.0:8080`. Run an ephemeral manual search that does not persist.

```
.venv/bin/python search.py --term "acme corp" --engagement acme
```

Tor port note. Installing the distro tor package starts a system service on 9050 that collides with the managed instance the app launches. The installer warns if it sees this. Free the port with `sudo systemctl disable --now tor`, or run with alternate ports using `export TOR_SOCKS_PORT=9060 TOR_CONTROL_PORT=9061`.

## Install with Docker

Requires Docker on the host. Tor and all dependencies are built into the image.

```
cd va-pt/darkweb-recon
docker compose up -d
```

The image builds on first up, or build it directly with `docker build -t darkweb-recon:latest .`. Seed the first admin with environment variables on first boot, then remove them.

```
CONSOLE_ADMIN_USER=admin CONSOLE_ADMIN_PASSWORD=change-me docker compose up -d
```

Or create one against the shared data volume.

```
docker compose run --rm recon manage.py create-admin --username admin
```

Run an ephemeral manual search.

```
docker compose run --rm recon search.py --term "acme corp" --engagement acme
```

The console listens on `0.0.0.0:8080`. State persists in the recondata and tordata volumes.

## Roles and scoping

Admins manage users, workspaces, sources, watch terms, and schedules and see every workspace. Operators are scoped to the workspaces they are assigned to and can add terms, run jobs, and triage findings within those.

## Management CLI

The management commands run through manage.py. Under a venv prefix with `.venv/bin/python`, under Docker prefix with `docker compose run --rm recon`.

```
.venv/bin/python manage.py create-admin --username admin
.venv/bin/python manage.py create-user --username analyst --role operator
.venv/bin/python manage.py list-users
.venv/bin/python manage.py create-workspace --name acme --client "Acme Corp"
.venv/bin/python manage.py assign --username analyst --workspace acme
```

## Configuration

All settings are environment variables.

| Variable | Default | Purpose |
| --- | --- | --- |
| CONSOLE_BIND | 0.0.0.0:8080 | Console listen address |
| CONSOLE_SECRET | generated | Flask session secret, persisted under the data dir if unset |
| CONSOLE_ADMIN_USER | unset | Seed admin username on first boot |
| CONSOLE_ADMIN_PASSWORD | unset | Seed admin password on first boot |
| WORKER_POOL_SIZE | 4 | Concurrent jobs |
| JOB_TOR_WAIT | 180 | Seconds a job waits for Tor readiness before failing |
| AHMIA_BASE_URL | https://ahmia.fi | Ahmia endpoint, routed through Tor |
| CREDENTIAL_MASK | true | Mask credential and card matches at rest |
| SNIPPET_MAX_CHARS | 500 | Stored snippet cap |
| MATCH_VALUE_MAX_CHARS | 200 | Stored match value cap |
| MATCH_PER_TERM_CAP | 25 | Max matches kept per term per document |
| DARKWEB_DATA_DIR | beside the code | Database and secret location |
| TOR_DATA_DIR | beside the code | Tor state location |
| TOR_SOCKS_PORT | 9050 | Tor SOCKS port |
| TOR_CONTROL_PORT | 9051 | Tor control port |

The data and Tor directories default to `data/` and `tordata/` next to the code. Under a local venv that is the repo folder, and in the image the code sits at /app so they resolve to /app/data and /app/tordata. Set the variables to override either.

## Data

The SQLite database and generated session secret live under the data dir. Tor state lives under the tor data dir. Under Docker these are the recondata and tordata volumes. Both persist across restarts.
