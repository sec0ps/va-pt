# darkweb-recon

Tor-based dark web reconnaissance for authorized OSINT and VAPT engagements. Runs manual searches from the CLI and scheduled or on-demand content searches from a multi-user web console. All fetching goes through a managed Tor instance with per-engagement stream isolation.

## Warning

This tool fetches hostile content from onion services. A container is packaging, not an isolation boundary. Run it inside a dedicated research VM or a segmented network. Do not run it on a host you care about.

## Components

The container runs one console daemon that starts Tor, a bounded worker pool, the APScheduler engine, and a waitress-served Flask console together. Tor bootstraps in the background so the console comes up immediately. A job that fires before Tor is ready fails cleanly rather than hanging.

- Search sources query Ahmia over Tor and return onion hits.
- Watch terms drive both the search queries and the match engine that scans returned titles and snippets.
- Findings are deduplicated per workspace on a content hash and carry a triage status of new, confirmed, or dismissed.
- Monitor sources are a plugin interface placeholder for curated source crawling and are not implemented yet.

## Match engine

Matching runs against Ahmia result titles and snippets only. Deep matching against fetched onion page bodies is tagged in the code and deferred to a later increment.

Watch term types are literal, regex, domain, email, ipv4, ipv6, credential, card, btc, eth, and hash. Entity types match a specific value when the term is set, or extract every value of that type when the term is left blank. Credential and card matches are masked at rest by default and can be unmasked with `CREDENTIAL_MASK=false`.

## Install

Requires a Linux host with Docker. From the repo:

```
cd va-pt/darkweb-recon
sudo bash install.sh
```

The installer installs Docker if missing, verifies the daemon, adds the invoking user to the docker group, and builds the image. Output is logged to `install.log`.

## First admin

Seed an admin on first boot with environment variables, then remove them:

```
CONSOLE_ADMIN_USER=admin CONSOLE_ADMIN_PASSWORD=change-me docker compose up -d
```

Or create one with the management CLI against the shared data volume:

```
docker compose run --rm recon manage.py create-admin --username admin
```

## Running the console

```
docker compose up -d
```

The console listens on `0.0.0.0:8080` by default. Admins manage users, workspaces, sources, watch terms, and schedules and see every workspace. Operators are scoped to the workspaces they are assigned to and can add terms, run jobs, and triage findings within those.

## Management CLI

```
docker compose run --rm recon manage.py create-admin --username admin
docker compose run --rm recon manage.py create-user --username analyst --role operator
docker compose run --rm recon manage.py list-users
docker compose run --rm recon manage.py create-workspace --name acme --client "Acme Corp"
docker compose run --rm recon manage.py assign --username analyst --workspace acme
```

## Manual search CLI

The manual search tool stays ephemeral and does not persist to the database. It shares the image entrypoint:

```
docker compose run --rm recon search.py --term "acme.com" --engagement acme
docker compose run --rm recon search.py -t "target one" -t "target two" --json
```

Persisted manual runs happen through the console run-now button on a workspace.

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
| DARKWEB_DATA_DIR | /app/data | Database and secret location |
| TOR_SOCKS_PORT | 9050 | Tor SOCKS port |
| TOR_CONTROL_PORT | 9051 | Tor control port |

## Data

The SQLite database and generated session secret live under the data volume. Tor state lives under the tordata volume. Both persist across restarts.
