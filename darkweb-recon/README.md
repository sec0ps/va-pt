# Darkweb Recon

Dedicated Tor-based reconnaissance service for authorized client engagements. This is increment 1, the manual search foundation. It launches a managed Tor process, fetches over SOCKS with hostile-content safeguards, and queries Ahmia for onion results.

## Install on the host

Unzip, then run the installer as root. It installs Docker if it is missing, verifies the daemon, and builds the image.

    cd darkweb-recon
    sudo bash install.sh

The installer needs the host to reach apt, pypi, and get.docker.com during setup. Progress is written to install.log.

## Build manually

    docker build -t darkweb-recon:latest .

## Run a manual search

    docker run --rm darkweb-recon:latest --term "acme corp breach" --engagement acme

Repeat --term for multiple queries in one Tor session.

    docker run --rm darkweb-recon:latest -t "acme creds" -t "acme dump" -e acme --json

## Persisting the Tor consensus

Use compose so the Tor data directory survives between runs and bootstrap is faster.

    docker compose build
    docker compose run --rm recon --term "acme corp" --engagement acme

## Configuration

All settings are environment variables read in config.py. Notable ones.

    AHMIA_BASE_URL      default https://ahmia.fi, set to the Ahmia onion to skip the exit hop
    FETCH_MAX_BYTES     hard response size cap, default 2 MiB
    TOR_BOOTSTRAP_TIMEOUT  seconds to wait for tor to bootstrap, default 180

## Safeguards in this build

Content-type allowlist limited to text and json. Hard response size cap. No redirect following. No raw media written to disk. Per-engagement SOCKS auth gives circuit isolation so separate engagements do not share Tor circuits.

## Not yet built

Persistence and the typed-entity match engine arrive in increment 2, alongside the bounded worker pool and the scheduler. The Flask operator console arrives in increment 3.
