# ssl-service

`ssl-service` is a Dockerized HTTPS front proxy for Linux hosts. It listens on `80/443`, reads route state from PostgreSQL, manages certificates with DNS-01 via Cloudflare, and exposes one operator entrypoint:

```bash
ssl-service
```

This README is the operator manual for production usage.

## What It Installs

Production install creates these top-level locations:

- `/root/.ssl-service/`: managed runtime root
- `/root/.ssl-service/config/`
- `/root/.ssl-service/state/`
- `/root/.ssl-service/logs/`
- `/root/.ssl-service/acme/`
- `/root/.ssl-service/env/`
- `/root/.ssl-service/meta/`
- `/root/.ssl-service/.tools-venv/`
- `/root/ssl-service/`: local source checkout
- `/root/ssl-service/scripts/`: core operator scripts
- `/usr/local/bin/ssl-service` -> `/root/ssl-service/scripts/setup.sh`

The service itself runs as a Docker container named `ssl-service`.

## Install

Run as `root` on the target Linux machine:

```bash
curl -fsSL -o /tmp/ssl-service-install.sh https://github.com/bitsfactor/ssl-service/raw/main/scripts/install.sh
bash /tmp/ssl-service-install.sh
```

The bootstrap installer ensures there is a local source checkout at `/root/ssl-service`, then runs the local `scripts/setup.sh`.

If the machine already has a clean checkout at `/root/ssl-service`, re-running `install.sh` updates that checkout first and then runs the local `scripts/setup.sh`.

If the checkout has local uncommitted changes, `install.sh` leaves the source tree as-is and continues with the current local code.

You can also install directly from an existing local checkout:

```bash
bash /root/ssl-service/scripts/setup.sh
```

You can also explicitly update with:

```bash
ssl-service update
```

## Install Modes

The runtime supports two modes:

- `readonly`: reads routes and certificates from PostgreSQL, does not issue certificates, uses default ACME email `domain@bitsfactor.com`
- `readwrite`: reads routes from PostgreSQL, issues and renews certificates, writes certificate state back to PostgreSQL

Use `readwrite` on the node that should actually manage certificates. Use `readonly` on follower nodes.

## First-Time Inputs

During install or reconfigure, `ssl-service` asks for:

- node mode: `readonly` or `readwrite`
- PostgreSQL DSN
- ACME email in `readwrite` mode

The installer validates database connectivity before continuing.

## Daily Commands

Main runtime commands:

```bash
ssl-service
ssl-service status
ssl-service logs
ssl-service restart
ssl-service update
ssl-service reconfigure
ssl-service uninstall --yes
```

Runtime helpers:

```bash
ssl-service start
ssl-service stop
```

The interactive menu is the preferred operator path. The global `ssl-service` command is a symlink to the source-tree `scripts/setup.sh`, so local script edits take effect immediately. All domain operations also live under the same entrypoint.

## Domain Management

Everything domain-related is under `ssl-service domain ...`.

Examples:

```bash
ssl-service domain list
ssl-service domain list-certs
ssl-service domain list-zones
ssl-service domain status api.example.com
ssl-service domain get api.example.com
ssl-service domain add api.example.com 6111 --sync-now
ssl-service domain set-target api.example.com 10.0.0.25:6111 --sync-now
ssl-service domain enable api.example.com --sync-now
ssl-service domain disable api.example.com --sync-now
ssl-service domain issue-now api.example.com
ssl-service domain set-zone-token example.com
ssl-service domain sync-now
```

Important behavior:

- `ssl-service domain add <domain>` can omit the upstream, which creates a certificate-only route
- `ssl-service domain delete <domain>` removes the row from `routes`
- `ssl-service domain purge <domain>` removes the row from both `routes` and `certificates`
- wildcard domains such as `*.example.com` are not supported

## Upstream Target Rules

Supported upstream formats:

- `6111`
- `127.0.0.1:6111`
- `localhost:6111`
- `10.0.0.25:6111`
- `backend.internal:6111`
- `[2001:db8::10]:6111`

Important networking rule:

- plain ports, `127.0.0.1:port`, and `localhost:port` are treated as services running on the Docker host
- they remain stored as loopback-style targets in the database
- the controller rewrites them to `host.docker.internal:port` only when rendering the containerized Caddy runtime

This matters because the proxy runs inside Docker. Container loopback is not the host loopback.

## Data Layout

State is stored under `/root/.ssl-service`:

- `config/`: runtime configuration
- `state/`: generated config, certificates, and runtime state
- `logs/`: controller and Caddy logs
- `acme/`: Certbot ACME working state
- `env/`: runtime environment files
- `meta/`: install metadata
- `.tools-venv/`: local helper Python environment

## Logs

Primary logs live under:

- `/root/.ssl-service/logs/`

Docker also keeps container stdout/stderr logs in its own storage.

`ssl-service logs` streams the container logs:

```bash
ssl-service logs
```

### Log Size Limits

Log growth is controlled in two layers.

Application file logs:

- controller log: `5 MiB` per file, `8` backups
- Caddy log: `5 MiB` per file, `8` backups

Docker stdout/stderr fallback logs:

- `max-size: 5m`
- `max-file: 2`

This keeps the managed logs under roughly `90 MiB`, with Docker fallback logs around `10 MiB`.

## How Updates Work

Use:

```bash
ssl-service update
```

Update does the following:

1. validates database connectivity and schema assumptions
2. pulls the latest image
3. refreshes the global `ssl-service` symlink to the current source checkout
4. rewrites generated runtime files
5. recreates the container

`ssl-service update` does not pull Git changes for the source checkout. If you want updated command logic from the repository, update `/root/ssl-service` with `git pull` first.

If you are upgrading a machine from an older installer generation, rerun the bootstrap installer:

```bash
curl -fsSL -o /tmp/ssl-service-install.sh https://github.com/bitsfactor/ssl-service/raw/main/scripts/install.sh
bash /tmp/ssl-service-install.sh update
```

## Runtime Status Checks

Useful status commands:

```bash
ssl-service status
ssl-service domain status api.example.com
ssl-service domain check api.example.com
```

Useful file inspections:

```bash
ls -lah /root/.ssl-service/config
ls -lah /root/.ssl-service/state
ls -lah /root/.ssl-service/logs
```

Container checks:

```bash
docker ps --filter name=ssl-service
docker exec ssl-service getent hosts host.docker.internal
docker exec ssl-service sh -lc 'nc -vz host.docker.internal 6111'
```

## Build Status

To check the GitHub image build state from a managed machine:

```bash
ssl-service build-status
```

This queries the repository workflow configured for image publishing.

## Configuration Notes

Production runtime config lives under:

- `/root/.ssl-service/config/`

Key defaults written by the installer:

- poll interval: `30s`
- renew before expiry: `30 days`
- certificate retry backoff after failure: `3600s`
- logs are written under `/root/.ssl-service/logs/`

In `readwrite` mode, `install`, `reconfigure`, and `update` will create or migrate the required PostgreSQL schema objects.

## Failure Model

When PostgreSQL is temporarily unavailable after startup:

- existing local runtime state under `/root/.ssl-service/state/` can usually continue serving current traffic
- new route sync, new certificate issuance, and renewals are affected until the database returns

When upstream reachability fails:

- first verify the domain's `upstream_target`
- then verify the target from inside the container, not only from the host
- if the upstream is host-local, use a plain port or `localhost:port` via `ssl-service domain`, not a hardcoded container loopback assumption

## Development

Development helpers are separate from production install and should only be used inside the source tree:

```bash
bash scripts/setup-dev.sh bootstrap
bash scripts/setup-dev.sh test
bash scripts/setup-dev.sh run-once --config config.yaml
bash scripts/setup-dev.sh domain list
```
