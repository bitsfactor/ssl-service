# ssl-service

`ssl-service` is a Dockerized HTTPS front proxy for Linux hosts. It listens on `80/443`, reads route state from PostgreSQL, manages certificates with DNS-01 via Cloudflare, and exposes one operator entrypoint:

```bash
ssl-service
```

This README is the operator manual for production usage.

## What It Installs

Production install creates a managed runtime under:

- `/root/.ssl-service/config/config.yaml`
- `/root/.ssl-service/compose.yaml`
- `/root/.ssl-service/bin/setup.sh`
- `/root/.ssl-service/bin/domain-manage.sh`
- `/root/.ssl-service/state/`
- `/root/.ssl-service/logs/`
- `/root/.ssl-service/acme/`
- `/usr/local/bin/ssl-service`

The service itself runs as a Docker container named `ssl-service`.

## Install

Run as `root` on the target Linux machine:

```bash
curl -fsSL -o /tmp/setup.sh https://github.com/bitsfactor/ssl-service/raw/main/scripts/setup.sh
bash /tmp/setup.sh
```

If the machine is already installed, running a fresh `setup.sh` again updates the managed runtime.

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

The interactive menu is the preferred operator path. All domain operations also live under the same entrypoint.

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
- they are normalized to `host.docker.internal:port` for the containerized Caddy runtime

This matters because the proxy runs inside Docker. Container loopback is not the host loopback.

## Data Layout

State is stored under `/root/.ssl-service`:

- `config/config.yaml`: runtime config
- `compose.yaml`: generated Docker Compose file
- `state/generated/Caddyfile`: live generated Caddy config
- `state/certs/`: local certificate material mirrored from the database
- `state/state/state.json`: runtime state checksum data
- `acme/`: Certbot ACME working state
- `logs/`: controller and Caddy file logs

## Logs

There are now three log paths to know about.

Application logs in our managed directory:

- `/root/.ssl-service/logs/controller.log`
- `/root/.ssl-service/logs/caddy.log`

Docker fallback logs:

- `/var/lib/docker/containers/<container-id>/<container-id>-json.log`

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

1. refreshes the managed `setup.sh`
2. re-execs into the newest managed script
3. validates database connectivity and schema assumptions
4. pulls the latest image
5. rewrites generated runtime files
6. recreates the container

If you are upgrading a machine from an older installer generation, running a fresh external `setup.sh` is also valid:

```bash
curl -fsSL -o /tmp/setup.sh https://github.com/bitsfactor/ssl-service/raw/main/scripts/setup.sh
bash /tmp/setup.sh update
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
cat /root/.ssl-service/config/config.yaml
cat /root/.ssl-service/state/generated/Caddyfile
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

Production config file:

- `/root/.ssl-service/config/config.yaml`

Key defaults written by the installer:

- poll interval: `30s`
- renew before expiry: `30 days`
- certificate retry backoff after failure: `3600s`
- controller log file: `/app/logs/controller.log`
- Caddy log file: `/app/logs/caddy.log`

In `readwrite` mode, `install`, `reconfigure`, and `update` will create or migrate the required PostgreSQL schema objects.

## Failure Model

When PostgreSQL is temporarily unavailable after startup:

- existing local certificates under `/root/.ssl-service/state/certs/` can continue serving TLS
- the last generated Caddyfile can usually continue routing current traffic
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
