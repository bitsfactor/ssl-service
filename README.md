# ssl-server

Caddy-based front proxy with two operating modes:

- `readonly`: reads certificates and routes from PostgreSQL, caches them locally, and reloads Caddy on change.
- `readwrite`: does everything from `readonly` and also issues or renews certificates with `certbot` HTTP-01, then writes them back to PostgreSQL.

## Components

- `Caddy`: listens on `80` and `443`, serves ACME challenge files, terminates TLS, and reverse-proxies by hostname.
- `ssl-proxy-controller`: sync daemon that talks to PostgreSQL, manages local certificate cache, renders the Caddyfile, reloads Caddy, and optionally runs renewals.

## Repository Layout

- `src/ssl_proxy_controller/`: controller implementation
- `config.example.yaml`: node configuration
- `sql/schema.sql`: PostgreSQL schema
- `scripts/domain-manage.sh`: domain and upstream target management helper
- `systemd/`: service templates
- `setup.sh`: full install and operations script

## Quick Start

1. Run the installer:

```bash
sudo bash setup.sh install
```

2. During install:

- choose `readonly` or `readwrite`
- enter the PostgreSQL DSN
- in `readwrite` mode, enter the ACME email
- the installer validates the DSN before writing config
- in `readonly` mode, the installer does not try to create schema objects; the database must already be initialized by a write-capable install

3. The installer initializes the schema automatically and enables the systemd services and timer.

4. Manage domains:

```bash
bash scripts/domain-manage.sh add a.com 6111 --sync-now
bash scripts/domain-manage.sh set-target a.com 10.0.0.25:6111 --sync-now
bash scripts/domain-manage.sh set-target api.example.com backend.internal:8443 --sync-now
bash scripts/domain-manage.sh add cert-only.example.com --sync-now
bash scripts/domain-manage.sh list
bash scripts/domain-manage.sh status a.com
bash scripts/domain-manage.sh check a.com
bash scripts/domain-manage.sh issue-now a.com
```

## Runtime

The controller keeps these paths updated:

- `/var/lib/ssl-proxy/certs/<domain>/fullchain.pem`
- `/var/lib/ssl-proxy/certs/<domain>/privkey.pem`
- `/var/lib/ssl-proxy/generated/Caddyfile`
- `/var/lib/ssl-proxy/state/state.json`

In `readwrite` mode, `certbot` writes challenge files under `/var/lib/ssl-proxy/acme-webroot`.

## Database Contract

`routes` is the authority for reverse proxy rules. Each enabled row maps a hostname to an upstream target.

`certificates` stores PEM material and metadata. Read-only nodes consume it. Read-write nodes update it after issuance or renewal.

`routes.upstream_target` can be `NULL`. In that case the domain is kept only for certificate issuance and renewal, and HTTPS requests will receive a static response instead of being proxied.

`routes.upstream_target` accepts either a plain port like `6111` or a full target like `127.0.0.1:6111`, `10.0.0.25:6111`, or `backend.internal:6111`. Plain ports are normalized to `127.0.0.1:<port>`.
IPv6 targets must use bracket form, for example `[2001:db8::10]:6111`.

The current implementation uses `HTTP-01`, so wildcard domains such as `*.example.com` are not supported.

## Notes

- The current implementation uses a rendered `Caddyfile` plus `caddy reload --adapter caddyfile`, which keeps the deployment simple while still allowing hot reloads.
- Multi-writer renewal coordination uses PostgreSQL advisory locks keyed by domain.
- The operations entrypoint supports `install`, `start`, `stop`, `restart`, `status`, `logs`, `update`, `timer-status`, and `uninstall`.
- The installed host also gets `/usr/local/bin/domain-manage` for route maintenance.
- `domain-manage.sh check <domain>` is a pre-issuance health check for DNS and HTTP-01 reachability. It can run on any node, but it reports `check_node_mode: fail` on `readonly` nodes because issuance is not available there.
- `domain-manage.sh issue-now <domain>` is only available on `readwrite` nodes.
- `points_to_this_host: unknown` means the node could not confidently determine a public self-IP, so DNS direction could not be conclusively verified.
