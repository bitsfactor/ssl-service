# ssl-service

A Dockerized front proxy service that:

- listens on `80/443`
- routes traffic by domain
- manages HTTPS certificates automatically

## Production Install

Run the standalone installer as `root` after downloading `setup.sh` to the current directory:

```bash
bash ./setup.sh
```

Or download only the installer:

```bash
curl -fsSL -o setup.sh https://github.com/bitsfactor/ssl-service/raw/main/scripts/setup.sh && bash setup.sh
```

If the machine is already installed, rerunning a freshly downloaded `setup.sh` will update the local runtime automatically.

Production behavior:

- installs runtime files under `/root/.ssl-service`
- installs Docker automatically if missing
- runs the service with `docker compose`
- adds one shell shortcut in `/root/.bashrc`: `ssl-service`
- does not require cloning the repository on the target server

The first screen detects current state and lets you choose:

- install or overwrite runtime
- change database or mode
- show status
- view logs
- restart
- update
- uninstall

`readonly` does not ask for ACME email and uses `domain@bitsfactor.com`.

## Production Runtime Layout

Main files after install:

- `/root/.ssl-service/config/config.yaml`
- `/root/.ssl-service/compose.yaml`
- `/root/.ssl-service/acme/`
- `/root/.ssl-service/state/`
- `/root/.ssl-service/state/certs/`
- `/root/.ssl-service/state/generated/Caddyfile`
- `/root/.ssl-service/logs/`
- `/root/.ssl-service/bin/setup.sh`
- `/root/.ssl-service/bin/domain-manage.sh`

## Production Commands

After opening a new shell or running `source /root/.bashrc`:

```bash
ssl-service
ssl-service start
ssl-service stop
ssl-service reconfigure
ssl-service status
ssl-service logs
ssl-service restart
ssl-service update
ssl-service uninstall --yes
```

Domain management stays under the single global entrypoint:

```bash
ssl-service domain list
ssl-service domain status api.example.com
ssl-service domain add api.example.com 6111 --sync-now
ssl-service domain issue-now api.example.com
```

## Development Mode

Development is separate from production install. Use `setup-dev.sh` only inside the source tree:

```bash
bash scripts/setup-dev.sh bootstrap
bash scripts/setup-dev.sh test
bash scripts/setup-dev.sh run-once --config config.yaml
```

## Notes

- wildcard certificates such as `*.example.com` are not supported
- supported upstream formats: `6111`, `127.0.0.1:6111`, `10.0.0.25:6111`, `backend.internal:6111`, `[2001:db8::10]:6111`
- production config file: `/root/.ssl-service/config/config.yaml`
- in `readwrite` mode, `install`, `reconfigure`, and `update` will create or migrate the service schema objects in the target PostgreSQL schema
- `ssl-service domain delete <domain>` deletes that domain from `routes`
- `ssl-service domain purge <domain>` deletes that domain from both `routes` and `certificates`
- local certificate cache is stored under `/root/.ssl-service/state/certs/`
- Certbot ACME state is stored under `/root/.ssl-service/acme/`
- if the database becomes temporarily unavailable after startup, existing locally cached certificates and the last generated Caddy config can usually keep current HTTPS traffic running
- if the database is unavailable, new route sync, certificate renewal, and first-time bootstrap will be affected
