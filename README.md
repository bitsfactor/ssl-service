# ssl-server

A front proxy service that:

- listens on `80/443`
- routes traffic by domain
- manages HTTPS certificates automatically

## Install

One-command install on a fresh Linux server:

```bash
git clone git@github.com:leoleoaabbcc/ssl-server.git && cd ssl-server && bash scripts/setup.sh install
```

If you prefer to clone the repo first:

```bash
bash scripts/setup.sh install
```

The installer will ask for:

- mode: `readonly` or `readwrite`
- PostgreSQL DSN
- ACME email for `readwrite`

If you are already logged in as `root`, do not prepend `sudo`.
Interactive menus use Up/Down arrows and Enter.

For `readonly`, the installer does not prompt for ACME email and uses `domain@bitsfactor.com`.

Mode summary:

- `readonly`: reads routes and certificates from PostgreSQL, does not issue certificates
- `readwrite`: issues and renews certificates, then writes them back to PostgreSQL

After install, these commands are available:

- `ssl-proxy`

## Add Your First Domain

First, update DNS:

- make sure the domain is hosted in Cloudflare DNS
- create or confirm a Cloudflare API token for the parent zone
- the domain does not need to point to this node before certificate issuance

Example: route `api.example.com` to local port `6111`

```bash
sudo ssl-proxy domain add api.example.com 6111 --sync-now
sudo ssl-proxy domain issue-now api.example.com
```

Route to another server:

```bash
sudo ssl-proxy domain add api.example.com 10.0.0.25:8080 --sync-now
sudo ssl-proxy domain issue-now api.example.com
```

Certificate only, no backend yet:

```bash
sudo ssl-proxy domain add api.example.com --sync-now
sudo ssl-proxy domain issue-now api.example.com
```

Optional pre-check:

```bash
ssl-proxy domain check api.example.com
ssl-proxy domain status api.example.com
```

## Check The Result

Check domain status:

```bash
ssl-proxy domain status api.example.com
```

Check service status:

```bash
sudo ssl-proxy status
```

Test HTTPS:

```bash
curl -I https://api.example.com
```

## Common Commands

Service management:

```bash
sudo ssl-proxy start
sudo ssl-proxy stop
sudo ssl-proxy restart
sudo ssl-proxy status
sudo ssl-proxy logs
sudo ssl-proxy update
sudo ssl-proxy uninstall
```

Domain management:

```bash
ssl-proxy domain list
ssl-proxy domain get <domain>
ssl-proxy domain status <domain>
ssl-proxy domain check <domain>
ssl-proxy domain logs <domain>
sudo ssl-proxy domain add <domain> [target] --sync-now
sudo ssl-proxy domain set-target <domain> <target> --sync-now
sudo ssl-proxy domain clear-target <domain> --sync-now
sudo ssl-proxy domain issue-now <domain>
sudo ssl-proxy domain sync-now
```

## Notes

- wildcard certificates such as `*.example.com` are not supported
- supported upstream formats: `6111`, `127.0.0.1:6111`, `10.0.0.25:6111`, `backend.internal:6111`, `[2001:db8::10]:6111`
- config file: `/etc/ssl-proxy/config.yaml`
