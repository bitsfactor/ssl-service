# ssl-server

A front proxy service that:

- listens on `80/443`
- routes traffic by domain
- manages HTTPS certificates automatically

## Install

One-command install on a fresh Linux server:

```bash
curl -fsSL https://raw.githubusercontent.com/leoleoaabbcc/ssl-server/main/scripts/install.sh | sudo bash
```

If you prefer to clone the repo first:

```bash
sudo bash scripts/setup.sh install
```

The installer will ask for:

- mode: `readonly` or `readwrite`
- PostgreSQL DSN
- ACME email for `readwrite`

Mode summary:

- `readonly`: reads routes and certificates from PostgreSQL, does not issue certificates
- `readwrite`: issues and renews certificates, then writes them back to PostgreSQL

After install, these commands are available:

- `ssl-proxy`
- `domain-manage`

## Add Your First Domain

First, update DNS:

- make sure the domain is hosted in Cloudflare DNS
- create or confirm a Cloudflare API token for the parent zone
- the domain does not need to point to this node before certificate issuance

Example: route `api.example.com` to local port `6111`

```bash
sudo domain-manage add api.example.com 6111 --sync-now
sudo domain-manage issue-now api.example.com
```

Route to another server:

```bash
sudo domain-manage add api.example.com 10.0.0.25:8080 --sync-now
sudo domain-manage issue-now api.example.com
```

Certificate only, no backend yet:

```bash
sudo domain-manage add api.example.com --sync-now
sudo domain-manage issue-now api.example.com
```

Optional pre-check:

```bash
domain-manage check api.example.com
domain-manage status api.example.com
```

## Check The Result

Check domain status:

```bash
domain-manage status api.example.com
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
domain-manage list
domain-manage get <domain>
domain-manage status <domain>
domain-manage check <domain>
domain-manage logs <domain>
sudo domain-manage add <domain> [target] --sync-now
sudo domain-manage set-target <domain> <target> --sync-now
sudo domain-manage clear-target <domain> --sync-now
sudo domain-manage issue-now <domain>
sudo domain-manage sync-now
```

## Notes

- wildcard certificates such as `*.example.com` are not supported
- supported upstream formats: `6111`, `127.0.0.1:6111`, `10.0.0.25:6111`, `backend.internal:6111`, `[2001:db8::10]:6111`
- config file: `/etc/ssl-proxy/config.yaml`
