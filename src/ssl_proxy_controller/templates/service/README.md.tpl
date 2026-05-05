# {{display_name}}

A small product service in the BitsFactor micro-product platform.

- Domain: https://{{domain}}
- Host port: `{{port}}` (mapped from container `$PORT`)
- Repo: {{repo_url}}

## Local dev

```bash
docker compose up --build
curl http://localhost:{{port}}/health
```

## Deploy

Push to `main`, then click **Deploy** in the ssl-service admin. Don't ssh
to the node and run things by hand — the platform owns the deploy.

## What goes where

- HTTP endpoints: `app/main.py`
- Business logic by topic: `app/<topic>.py`
- Tests: `tests/test_<topic>.py`
- Platform contract & AI agent rules: `CLAUDE.md` (also `AGENTS.md`)
