# Service template

This directory is a reference layout. Copy it into a fresh repo to
make a project deployable by the **ssl-service admin platform**.

## What every deployable service needs

```
your-repo/
├── .deploy.yaml           ← contract with the platform (REQUIRED)
├── Dockerfile             ← how to build the container (REQUIRED)
├── docker-compose.yml     ← how to run it (REQUIRED)
├── .env.example           ← documents the env shape (recommended)
├── scripts/
│   ├── setup.sh           ← optional, for hand-deploys / debug
│   ├── pre_deploy.sh      ← optional escape hatch
│   └── post_deploy.sh     ← optional escape hatch
└── ... (your app code)
```

The platform clones the repo onto the target node, reads `.deploy.yaml`,
writes the effective `.env`, runs `docker compose up -d --build`, then
verifies the healthcheck. That's the whole flow.

## Adapting an existing repo

```bash
# 1. Drop these four files in:
cp examples/service-template/.deploy.yaml       <repo>/.deploy.yaml
cp examples/service-template/Dockerfile         <repo>/Dockerfile        # if you don't have one
cp examples/service-template/docker-compose.yml <repo>/docker-compose.yml
cp examples/service-template/.env.example       <repo>/.env.example

# 2. Edit .deploy.yaml — set service name, required_env, healthcheck,
#    exposed_ports. Everything else can stay default.

# 3. Make sure your Dockerfile builds and `docker compose up -d` runs
#    locally before you ask the platform to deploy it.

# 4. In the admin UI: Services → "+ Add service" → fill in the
#    GitHub URL. The platform will pull, parse .deploy.yaml, and
#    show a Deploy button.
```

## Why declarative + .env (not setup.sh)?

Because the platform does:

* **Validate** required env BEFORE shelling to the node
* **Preview** the rendered `.env` + compose to a human before deploying
* **Roll back** to the previous revision automatically if healthcheck
  fails (Compose makes this trivial; shell scripts don't)
* **Audit** — `.deploy.yaml` + .env diff is the source of truth

`scripts/pre_deploy.sh` and `scripts/post_deploy.sh` are still there as
escape hatches for one-off needs (DB migrations, cache warming, etc).
But they should be the exception, not the rule.

## Local hand-deploy (no platform)

```bash
git clone <repo> /opt/my-api
cd /opt/my-api
cp .env.example .env && $EDITOR .env
bash scripts/setup.sh
```

`scripts/setup.sh` mimics what the platform does: load `.env`, build,
up, wait for healthcheck. Useful for development / debugging on a
fresh box without touching the admin.
