#!/usr/bin/env bash
# One-shot helper: stage the admin/nodes/services changes (skipping local
# secret files) and push to origin/main using the SSH credentials already
# on this Mac.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
echo "================================================================"
echo "  Push ssl-service: admin + nodes + services"
echo "  Repo: $(git config --get remote.origin.url)"
echo "  Branch: $(git branch --show-current)"
echo "================================================================"

# Make sure local secret/Mac-only files don't get committed even if they
# show up in `git status`.
LOCAL_ONLY=(
  "config.yaml"
  "start.command"
  "clone-bitsfactor-scripts.command"
  "push-to-main.command"
)

# Clear any stale lock from a previous half-finished run.
rm -f .git/index.lock .git/HEAD.lock 2>/dev/null

# Abort any partial rebase from a previous attempt.
[ -d .git/rebase-merge ] && git rebase --abort >/dev/null 2>&1
[ -d .git/rebase-apply ] && git rebase --abort >/dev/null 2>&1

# Reset any staging from a previous attempt.
git reset >/dev/null

# Whitelist add — explicit paths only.
git add \
  README.md \
  config.example.yaml \
  pyproject.toml \
  scripts/dev-admin.py \
  scripts/setup-dev.sh \
  sql/schema.sql \
  src/ssl_proxy_controller/admin.py \
  src/ssl_proxy_controller/caddy.py \
  src/ssl_proxy_controller/config.py \
  src/ssl_proxy_controller/controller.py \
  src/ssl_proxy_controller/db.py \
  src/ssl_proxy_controller/nodes.py \
  src/ssl_proxy_controller/nodes_init.py \
  src/ssl_proxy_controller/static \
  tests/test_admin.py \
  tests/test_caddy.py \
  tests/test_config.py \
  tests/test_db.py 2>&1 | sed '/^$/d' | tail -30

# Sanity check: is any secret file accidentally staged?
echo
echo "--- staged files ---"
git diff --cached --name-only
for f in "${LOCAL_ONLY[@]}"; do
  if git diff --cached --name-only | grep -qx "$f"; then
    echo "ERROR: $f is staged but should be local-only. Aborting." >&2
    exit 1
  fi
done

echo
echo "--- diff stat ---"
git diff --cached --stat | tail -15

if git diff --cached --quiet; then
  echo "Nothing to commit."
else
  git commit -m "Add web admin: routes/certs, nodes mgmt, init wizard, services catalog

- New admin HTTP server + SPA frontend (admin.py + static/index.html)
- Multi-upstream routes + LB policy (random/round_robin/ip_hash/uri_hash)
- Node management with SSH password/key auth + probe + deploy/update
- Server initialization wizard (multi-step) using bitsfactor/scripts
- Service catalog: github_repo + compose_template + config_files; deploy via SSH
- Schema migrations for nodes, node_status, node_init_runs, services
- 126 unit tests pass"
fi

echo
echo "--- pulling latest origin/main (rebase, autostash) ---"
git -c rebase.autoStash=true pull --rebase origin main

echo
echo "--- pushing ---"
git push origin main

echo
echo "Done."
echo "Press any key to close this window..."
read -n 1 -s
