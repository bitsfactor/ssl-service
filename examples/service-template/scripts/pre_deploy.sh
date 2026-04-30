#!/usr/bin/env bash
# Optional escape hatch — runs on the target node BEFORE
# `docker compose up -d --build`. Working directory is the install
# directory (e.g. /opt/<service>). The platform-rendered .env is
# already in place and sourced into the environment.
#
# 99% of services don't need this. Common legitimate uses:
#   * pull a sibling repo this service depends on
#   * download a binary that doesn't fit in git
#   * run a one-shot DB migration via a sidecar container
#
# Don't use this for env / config — put those in .deploy.yaml so the
# platform can preview and validate them.

set -euo pipefail

echo "pre_deploy: nothing to do"
