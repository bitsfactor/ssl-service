#!/usr/bin/env bash
# Optional escape hatch — runs on the target node AFTER
# `docker compose up -d --build` AND the healthcheck passed. Working
# directory is the install directory.
#
# Common legitimate uses:
#   * register the service with an external service registry
#   * send a deploy notification (Slack, etc.)
#   * warm caches, run smoke tests

set -euo pipefail

echo "post_deploy: nothing to do"
