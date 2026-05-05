#!/usr/bin/env bash
# Pre-deploy hook — runs on the target node before `docker compose up -d`.
# stdout/stderr are captured into the deployment log.
#
# Use this for one-shot tasks that must complete before the container
# starts (DB migrations, schema setup, cache warmup). Empty stub by
# default so the deploy succeeds for new services with no migrations yet.

set -euo pipefail

echo "pre_deploy: nothing to do"
