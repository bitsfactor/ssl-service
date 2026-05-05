#!/usr/bin/env bash
# Post-deploy hook — runs on the target node after `docker compose up -d`
# and after the platform's healthcheck passes.
#
# Use this for things that depend on the container being live (cache
# preload, smoke check, sending a deploy notification). Empty stub by
# default.

set -euo pipefail

echo "post_deploy: nothing to do"
