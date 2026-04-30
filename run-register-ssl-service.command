#!/usr/bin/env bash
# One-shot: register ssl-service in the running admin + sync manifest.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
ADMIN_TOKEN=dev-token bash scripts/register-ssl-service.sh
echo
echo "Press any key to close..."
sleep 4
