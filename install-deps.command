#!/usr/bin/env bash
# Install / refresh runtime Python deps into the local .venv.
#
# Run this once after a `git pull` that adds a new dep to
# pyproject.toml or requirements.txt — e.g. PySocks for the static-IP
# speed-test bandwidth measurement. Idempotent; running it again is
# a no-op when everything is already installed.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
REPO_DIR="$(pwd)"
VENV_DIR="${REPO_DIR}/.venv"

export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH:-/usr/bin:/bin}"

echo "================================================================"
echo "  ssl-service — install / refresh deps"
echo "================================================================"
echo

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "ERROR: ${VENV_DIR} not found. Run \`scripts/setup-dev.sh bootstrap\` first."
  echo "Press any key to close..."
  read -n 1 -s
  exit 1
fi

echo "Using venv: ${VENV_DIR}"
echo
"${VENV_DIR}/bin/pip" install -e "${REPO_DIR}" --upgrade
EXIT=$?

echo
if [[ $EXIT -eq 0 ]]; then
  echo "Done. Restart the admin (Settings → Restart admin, or re-run start.command)"
  echo "to pick up the new packages."
else
  echo "pip install failed with exit code ${EXIT}."
fi

echo
echo "Press any key to close..."
read -n 1 -s
