#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="/app/config/config.yaml"
STATE_DIR="/app/state"
LOG_DIR="/app/logs"
GENERATED_DIR="${STATE_DIR}/generated"
RUNTIME_STATE_DIR="${STATE_DIR}/state"
CERTS_DIR="${STATE_DIR}/certs"
CADDYFILE_PATH="${GENERATED_DIR}/Caddyfile"

mkdir -p "${GENERATED_DIR}" "${RUNTIME_STATE_DIR}" "${CERTS_DIR}" "${LOG_DIR}"

if [[ ! -f "${CONFIG_PATH}" ]]; then
  printf 'ERROR: config not found: %s\n' "${CONFIG_PATH}" >&2
  exit 1
fi

if [[ ! -f "${CADDYFILE_PATH}" ]]; then
  cat > "${CADDYFILE_PATH}" <<'EOF'
{
  admin 127.0.0.1:2019
}
EOF
fi

/usr/bin/caddy run --environ --config "${CADDYFILE_PATH}" --adapter caddyfile &
CADDY_PID=$!
python -m ssl_proxy_controller --config "${CONFIG_PATH}" &
CONTROLLER_PID=$!

cleanup() {
  for pid in "${CONTROLLER_PID}" "${CADDY_PID}"; do
    if kill -0 "${pid}" >/dev/null 2>&1; then
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
    fi
  done
}

trap cleanup EXIT INT TERM

wait -n "${CADDY_PID}" "${CONTROLLER_PID}"
exit $?
