#!/usr/bin/env bash
# ssl-service container entrypoint.
#
# Environment-driven: the controller reads SSL_SERVICE_* env vars
# directly (see ssl_proxy_controller.config.load_config_from_env), so
# we don't need a config.yaml file. Caddy's bootstrap Caddyfile is
# tiny and identical for every deploy, so we just write it inline.
set -euo pipefail

STATE_DIR="${SSL_SERVICE_STATE_DIR:-/app/state}"
LOG_DIR="${SSL_SERVICE_LOG_DIR:-/app/logs}"
GENERATED_DIR="${STATE_DIR}/generated"
RUNTIME_STATE_DIR="${STATE_DIR}/state"
CERTS_DIR="${STATE_DIR}/certs"
CADDYFILE_PATH="${GENERATED_DIR}/Caddyfile"

mkdir -p "${GENERATED_DIR}" "${RUNTIME_STATE_DIR}" "${CERTS_DIR}" "${LOG_DIR}"

if [[ ! -f "${CADDYFILE_PATH}" ]]; then
  cat > "${CADDYFILE_PATH}" <<'EOF'
{
  admin 127.0.0.1:2019
}
EOF
fi

/usr/bin/caddy run --environ --config "${CADDYFILE_PATH}" --adapter caddyfile &
CADDY_PID=$!
# No --config: controller falls through to load_config_from_env(),
# reading SSL_SERVICE_* directly from the env passed in by compose.
python -m ssl_proxy_controller &
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
