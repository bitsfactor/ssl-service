#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ssl-proxy"
CONFIG_DIR="/etc/ssl-proxy"
CONFIG_PATH="${CONFIG_DIR}/config.yaml"
STATE_DIR="/var/lib/ssl-proxy"
LOG_DIR="/var/log/ssl-proxy"
VENV_DIR="${INSTALL_DIR}/.venv"
SYSTEMD_DIR="/etc/systemd/system"
TIMER_NAME="ssl-proxy-update.timer"
SERVICE_NAME="ssl-proxy-controller.service"
CADDY_SERVICE_NAME="caddy.service"
UPDATE_SERVICE_NAME="ssl-proxy-update.service"
UPDATE_SCHEDULE="*-*-* 04:00:00"
UPDATE_LOG="${STATE_DIR}/update.log"
DEFAULT_DSN=""
SOURCE_DIR_FILE="${INSTALL_DIR}/.source_dir"

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "run this script as root"
}

require_systemd() {
  command -v systemctl >/dev/null 2>&1 || fail "systemctl is required"
  systemctl --version >/dev/null 2>&1 || fail "systemctl is not usable on this host"
}

ensure_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y curl python3 python3-venv python3-pip rsync caddy certbot
}

ensure_layout() {
  mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}"
  mkdir -p "${STATE_DIR}/generated" "${STATE_DIR}/state" "${STATE_DIR}/certs" "${STATE_DIR}/acme-webroot"
  touch "${UPDATE_LOG}"
}

sync_repo() {
  local source_dir
  source_dir="$(resolve_source_dir)"
  rsync -a --delete \
    --exclude '.git' \
    --exclude '.codex' \
    --exclude '__pycache__' \
    --exclude '.venv' \
    "${source_dir}/" "${INSTALL_DIR}/"
}

ensure_venv() {
  local source_dir
  source_dir="$(resolve_source_dir)"
  if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${VENV_DIR}"
  fi
  "${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${VENV_DIR}/bin/pip" install "${source_dir}" >/dev/null
}

seed_bootstrap_caddyfile() {
  if [[ ! -f "${STATE_DIR}/generated/Caddyfile" ]]; then
    cat > "${STATE_DIR}/generated/Caddyfile" <<'EOF'
{
  admin 127.0.0.1:2019
}
EOF
  fi
}

port_in_use() {
  local port="$1"
  ss -ltn "( sport = :${port} )" | tail -n +2 | grep -q .
}

check_bind_ports() {
  local caddy_active
  caddy_active="$(systemctl is-active "${CADDY_SERVICE_NAME}" 2>/dev/null || true)"
  for port in 80 443; do
    if port_in_use "${port}" && [[ "${caddy_active}" != "active" ]]; then
      fail "port ${port} is already in use"
    fi
  done
}

prompt_with_default() {
  local prompt="$1"
  local default_value="$2"
  local value
  read -r -p "${prompt} [${default_value}]: " value
  if [[ -z "${value}" ]]; then
    value="${default_value}"
  fi
  printf '%s' "${value}"
}

resolve_source_dir() {
  if [[ -f "${SCRIPT_DIR}/pyproject.toml" ]]; then
    printf '%s' "${SCRIPT_DIR}"
    return 0
  fi
  if [[ -f "${SOURCE_DIR_FILE}" ]]; then
    local recorded_source_dir
    recorded_source_dir="$(cat "${SOURCE_DIR_FILE}")"
    if [[ -f "${recorded_source_dir}/pyproject.toml" ]]; then
      printf '%s' "${recorded_source_dir}"
      return 0
    fi
  fi
  if [[ -f "${INSTALL_DIR}/pyproject.toml" ]]; then
    printf '%s' "${INSTALL_DIR}"
    return 0
  fi
  fail "could not determine source directory"
}

record_source_dir() {
  local source_dir
  source_dir="$(resolve_source_dir)"
  printf '%s\n' "${source_dir}" > "${SOURCE_DIR_FILE}"
}

prompt_required() {
  local prompt="$1"
  local value
  while true; do
    read -r -p "${prompt}: " value
    if [[ -n "${value}" ]]; then
      printf '%s' "${value}"
      return 0
    fi
    log "value is required"
  done
}

select_mode() {
  local value
  while true; do
    read -r -p "Select mode (readonly/readwrite) [readonly]: " value
    value="${value:-readonly}"
    case "${value}" in
      readonly|readwrite)
        printf '%s' "${value}"
        return 0
        ;;
      *)
        log "mode must be readonly or readwrite"
        ;;
    esac
  done
}

validate_dsn() {
  local dsn="$1"
  SSL_PROXY_TEST_DSN="${dsn}" "${VENV_DIR}/bin/python" - <<'PY'
import os
import psycopg

dsn = os.environ["SSL_PROXY_TEST_DSN"]
with psycopg.connect(dsn, connect_timeout=10, sslmode="require") as conn:
  with conn.cursor() as cur:
    cur.execute("SELECT current_database(), current_user")
    row = cur.fetchone()
print(f"database={row[0]} user={row[1]}")
PY
}

validate_readonly_schema() {
  local dsn="$1"
  SSL_PROXY_TEST_DSN="${dsn}" "${VENV_DIR}/bin/python" - <<'PY'
import os
import psycopg

dsn = os.environ["SSL_PROXY_TEST_DSN"]
with psycopg.connect(dsn, connect_timeout=10, sslmode="require") as conn:
  with conn.cursor() as cur:
    cur.execute("SELECT 1 FROM routes LIMIT 1")
    cur.execute("SELECT 1 FROM certificates LIMIT 1")
print("readonly schema verified")
PY
}

run_schema() {
  SSL_PROXY_SCHEMA_PATH="${INSTALL_DIR}/sql/schema.sql" \
  SSL_PROXY_TEST_DSN="$1" \
  "${VENV_DIR}/bin/python" - <<'PY'
from pathlib import Path
import os
import psycopg

schema = Path(os.environ["SSL_PROXY_SCHEMA_PATH"]).read_text()
dsn = os.environ["SSL_PROXY_TEST_DSN"]
with psycopg.connect(dsn, sslmode="require") as conn:
  with conn.cursor() as cur:
    cur.execute(schema)
  conn.commit()
print("schema initialized")
PY
}

render_config() {
  local mode="$1"
  local dsn="$2"
  local acme_email="$3"
  SSL_PROXY_MODE="${mode}" \
  SSL_PROXY_DSN="${dsn}" \
  SSL_PROXY_ACME_EMAIL="${acme_email}" \
  SSL_PROXY_CONFIG_PATH="${CONFIG_PATH}" \
  SSL_PROXY_STATE_DIR="${STATE_DIR}" \
  SSL_PROXY_LOG_DIR="${LOG_DIR}" \
  "${VENV_DIR}/bin/python" - <<'PY'
import os
from pathlib import Path

import yaml

config = {
  "mode": os.environ["SSL_PROXY_MODE"],
  "postgres": {
    "dsn": os.environ["SSL_PROXY_DSN"],
  },
  "sync": {
    "poll_interval_seconds": 30,
    "renew_before_days": 30,
    "retry_backoff_seconds": 3600,
    "loop_error_backoff_seconds": 10,
  },
  "paths": {
    "state_dir": os.environ["SSL_PROXY_STATE_DIR"],
    "log_dir": os.environ["SSL_PROXY_LOG_DIR"],
    "caddy_binary": "/usr/bin/caddy",
    "certbot_binary": "/usr/bin/certbot",
  },
  "caddy": {
    "admin_url": "http://127.0.0.1:2019",
    "reload_command": [
      "/usr/bin/caddy",
      "reload",
      "--config",
      f"{os.environ['SSL_PROXY_STATE_DIR']}/generated/Caddyfile",
      "--adapter",
      "caddyfile",
    ],
  },
  "acme": {
    "email": os.environ["SSL_PROXY_ACME_EMAIL"],
    "staging": False,
    "webroot": f"{os.environ['SSL_PROXY_STATE_DIR']}/acme-webroot",
    "certbot_args": [],
  },
  "logging": {
    "level": "INFO",
  },
}

config_path = Path(os.environ["SSL_PROXY_CONFIG_PATH"])
config_path.write_text(yaml.safe_dump(config, sort_keys=False))
config_path.chmod(0o600)
PY
}

get_config_value() {
  local path_expr="$1"
  SSL_PROXY_CONFIG_PATH="${CONFIG_PATH}" \
  SSL_PROXY_CONFIG_EXPR="${path_expr}" \
  "${VENV_DIR}/bin/python" - <<'PY'
import os
from pathlib import Path

import yaml

config = yaml.safe_load(Path(os.environ["SSL_PROXY_CONFIG_PATH"]).read_text()) or {}
value = config
for part in os.environ["SSL_PROXY_CONFIG_EXPR"].split("."):
  value = value[part]
print(value)
PY
}

mask_dsn() {
  local dsn="$1"
  MASK_DSN_VALUE="${dsn}" "${VENV_DIR}/bin/python" - <<'PY'
import os
from urllib.parse import urlsplit, urlunsplit

dsn = os.environ["MASK_DSN_VALUE"]
parsed = urlsplit(dsn)
hostname = parsed.hostname or ""
if parsed.port:
  hostname = f"{hostname}:{parsed.port}"
username = parsed.username or ""
netloc = hostname
if username:
  netloc = f"{username}:***@{hostname}"
print(urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)))
PY
}

config_exists_prompt() {
  if [[ -f "${CONFIG_PATH}" ]]; then
    local answer
    read -r -p "Config already exists at ${CONFIG_PATH}. Reconfigure it? [y/N]: " answer
    [[ "${answer}" == "y" || "${answer}" == "Y" ]] || return 1
  fi
  return 0
}

install_units() {
  cp "${INSTALL_DIR}/systemd/caddy.service" "${SYSTEMD_DIR}/caddy.service"
  cp "${INSTALL_DIR}/systemd/ssl-proxy-controller.service" "${SYSTEMD_DIR}/ssl-proxy-controller.service"
  cat > "${SYSTEMD_DIR}/${UPDATE_SERVICE_NAME}" <<EOF
[Unit]
Description=SSL Proxy Update Runner
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ssl-proxy update
EOF
  cat > "${SYSTEMD_DIR}/${TIMER_NAME}" <<EOF
[Unit]
Description=Daily SSL Proxy Update

[Timer]
OnCalendar=${UPDATE_SCHEDULE}
Persistent=true
Unit=${UPDATE_SERVICE_NAME}

[Install]
WantedBy=timers.target
EOF
  install -m 0755 "${INSTALL_DIR}/setup.sh" /usr/local/bin/ssl-proxy
  install -m 0755 "${INSTALL_DIR}/scripts/domain-manage.sh" /usr/local/bin/domain-manage
  systemctl daemon-reload
  systemctl enable "${CADDY_SERVICE_NAME}" "${SERVICE_NAME}" "${TIMER_NAME}" >/dev/null
}

wait_for_controller() {
  local retries=30
  while (( retries > 0 )); do
    if systemctl is-active --quiet "${SERVICE_NAME}" && systemctl is-active --quiet "${CADDY_SERVICE_NAME}"; then
      return 0
    fi
    sleep 1
    retries=$((retries - 1))
  done
  return 1
}

append_update_log() {
  local status="$1"
  printf '%s %s\n' "$(date -Is)" "${status}" >> "${UPDATE_LOG}"
}

install_command() {
  require_linux
  require_root
  require_systemd
  ensure_packages
  ensure_layout
  check_bind_ports
  sync_repo
  record_source_dir
  ensure_venv
  seed_bootstrap_caddyfile

  local mode
  local dsn
  local acme_email
  if config_exists_prompt; then
    mode="$(select_mode)"
    if [[ -n "${DEFAULT_DSN}" ]]; then
      dsn="$(prompt_with_default "PostgreSQL DSN" "${DEFAULT_DSN}")"
    else
      dsn="$(prompt_required "PostgreSQL DSN")"
    fi
    while ! validate_dsn "${dsn}"; do
      log "database connection failed"
      dsn="$(prompt_required "PostgreSQL DSN")"
    done

    if [[ "${mode}" == "readwrite" ]]; then
      acme_email="$(prompt_required "ACME email")"
    else
      acme_email="$(prompt_with_default "ACME email" "ops@example.com")"
    fi

    render_config "${mode}" "${dsn}" "${acme_email}"
  else
    log "preserving existing config at ${CONFIG_PATH}"
    mode="$(get_config_value "mode")"
    dsn="$(get_config_value "postgres.dsn")"
    validate_dsn "${dsn}"
  fi
  chmod 600 "${CONFIG_PATH}"
  if [[ "${mode}" == "readwrite" ]]; then
    run_schema "${dsn}"
  else
    validate_readonly_schema "${dsn}"
  fi
  install_units
  systemctl restart "${CADDY_SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
  systemctl restart "${TIMER_NAME}"

  wait_for_controller || fail "services did not become healthy in time"
  append_update_log "install ok"
  log "installed successfully"
  log "config: ${CONFIG_PATH}"
  log "mode: ${mode}"
}

start_command() {
  require_root
  systemctl start "${CADDY_SERVICE_NAME}" "${SERVICE_NAME}"
  wait_for_controller || fail "services did not become healthy in time"
}

stop_command() {
  require_root
  systemctl stop "${SERVICE_NAME}" "${CADDY_SERVICE_NAME}"
}

restart_command() {
  require_root
  systemctl restart "${CADDY_SERVICE_NAME}" "${SERVICE_NAME}"
  wait_for_controller || fail "services did not become healthy in time"
}

status_command() {
  local public_ip
  public_ip="$(curl -fsS --max-time 3 https://api.ipify.org || true)"
  log "caddy: $(systemctl is-active "${CADDY_SERVICE_NAME}" 2>/dev/null || true)"
  log "controller: $(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || true)"
  if [[ -f "${CONFIG_PATH}" ]]; then
    log "config: ${CONFIG_PATH}"
    log "mode: $(get_config_value "mode")"
    log "dsn: $(mask_dsn "$(get_config_value "postgres.dsn")")"
  fi
  log "listening ports:"
  ss -ltn '( sport = :80 or sport = :443 )' || true
  log "recent update log:"
  tail -n 10 "${UPDATE_LOG}" 2>/dev/null || true
  if [[ -n "${public_ip}" ]]; then
    log "public_ip: ${public_ip}"
  fi
}

logs_command() {
  journalctl -u "${CADDY_SERVICE_NAME}" -u "${SERVICE_NAME}" -n 100 -f
}

update_command() {
  require_root
  sync_repo
  record_source_dir
  ensure_venv
  if [[ -f "${CONFIG_PATH}" ]]; then
    chmod 600 "${CONFIG_PATH}"
    local mode
    local dsn
    mode="$(get_config_value "mode")"
    dsn="$(get_config_value "postgres.dsn")"
    validate_dsn "${dsn}"
    if [[ "${mode}" == "readwrite" ]]; then
      run_schema "${dsn}"
    else
      validate_readonly_schema "${dsn}"
    fi
  fi
  install_units
  systemctl restart "${CADDY_SERVICE_NAME}" "${SERVICE_NAME}"
  if wait_for_controller; then
    append_update_log "update ok"
  else
    append_update_log "update failed"
    fail "services did not become healthy after update"
  fi
}

timer_status_command() {
  systemctl is-enabled "${TIMER_NAME}" || true
  systemctl is-active "${TIMER_NAME}" || true
  systemctl status "${TIMER_NAME}" --no-pager || true
  journalctl -u "${UPDATE_SERVICE_NAME}" -n 20 --no-pager || true
}

uninstall_command() {
  require_root
  local delete_config=0
  local delete_all=0
  local yes=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes) yes=1 ;;
      --delete-config) delete_config=1 ;;
      --delete-all) delete_all=1 ;;
      *) fail "unknown uninstall flag: $1" ;;
    esac
    shift
  done

  if [[ "${yes}" -ne 1 ]]; then
    read -r -p "Proceed with uninstall? [y/N]: " confirm
    [[ "${confirm}" == "y" || "${confirm}" == "Y" ]] || exit 0
  fi

  systemctl disable --now "${TIMER_NAME}" "${SERVICE_NAME}" "${CADDY_SERVICE_NAME}" >/dev/null 2>&1 || true
  rm -f \
    "${SYSTEMD_DIR}/caddy.service" \
    "${SYSTEMD_DIR}/ssl-proxy-controller.service" \
    "${SYSTEMD_DIR}/${UPDATE_SERVICE_NAME}" \
    "${SYSTEMD_DIR}/${TIMER_NAME}" \
    /usr/local/bin/ssl-proxy \
    /usr/local/bin/domain-manage
  systemctl daemon-reload

  rm -rf "${INSTALL_DIR}"

  if [[ "${delete_config}" -eq 1 || "${delete_all}" -eq 1 ]]; then
    rm -rf "${CONFIG_DIR}"
  fi
  if [[ "${delete_all}" -eq 1 ]]; then
    rm -rf "${STATE_DIR}" "${LOG_DIR}"
  fi

  log "uninstall complete"
  if [[ "${delete_all}" -eq 1 ]]; then
    log "deleted: ${CONFIG_DIR}, ${STATE_DIR}, ${LOG_DIR}"
  elif [[ "${delete_config}" -eq 1 ]]; then
    log "deleted: ${CONFIG_DIR}"
    log "preserved: ${STATE_DIR}, ${LOG_DIR}"
  else
    log "preserved: ${CONFIG_DIR}, ${STATE_DIR}, ${LOG_DIR}"
  fi
}

interactive_menu() {
  cat <<'EOF'
1. install
2. start
3. stop
4. restart
5. status
6. logs
7. update
8. timer-status
9. uninstall
EOF
  local choice
  read -r -p "Choose an action [1-9]: " choice
  case "${choice}" in
    1) install_command ;;
    2) start_command ;;
    3) stop_command ;;
    4) restart_command ;;
    5) status_command ;;
    6) logs_command ;;
    7) update_command ;;
    8) timer_status_command ;;
    9) uninstall_command ;;
    *) fail "invalid choice" ;;
  esac
}

main() {
  local command="${1:-}"
  case "${command}" in
    install) shift; install_command "$@" ;;
    start) shift; start_command "$@" ;;
    stop) shift; stop_command "$@" ;;
    restart) shift; restart_command "$@" ;;
    status) shift; status_command "$@" ;;
    logs) shift; logs_command "$@" ;;
    update) shift; update_command "$@" ;;
    timer-status) shift; timer_status_command "$@" ;;
    uninstall) shift; uninstall_command "$@" ;;
    "") interactive_menu ;;
    *) fail "unknown command: ${command}" ;;
  esac
}

main "$@"
