#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_DIR="/opt/ssl-proxy"
CONFIG_DIR="/etc/ssl-proxy"
CONFIG_PATH="${CONFIG_DIR}/config.yaml"
STATE_DIR="/var/lib/ssl-proxy"
LOG_DIR="/var/log/ssl-proxy"
VENV_DIR="${INSTALL_DIR}/.venv"
ACME_VENV_DIR="${INSTALL_DIR}/.acme-venv"
TOOLS_VENV_DIR="${INSTALL_DIR}/.tools-venv"
SYSTEMD_DIR="/etc/systemd/system"
TIMER_NAME="ssl-proxy-update.timer"
SERVICE_NAME="ssl-proxy-controller.service"
CADDY_SERVICE_NAME="caddy.service"
UPDATE_SERVICE_NAME="ssl-proxy-update.service"
UPDATE_SCHEDULE="*-*-* 04:00:00"
UPDATE_LOG="${STATE_DIR}/update.log"
DEFAULT_DSN=""
SOURCE_DIR_FILE="${INSTALL_DIR}/.source_dir"
SHELL_PROMPT_PROFILE="/etc/profile.d/ssl-proxy-shell.sh"
DEFAULT_ACME_EMAIL="domain@bitsfactor.com"
SETUP_MENU_ACTIONS=(install domain start stop restart status logs update timer-status uninstall exit)
SETUP_MENU_LABELS=(
  "Install or reconfigure this node"
  "Open domain manager"
  "Start services"
  "Stop services"
  "Restart services"
  "Show service status"
  "Tail service logs"
  "Update code and restart"
  "Show update timer status"
  "Uninstall this node"
  "Exit"
)

ui_supports_color() {
  [[ -t 1 ]] || return 1
  [[ "${TERM:-}" != "dumb" ]] || return 1
  return 0
}

if ui_supports_color; then
  COLOR_RESET=$'\033[0m'
  COLOR_BOLD=$'\033[1m'
  COLOR_DIM=$'\033[2m'
  COLOR_RED=$'\033[31m'
  COLOR_GREEN=$'\033[32m'
  COLOR_YELLOW=$'\033[33m'
  COLOR_BLUE=$'\033[34m'
  COLOR_CYAN=$'\033[36m'
  COLOR_WHITE=$'\033[37m'
  COLOR_REVERSE=$'\033[7m'
else
  COLOR_RESET=""
  COLOR_BOLD=""
  COLOR_DIM=""
  COLOR_RED=""
  COLOR_GREEN=""
  COLOR_YELLOW=""
  COLOR_BLUE=""
  COLOR_CYAN=""
  COLOR_WHITE=""
  COLOR_REVERSE=""
fi

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  setup.sh install [--mode readonly|readwrite] [--dsn <postgres_dsn>] [--acme-email <email>] [--force-reconfigure]
  setup.sh domain <domain-command> [args...]
  setup.sh start
  setup.sh stop
  setup.sh restart
  setup.sh status
  setup.sh logs
  setup.sh update
  setup.sh timer-status
  setup.sh uninstall [--yes] [--delete-config] [--delete-all]

Notes:
  - install prompts for missing values unless --mode and --dsn are provided.
  - --acme-email is required for non-interactive readwrite installs.
  - --force-reconfigure overwrites an existing config without asking.
EOF
}

ui_has_tty() {
  [[ -t 0 && -t 1 ]]
}

ui_clear_screen() {
  if [[ -t 1 ]]; then
    printf '\033c' >&2
  fi
}

ui_trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

ui_read_key() {
  local key
  IFS= read -rsn1 key || return 1
  if [[ "${key}" == $'\x1b' ]]; then
    local next rest
    IFS= read -rsn1 -t 0.05 next || true
    if [[ "${next}" == "[" ]]; then
      IFS= read -rsn1 -t 0.05 rest || true
      key+="${next}${rest}"
    else
      key+="${next}"
    fi
  fi
  printf '%s' "${key}"
}

ui_menu_select() {
  local title="$1"
  local default_index="$2"
  shift 2
  local -a items=("$@")
  local selected=0 key index

  if [[ "${default_index}" =~ ^[0-9]+$ ]] && (( default_index >= 0 && default_index < ${#items[@]} )); then
    selected="${default_index}"
  fi

  if ! ui_has_tty; then
    printf '%s' "${selected}"
    return 0
  fi

  while true; do
    ui_clear_screen
    printf '%s%s%s\n' "${COLOR_BOLD}${COLOR_CYAN}" "${title}" "${COLOR_RESET}" >&2
    printf '%sUse Up/Down arrows and Enter to select.%s\n\n' "${COLOR_DIM}" "${COLOR_RESET}" >&2
    for index in "${!items[@]}"; do
      if [[ "${index}" -eq "${selected}" ]]; then
        printf '%s%s> %s%s\n' "${COLOR_REVERSE}${COLOR_WHITE}" "${COLOR_BOLD}" "${items[index]}" "${COLOR_RESET}" >&2
      else
        printf '  %s\n' "${items[index]}" >&2
      fi
    done

    key="$(ui_read_key)" || return 1
    case "${key}" in
      $'\x1b[A'|k)
        selected=$(( (selected - 1 + ${#items[@]}) % ${#items[@]} ))
        ;;
      $'\x1b[B'|j)
        selected=$(( (selected + 1) % ${#items[@]} ))
        ;;
      ""|$'\n'|$'\r')
        printf '%s' "${selected}"
        return 0
        ;;
    esac
  done
}

ui_yes_no() {
  local prompt="$1"
  local default_answer="${2:-no}"
  local default_index=1
  local index

  if [[ "${default_answer}" == "yes" ]]; then
    default_index=0
  fi

  if ui_has_tty; then
    index="$(ui_menu_select "${prompt}" "${default_index}" "Yes" "No")" || return 1
    [[ "${index}" == "0" ]]
    return $?
  fi

  local answer
  if [[ "${default_answer}" == "yes" ]]; then
    read -r -p "${prompt} [Y/n]: " answer || return 1
    answer="$(ui_trim "${answer}")"
    [[ -z "${answer}" || "${answer}" == "y" || "${answer}" == "Y" ]]
    return 0
  fi

  read -r -p "${prompt} [y/N]: " answer || return 1
  answer="$(ui_trim "${answer}")"
  [[ "${answer}" == "y" || "${answer}" == "Y" ]]
}

ui_pause() {
  ui_has_tty || return 0
  printf '\n%sPress Enter to continue...%s' "${COLOR_DIM}" "${COLOR_RESET}"
  local _
  read -r _
}

ui_setup_header() {
  local mode="unconfigured"
  if [[ -f "${CONFIG_PATH}" ]]; then
    mode="$(awk '$1 == "mode:" { print $2; exit }' "${CONFIG_PATH}" 2>/dev/null || printf '%s' "unknown")"
  fi
  printf '%s%s%s\n' "${COLOR_BOLD}${COLOR_BLUE}" "ssl-proxy control" "${COLOR_RESET}"
  printf '%shost:%s %s  %smode:%s %s  %sconfig:%s %s\n\n' \
    "${COLOR_DIM}" "${COLOR_RESET}" "${HOSTNAME%%.*}" \
    "${COLOR_DIM}" "${COLOR_RESET}" "${mode}" \
    "${COLOR_DIM}" "${COLOR_RESET}" "${CONFIG_PATH}"
}

domain_script_path() {
  if [[ -x "${REPO_DIR}/scripts/domain-manage.sh" ]]; then
    printf '%s' "${REPO_DIR}/scripts/domain-manage.sh"
    return 0
  fi
  if [[ -x "${INSTALL_DIR}/scripts/domain-manage.sh" ]]; then
    printf '%s' "${INSTALL_DIR}/scripts/domain-manage.sh"
    return 0
  fi
  fail "domain management script not found"
}

domain_command() {
  local script_path
  script_path="$(domain_script_path)"
  SSL_PROXY_DOMAIN_PROGRAM_NAME="ssl-proxy domain" bash "${script_path}" "$@"
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
  apt-get install -y curl python3 python3-venv python3-pip rsync caddy
}

ensure_layout() {
  mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}"
  mkdir -p "${STATE_DIR}/generated" "${STATE_DIR}/state" "${STATE_DIR}/certs"
  touch "${UPDATE_LOG}"
}

install_shell_prompt() {
  cat > "${SHELL_PROMPT_PROFILE}" <<'EOF'
# shellcheck shell=bash

case $- in
  *i*) ;;
  *) return 0 2>/dev/null || exit 0 ;;
esac

ssl_proxy_prompt_mode() {
  local config_path="/etc/ssl-proxy/config.yaml"
  local mode="unknown"
  if [[ -r "${config_path}" ]]; then
    mode="$(awk '$1 == "mode:" { print $2; exit }' "${config_path}" 2>/dev/null)"
  fi
  printf '%s' "${mode:-unknown}"
}

ssl_proxy_apply_prompt() {
  local mode color label reset host_color path_color
  mode="$(ssl_proxy_prompt_mode)"
  reset='\[\033[0m\]'
  host_color='\[\033[1;37m\]'
  path_color='\[\033[1;33m\]'

  case "${mode}" in
    readwrite)
      color='\[\033[1;31m\]'
      label='RW'
      ;;
    readonly)
      color='\[\033[1;34m\]'
      label='RO'
      ;;
    *)
      color='\[\033[1;35m\]'
      label='??'
      ;;
  esac

  PS1="${color}[${label}]${reset} ${host_color}\u@\h${reset}:${path_color}\w${reset}\\$ "
}

ssl_proxy_apply_prompt
unset -f ssl_proxy_apply_prompt
unset -f ssl_proxy_prompt_mode
EOF
  chmod 0644 "${SHELL_PROMPT_PROFILE}"

  if [[ -f /etc/bash.bashrc ]] && ! grep -Fq "${SHELL_PROMPT_PROFILE}" /etc/bash.bashrc; then
    cat >> /etc/bash.bashrc <<EOF

# Load ssl-proxy prompt customizations for interactive bash shells.
if [ -r "${SHELL_PROMPT_PROFILE}" ]; then
  . "${SHELL_PROMPT_PROFILE}"
fi
EOF
  fi
}

sync_repo() {
  local source_dir
  source_dir="$(resolve_source_dir)"
  rsync -a --delete \
    --exclude '.git' \
    --exclude '.codex' \
    --exclude '__pycache__' \
    --exclude '.venv' \
    --exclude '.acme-venv' \
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

ensure_tools_venv() {
  local source_dir
  source_dir="$(resolve_source_dir)"
  if [[ ! -x "${TOOLS_VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${TOOLS_VENV_DIR}"
  fi
  "${TOOLS_VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${TOOLS_VENV_DIR}/bin/pip" install "${source_dir}[test]" >/dev/null
}

ensure_acme_venv() {
  if [[ ! -x "${ACME_VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${ACME_VENV_DIR}"
  fi
  "${ACME_VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${ACME_VENV_DIR}/bin/pip" install --upgrade "certbot>=2.11,<3.0" "certbot-dns-cloudflare>=2.11,<3.0" >/dev/null
}

certbot_binary_path() {
  printf '%s' "${ACME_VENV_DIR}/bin/certbot"
}

verify_certbot_cloudflare_plugin() {
  local certbot_bin
  certbot_bin="$(certbot_binary_path)"
  [[ -x "${certbot_bin}" ]] || fail "certbot binary not found at ${certbot_bin}"

  local plugin_output
  if ! plugin_output="$("${certbot_bin}" plugins 2>&1)"; then
    printf '%s\n' "${plugin_output}" >&2
    fail "failed to inspect certbot plugins"
  fi
  if ! printf '%s\n' "${plugin_output}" | grep -Fq 'dns-cloudflare'; then
    printf '%s\n' "${plugin_output}" >&2
    fail "certbot dns-cloudflare plugin is not available"
  fi
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
  read -r -p "${prompt} [${default_value}]: " value || fail "input cancelled for: ${prompt}"
  if [[ -z "${value}" ]]; then
    value="${default_value}"
  fi
  printf '%s' "${value}"
}

resolve_source_dir() {
  if [[ -f "${REPO_DIR}/pyproject.toml" ]]; then
    printf '%s' "${REPO_DIR}"
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
    read -r -p "${prompt}: " value || fail "input cancelled for: ${prompt}"
    if [[ -n "${value}" ]]; then
      printf '%s' "${value}"
      return 0
    fi
    log "value is required"
  done
}

select_mode() {
  if ui_has_tty; then
    local selected
    selected="$(ui_menu_select "Select node mode" 0 \
      "readonly  - follow database state and do not issue certificates" \
      "readwrite - manage certificates and write state back to PostgreSQL")" || return 1
    case "${selected}" in
      0) printf '%s' "readonly" ;;
      1) printf '%s' "readwrite" ;;
      *) fail "invalid mode selection" ;;
    esac
    return 0
  fi

  local value
  while true; do
    read -r -p "Select mode (readonly/readwrite) [readonly]: " value || fail "input cancelled for mode selection"
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
    cur.execute(
      """
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'routes'
      """
    )
    route_columns = {row[0] for row in cur.fetchall()}
    cur.execute(
      """
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'certificates'
      """
    )
    certificate_columns = {row[0] for row in cur.fetchall()}

missing = []
if "domain" not in route_columns or "upstream_target" not in route_columns:
  missing.append("routes(domain, upstream_target)")
if "domain" not in certificate_columns:
  missing.append("certificates(domain)")
if missing:
  raise SystemExit(
    "readonly schema verification failed; missing required objects: "
    + ", ".join(missing)
    + ". Run 'ssl-proxy update' on a readwrite node first."
  )
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
  SSL_PROXY_CERTBOT_BINARY="$(certbot_binary_path)" \
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
    "certbot_binary": os.environ["SSL_PROXY_CERTBOT_BINARY"],
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
    "challenge_type": "dns-01",
    "dns_provider": "cloudflare",
    "dns_propagation_seconds": 30,
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

normalize_config_certbot_binary() {
  [[ -f "${CONFIG_PATH}" ]] || return 0
  SSL_PROXY_CONFIG_PATH="${CONFIG_PATH}" \
  SSL_PROXY_CERTBOT_BINARY="$(certbot_binary_path)" \
  "${VENV_DIR}/bin/python" - <<'PY'
import os
from pathlib import Path

import yaml

config_path = Path(os.environ["SSL_PROXY_CONFIG_PATH"])
config = yaml.safe_load(config_path.read_text()) or {}
paths = dict(config.get("paths", {}))
paths["certbot_binary"] = os.environ["SSL_PROXY_CERTBOT_BINARY"]
config["paths"] = paths
config_path.write_text(yaml.safe_dump(config, sort_keys=False))
config_path.chmod(0o600)
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
    ui_yes_no "Config already exists at ${CONFIG_PATH}. Reconfigure it?" "no" || return 1
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
  install -m 0755 "${INSTALL_DIR}/scripts/setup.sh" /usr/local/bin/ssl-proxy
  rm -f /usr/local/bin/domain-manage
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
  local mode=""
  local dsn=""
  local acme_email=""
  local force_reconfigure=0
  local interactive_input=0
  local config_missing=1

  if ui_has_tty; then
    interactive_input=1
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        shift
        [[ $# -gt 0 ]] || fail "--mode requires a value"
        mode="$1"
        ;;
      --dsn)
        shift
        [[ $# -gt 0 ]] || fail "--dsn requires a value"
        dsn="$1"
        ;;
      --acme-email)
        shift
        [[ $# -gt 0 ]] || fail "--acme-email requires a value"
        acme_email="$1"
        ;;
      --force-reconfigure)
        force_reconfigure=1
        ;;
      *)
        fail "unknown install flag: $1"
        ;;
    esac
    shift
  done

  if [[ -n "${mode}" && "${mode}" != "readonly" && "${mode}" != "readwrite" ]]; then
    fail "--mode must be readonly or readwrite"
  fi

  [[ -f "${CONFIG_PATH}" ]] && config_missing=0

  if [[ "${interactive_input}" -ne 1 && ( "${force_reconfigure}" -eq 1 || "${config_missing}" -eq 1 ) ]]; then
    [[ -n "${mode}" ]] || fail "--mode is required when install runs without a TTY"
    [[ -n "${dsn}" ]] || fail "--dsn is required when install runs without a TTY"
    if [[ "${mode}" == "readwrite" && -z "${acme_email}" ]]; then
      fail "--acme-email is required for readwrite install without a TTY"
    fi
  fi

  if [[ "${interactive_input}" -ne 1 && "${config_missing}" -eq 0 && "${force_reconfigure}" -ne 1 ]]; then
    if [[ -n "${mode}" || -n "${dsn}" || -n "${acme_email}" ]]; then
      fail "existing config detected; use --force-reconfigure to apply new install parameters without a TTY"
    fi
  fi

  require_linux
  require_root
  require_systemd
  ensure_packages
  ensure_layout
  check_bind_ports
  sync_repo
  record_source_dir
  ensure_venv
  ensure_tools_venv
  ensure_acme_venv
  verify_certbot_cloudflare_plugin
  seed_bootstrap_caddyfile

  if [[ "${force_reconfigure}" -eq 1 || ! -f "${CONFIG_PATH}" ]]; then
    if [[ -z "${mode}" ]]; then
      mode="$(select_mode)"
    fi

    if [[ -z "${dsn}" ]]; then
      if [[ -n "${DEFAULT_DSN}" ]]; then
        dsn="$(prompt_with_default "PostgreSQL DSN" "${DEFAULT_DSN}")"
      else
        dsn="$(prompt_required "PostgreSQL DSN")"
      fi
    fi
    while ! validate_dsn "${dsn}"; do
      [[ "${interactive_input}" -eq 1 ]] || fail "database connection failed for supplied --dsn"
      log "database connection failed"
      dsn="$(prompt_required "PostgreSQL DSN")"
    done

    if [[ -z "${acme_email}" ]]; then
      if [[ "${mode}" == "readwrite" ]]; then
        acme_email="$(prompt_required "ACME email")"
      else
        acme_email="${DEFAULT_ACME_EMAIL}"
      fi
    fi

    render_config "${mode}" "${dsn}" "${acme_email}"
  elif config_exists_prompt; then
    if [[ "${interactive_input}" -ne 1 ]]; then
      [[ -n "${mode}" ]] || fail "--mode is required when reconfiguring without a TTY"
      [[ -n "${dsn}" ]] || fail "--dsn is required when reconfiguring without a TTY"
      if [[ "${mode}" == "readwrite" && -z "${acme_email}" ]]; then
        fail "--acme-email is required for readwrite reconfigure without a TTY"
      fi
    fi
    if [[ -z "${mode}" ]]; then
      mode="$(select_mode)"
    fi
    if [[ -z "${dsn}" ]]; then
      if [[ -n "${DEFAULT_DSN}" ]]; then
        dsn="$(prompt_with_default "PostgreSQL DSN" "${DEFAULT_DSN}")"
      else
        dsn="$(prompt_required "PostgreSQL DSN")"
      fi
    fi
    while ! validate_dsn "${dsn}"; do
      [[ "${interactive_input}" -eq 1 ]] || fail "database connection failed for supplied --dsn"
      log "database connection failed"
      dsn="$(prompt_required "PostgreSQL DSN")"
    done

    if [[ -z "${acme_email}" ]]; then
      if [[ "${mode}" == "readwrite" ]]; then
        acme_email="$(prompt_required "ACME email")"
      else
        acme_email="${DEFAULT_ACME_EMAIL}"
      fi
    fi

    render_config "${mode}" "${dsn}" "${acme_email}"
  else
    log "preserving existing config at ${CONFIG_PATH}"
    mode="$(get_config_value "mode")"
    dsn="$(get_config_value "postgres.dsn")"
    validate_dsn "${dsn}"
  fi
  normalize_config_certbot_binary
  chmod 600 "${CONFIG_PATH}"
  if [[ "${mode}" == "readwrite" ]]; then
    run_schema "${dsn}"
  else
    validate_readonly_schema "${dsn}"
  fi
  install_shell_prompt
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
  local caddy_status
  local controller_status
  public_ip="$(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)"
  caddy_status="$(systemctl is-active "${CADDY_SERVICE_NAME}" 2>/dev/null || echo unavailable)"
  controller_status="$(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || echo unavailable)"
  log "caddy: ${caddy_status}"
  log "controller: ${controller_status}"
  if [[ -f "${CONFIG_PATH}" ]]; then
    log "config: ${CONFIG_PATH}"
    log "mode: $(get_config_value "mode")"
    log "dsn: $(mask_dsn "$(get_config_value "postgres.dsn")")"
  fi
  log "listening ports:"
  local port_output
  if ! port_output="$(ss -ltn '( sport = :80 or sport = :443 )' 2>/dev/null)"; then
    log "unavailable"
  elif [[ "$(printf '%s\n' "${port_output}" | wc -l)" -le 1 ]]; then
    log "none"
  else
    printf '%s\n' "${port_output}"
  fi
  log "recent update log:"
  tail -n 10 "${UPDATE_LOG}" 2>/dev/null || true
  if [[ -n "${public_ip}" ]]; then
    log "public_ip: ${public_ip}"
  else
    log "public_ip: unavailable"
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
  ensure_tools_venv
  ensure_acme_venv
  verify_certbot_cloudflare_plugin
  if [[ -f "${CONFIG_PATH}" ]]; then
    normalize_config_certbot_binary
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
  install_shell_prompt
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
    ui_yes_no "Proceed with uninstall?" "no" || exit 0
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
  local selection action default_index=0
  while true; do
    if ui_has_tty; then
      ui_clear_screen
      ui_setup_header
    fi
    selection="$(ui_menu_select "ssl-proxy control" "${default_index}" "${SETUP_MENU_LABELS[@]}")" || return 0
    action="${SETUP_MENU_ACTIONS[selection]}"
    default_index="${selection}"
    case "${action}" in
      install) install_command ;;
      domain) domain_command ;;
      start) start_command ;;
      stop) stop_command ;;
      restart) restart_command ;;
      status) status_command ;;
      logs) logs_command ;;
      update) update_command ;;
      timer-status) timer_status_command ;;
      uninstall) uninstall_command ;;
      exit) return 0 ;;
      *) fail "invalid choice" ;;
    esac
    ui_pause
  done
}

main() {
  local command="${1:-}"
  case "${command}" in
    -h|--help|help)
      usage
      ;;
    domain) shift; domain_command "$@" ;;
    install) shift; install_command "$@" ;;
    start) shift; start_command "$@" ;;
    stop) shift; stop_command "$@" ;;
    restart) shift; restart_command "$@" ;;
    status) shift; status_command "$@" ;;
    logs) shift; logs_command "$@" ;;
    update) shift; update_command "$@" ;;
    timer-status) shift; timer_status_command "$@" ;;
    uninstall) shift; uninstall_command "$@" ;;
    "")
      if ui_has_tty; then
        interactive_menu
      else
        usage
        exit 1
      fi
      ;;
    *) fail "unknown command: ${command}" ;;
  esac
}

main "$@"
