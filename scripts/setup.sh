#!/usr/bin/env bash
set -euo pipefail

PROGRAM_NAME="${SSL_SERVICE_PROGRAM_NAME:-$(basename "${BASH_SOURCE[0]}")}"
SCRIPT_PATH="$0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALL_ROOT="${SSL_SERVICE_INSTALL_ROOT:-/root/.ssl-service}"
CONFIG_DIR="${INSTALL_ROOT}/config"
CONFIG_PATH="${CONFIG_DIR}/config.yaml"
STATE_DIR="${INSTALL_ROOT}/state"
LOG_DIR="${INSTALL_ROOT}/logs"
ACME_DIR="${INSTALL_ROOT}/acme"
ENV_DIR="${INSTALL_ROOT}/env"
BIN_DIR="${INSTALL_ROOT}/bin"
META_DIR="${INSTALL_ROOT}/meta"
COMPOSE_PATH="${INSTALL_ROOT}/compose.yaml"
ENTRYPOINT_PATH="${BIN_DIR}/ssl-service"
MANAGED_SETUP_PATH="${BIN_DIR}/setup.sh"
MANAGED_DOMAIN_PATH="${BIN_DIR}/domain-manage.sh"
TOOLS_VENV_DIR="${INSTALL_ROOT}/.tools-venv"
BASHRC_PATH="${SSL_SERVICE_BASHRC_PATH:-/root/.bashrc}"
ALIAS_MARKER_BEGIN="# >>> ssl-service alias >>>"
ALIAS_MARKER_END="# <<< ssl-service alias <<<"
DEFAULT_ACME_EMAIL="domain@bitsfactor.com"
DEFAULT_IMAGE="${SSL_SERVICE_IMAGE:-ghcr.io/leoleoaabbcc/ssl-service:latest}"
GITHUB_CONTENT_BASE_URL="${SSL_SERVICE_GITHUB_CONTENT_BASE_URL:-https://github.com/leoleoaabbcc/ssl-service/raw/${SSL_SERVICE_INSTALL_REF:-main}}"
STATE_MENU_ACTIONS=(install reconfigure status logs restart update uninstall exit)
STATE_MENU_LABELS=(
  "Install or overwrite runtime"
  "Change database or mode"
  "Show service status"
  "Tail service logs"
  "Restart container"
  "Pull latest image and recreate"
  "Uninstall runtime"
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
  cat <<EOF
Usage:
  ${PROGRAM_NAME}                         # interactive menu
  ${PROGRAM_NAME} install [--mode readonly|readwrite] [--dsn <postgres_dsn>] [--acme-email <email>] [--force-reconfigure]
  ${PROGRAM_NAME} reconfigure
  ${PROGRAM_NAME} status
  ${PROGRAM_NAME} logs
  ${PROGRAM_NAME} start
  ${PROGRAM_NAME} stop
  ${PROGRAM_NAME} restart
  ${PROGRAM_NAME} update
  ${PROGRAM_NAME} uninstall [--yes]
  ${PROGRAM_NAME} domain <domain-command> [args...]

Notes:
  - production runtime is installed under ${INSTALL_ROOT}
  - Docker is installed automatically if it is missing
  - the global shortcut is provided via /root/.bashrc as 'ssl-service'
  - readonly uses the default ACME email ${DEFAULT_ACME_EMAIL}
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
    return $?
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

prompt_required() {
  local prompt="$1"
  local value
  while true; do
    read -r -p "${prompt}: " value || fail "input cancelled for: ${prompt}"
    value="$(ui_trim "${value}")"
    if [[ -n "${value}" ]]; then
      printf '%s' "${value}"
      return 0
    fi
    log "value is required"
  done
}

prompt_with_default() {
  local prompt="$1"
  local default_value="$2"
  local value
  read -r -p "${prompt} [${default_value}]: " value || fail "input cancelled for: ${prompt}"
  value="$(ui_trim "${value}")"
  if [[ -z "${value}" ]]; then
    value="${default_value}"
  fi
  printf '%s' "${value}"
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
    value="$(ui_trim "${value:-readonly}")"
    case "${value}" in
      readonly|readwrite)
        printf '%s' "${value}"
        return 0
        ;;
    esac
    log "mode must be readonly or readwrite"
  done
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "run this script as root"
}

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
}

require_systemd() {
  command -v systemctl >/dev/null 2>&1 || fail "systemd is required"
  systemctl --version >/dev/null 2>&1 || fail "systemd is not usable on this host"
}

apt_install() {
  command -v apt-get >/dev/null 2>&1 || fail "apt-get is required on this host"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y "$@"
}

ensure_curl() {
  command -v curl >/dev/null 2>&1 || apt_install curl ca-certificates
}

ensure_python() {
  if command -v python3 >/dev/null 2>&1 && python3 -m venv --help >/dev/null 2>&1; then
    if python3 - <<'PY' >/dev/null 2>&1
import yaml
PY
    then
      return 0
    fi
  fi
  apt_install python3 python3-venv python3-pip python3-yaml
}

ensure_docker() {
  require_systemd
  if command -v docker >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
  else
    ensure_curl
    local installer
    installer="$(mktemp)"
    curl -fsSL https://get.docker.com -o "${installer}"
    sh "${installer}"
    rm -f "${installer}"
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi

  docker version >/dev/null 2>&1 || fail "docker is installed but not usable"

  if ! docker compose version >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt_install docker-compose-plugin
    fi
  fi
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
}

docker_compose() {
  docker compose -f "${COMPOSE_PATH}" "$@"
}

ensure_layout() {
  mkdir -p "${INSTALL_ROOT}" "${CONFIG_DIR}" "${STATE_DIR}" "${STATE_DIR}/generated" "${STATE_DIR}/state" "${STATE_DIR}/certs" \
    "${LOG_DIR}" "${ACME_DIR}" "${ENV_DIR}" "${BIN_DIR}" "${META_DIR}"
}

ensure_tools_venv() {
  ensure_python
  if [[ ! -x "${TOOLS_VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${TOOLS_VENV_DIR}"
  fi
  "${TOOLS_VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${TOOLS_VENV_DIR}/bin/pip" install "PyYAML>=6.0.1,<7.0.0" "psycopg[binary]>=3.1.18,<4.0.0" >/dev/null
}

copy_or_download() {
  local target="$1"
  local local_source="$2"
  local remote_suffix="$3"
  if [[ -r "${local_source}" ]]; then
    install -m 0755 "${local_source}" "${target}"
    return 0
  fi
  ensure_curl
  curl -fsSL "${GITHUB_CONTENT_BASE_URL}/${remote_suffix}" -o "${target}"
  chmod 0755 "${target}"
}

install_managed_scripts() {
  local self_source="${SCRIPT_PATH}"
  if [[ -r "${self_source}" && "$(realpath "${self_source}" 2>/dev/null || printf '%s' "${self_source}")" != "$(realpath "${MANAGED_SETUP_PATH}" 2>/dev/null || printf '%s' "${MANAGED_SETUP_PATH}")" ]]; then
    install -m 0755 "${self_source}" "${MANAGED_SETUP_PATH}"
  else
    copy_or_download "${MANAGED_SETUP_PATH}" "/nonexistent" "scripts/setup.sh"
  fi

  local domain_local="${REPO_DIR}/scripts/domain-manage.sh"
  if [[ ! -f "${domain_local}" ]] && [[ -f "${SCRIPT_DIR}/domain-manage.sh" ]]; then
    domain_local="${SCRIPT_DIR}/domain-manage.sh"
  fi
  if [[ -r "${domain_local}" && "$(realpath "${domain_local}" 2>/dev/null || printf '%s' "${domain_local}")" == "$(realpath "${MANAGED_DOMAIN_PATH}" 2>/dev/null || printf '%s' "${MANAGED_DOMAIN_PATH}")" ]]; then
    :
  else
    copy_or_download "${MANAGED_DOMAIN_PATH}" "${domain_local}" "scripts/domain-manage.sh"
  fi

  cat > "${ENTRYPOINT_PATH}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec bash "${MANAGED_SETUP_PATH}" "\$@"
EOF
  chmod 0755 "${ENTRYPOINT_PATH}"
}

install_shell_alias() {
  if grep -Fq "${ALIAS_MARKER_BEGIN}" "${BASHRC_PATH}" 2>/dev/null; then
    return 0
  fi
  cat >> "${BASHRC_PATH}" <<EOF

${ALIAS_MARKER_BEGIN}
alias ssl-service='bash ${ENTRYPOINT_PATH}'
${ALIAS_MARKER_END}
EOF
}

remove_shell_alias() {
  if [[ -f "${BASHRC_PATH}" ]] && grep -Fq "${ALIAS_MARKER_BEGIN}" "${BASHRC_PATH}"; then
    awk -v begin="${ALIAS_MARKER_BEGIN}" -v end="${ALIAS_MARKER_END}" '
      $0 == begin { skip = 1; next }
      $0 == end { skip = 0; next }
      !skip { print }
    ' "${BASHRC_PATH}" > "${BASHRC_PATH}.ssl-service.tmp"
    mv "${BASHRC_PATH}.ssl-service.tmp" "${BASHRC_PATH}"
  fi
}

yaml_single_quote() {
  local value="$1"
  value="${value//\'/\'\'}"
  printf "'%s'" "${value}"
}

schema_sql() {
  cat <<'EOF'
CREATE TABLE IF NOT EXISTS routes (
  domain TEXT PRIMARY KEY,
  upstream_port INTEGER CHECK (upstream_port > 0 AND upstream_port < 65536),
  upstream_target TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE routes
ALTER COLUMN upstream_port DROP NOT NULL;

ALTER TABLE routes
ADD COLUMN IF NOT EXISTS upstream_target TEXT;

UPDATE routes
SET upstream_target = '127.0.0.1:' || upstream_port::text
WHERE upstream_target IS NULL
  AND upstream_port IS NOT NULL;

CREATE TABLE IF NOT EXISTS certificates (
  domain TEXT PRIMARY KEY,
  fullchain_pem TEXT NOT NULL,
  private_key_pem TEXT NOT NULL,
  not_before TIMESTAMPTZ NOT NULL,
  not_after TIMESTAMPTZ NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active',
  source TEXT NOT NULL DEFAULT 'manual',
  retry_after TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_error TEXT
);

CREATE TABLE IF NOT EXISTS dns_zone_tokens (
  zone_name TEXT PRIMARY KEY,
  provider TEXT NOT NULL DEFAULT 'cloudflare',
  zone_id TEXT NOT NULL,
  api_token TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE certificates
ADD COLUMN IF NOT EXISTS retry_after TIMESTAMPTZ;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'certificates_domain_fkey'
      AND conrelid = 'certificates'::regclass
  ) THEN
    ALTER TABLE certificates
    ADD CONSTRAINT certificates_domain_fkey
    FOREIGN KEY (domain)
    REFERENCES routes (domain)
    ON DELETE RESTRICT;
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_routes_enabled ON routes (enabled);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates (not_after);
CREATE INDEX IF NOT EXISTS idx_dns_zone_tokens_provider ON dns_zone_tokens (provider);

CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS routes_touch_updated_at ON routes;
CREATE TRIGGER routes_touch_updated_at
BEFORE UPDATE ON routes
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS certificates_touch_updated_at ON certificates;
CREATE TRIGGER certificates_touch_updated_at
BEFORE UPDATE ON certificates
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS dns_zone_tokens_touch_updated_at ON dns_zone_tokens;
CREATE TRIGGER dns_zone_tokens_touch_updated_at
BEFORE UPDATE ON dns_zone_tokens
FOR EACH ROW
EXECUTE FUNCTION touch_updated_at();
EOF
}

mask_dsn() {
  local dsn="$1"
  MASK_DSN_VALUE="${dsn}" python3 - <<'PY'
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

get_config_value() {
  local key="$1"
  [[ -f "${CONFIG_PATH}" ]] || return 1
  SSL_SERVICE_CONFIG_PATH="${CONFIG_PATH}" SSL_SERVICE_CONFIG_KEY="${key}" python3 - <<'PY'
from pathlib import Path
import os

import yaml

path = Path(os.environ["SSL_SERVICE_CONFIG_PATH"])
key = os.environ["SSL_SERVICE_CONFIG_KEY"]
data = yaml.safe_load(path.read_text()) or {}
value = data
for part in key.split("."):
  value = value[part]
print(value)
PY
}

validate_dsn() {
  local dsn="$1"
  ensure_tools_venv
  SSL_PROXY_TEST_DSN="${dsn}" "${TOOLS_VENV_DIR}/bin/python" - <<'PY'
import os
import sys
import psycopg

dsn = os.environ["SSL_PROXY_TEST_DSN"]
with psycopg.connect(dsn, connect_timeout=10) as conn:
  with conn.cursor() as cur:
    cur.execute("SELECT current_database(), current_user")
    row = cur.fetchone()
print(f"database={row[0]} user={row[1]}", file=sys.stderr)
PY
}

validate_readonly_schema() {
  local dsn="$1"
  ensure_tools_venv
  SSL_PROXY_TEST_DSN="${dsn}" "${TOOLS_VENV_DIR}/bin/python" - <<'PY'
import os
import psycopg

dsn = os.environ["SSL_PROXY_TEST_DSN"]
with psycopg.connect(dsn, connect_timeout=10) as conn:
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
    + ". Run install in readwrite mode once first."
  )
print("readonly schema verified")
PY
}

run_schema() {
  local dsn="$1"
  ensure_tools_venv
  local schema
  schema="$(schema_sql)"
  SSL_PROXY_TEST_DSN="${dsn}" SSL_PROXY_SCHEMA_SQL="${schema}" "${TOOLS_VENV_DIR}/bin/python" - <<'PY'
import os
import psycopg

schema = os.environ["SSL_PROXY_SCHEMA_SQL"]
dsn = os.environ["SSL_PROXY_TEST_DSN"]
with psycopg.connect(dsn, connect_timeout=10) as conn:
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
  cat > "${CONFIG_PATH}" <<EOF
mode: ${mode}

postgres:
  dsn: $(yaml_single_quote "${dsn}")

sync:
  poll_interval_seconds: 30
  renew_before_days: 30
  retry_backoff_seconds: 3600
  loop_error_backoff_seconds: 10

paths:
  state_dir: /app/state
  log_dir: /app/logs
  caddy_binary: /usr/bin/caddy
  certbot_binary: /usr/local/bin/certbot

caddy:
  admin_url: http://127.0.0.1:2019
  reload_command:
    - /usr/bin/caddy
    - reload
    - --config
    - /app/state/generated/Caddyfile
    - --adapter
    - caddyfile

acme:
  email: $(yaml_single_quote "${acme_email}")
  staging: false
  challenge_type: dns-01
  dns_provider: cloudflare
  dns_propagation_seconds: 30
  certbot_args: []

logging:
  level: INFO
EOF
  chmod 0600 "${CONFIG_PATH}"
}

render_compose() {
  local image="$1"
  cat > "${COMPOSE_PATH}" <<EOF
services:
  ssl-service:
    image: ${image}
    container_name: ssl-service
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ${CONFIG_DIR}:/app/config
      - ${STATE_DIR}:/app/state
      - ${LOG_DIR}:/app/logs
      - ${ACME_DIR}:/etc/letsencrypt
EOF
}

write_install_meta() {
  local image="$1"
  cat > "${META_DIR}/install.json" <<EOF
{
  "image": "${image}",
  "config_path": "${CONFIG_PATH}",
  "installed_at": "$(date -Is)"
}
EOF
}

installed_image() {
  local image="${DEFAULT_IMAGE}"
  if [[ -f "${META_DIR}/install.json" ]]; then
    image="$(python3 - <<PY
from pathlib import Path
import json
path = Path("${META_DIR}/install.json")
print(json.loads(path.read_text()).get("image", "${DEFAULT_IMAGE}"))
PY
)"
  fi
  printf '%s' "${image}"
}

config_exists() {
  [[ -f "${CONFIG_PATH}" ]]
}

runtime_exists() {
  [[ -d "${INSTALL_ROOT}" || -f "${COMPOSE_PATH}" || -f "${CONFIG_PATH}" ]]
}

compose_service_running() {
  command -v docker >/dev/null 2>&1 || return 1
  docker compose version >/dev/null 2>&1 || return 1
  [[ -f "${COMPOSE_PATH}" ]] || return 1
  docker_compose ps --status running --services 2>/dev/null | grep -Fxq "ssl-service"
}

compose_service_exists() {
  command -v docker >/dev/null 2>&1 || return 1
  docker compose version >/dev/null 2>&1 || return 1
  [[ -f "${COMPOSE_PATH}" ]] || return 1
  docker_compose ps --services 2>/dev/null | grep -Fxq "ssl-service"
}

container_admin_ready() {
  compose_service_running || return 1
  docker_compose exec -T ssl-service python -c \
    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:2019/config/', timeout=2).read(1)" \
    >/dev/null 2>&1
}

status_summary() {
  local installed="no"
  local docker_state="missing"
  local container_state="not-installed"
  local mode="unconfigured"
  local dsn="unconfigured"

  if runtime_exists; then
    installed="yes"
  fi
  if command -v docker >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active docker >/dev/null 2>&1; then
      docker_state="active"
    else
      docker_state="inactive"
    fi
  fi
  if compose_service_running; then
    container_state="running"
  elif compose_service_exists; then
    container_state="stopped"
  fi
  if config_exists; then
    mode="$(get_config_value "mode" 2>/dev/null || printf '%s' "invalid")"
    dsn="$(mask_dsn "$(get_config_value "postgres.dsn" 2>/dev/null || printf '%s' "")")"
  fi
  printf 'installed=%s docker=%s container=%s mode=%s dsn=%s\n' \
    "${installed}" "${docker_state}" "${container_state}" "${mode}" "${dsn}"
}

ui_status_header() {
  local summary installed docker_state container_state mode dsn image
  summary="$(status_summary)"
  installed="$(printf '%s' "${summary}" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^installed=/) {sub(/^installed=/,"",$i); print $i}}')"
  docker_state="$(printf '%s' "${summary}" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^docker=/) {sub(/^docker=/,"",$i); print $i}}')"
  container_state="$(printf '%s' "${summary}" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^container=/) {sub(/^container=/,"",$i); print $i}}')"
  mode="$(printf '%s' "${summary}" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^mode=/) {sub(/^mode=/,"",$i); print $i}}')"
  dsn="$(printf '%s' "${summary}" | sed -n 's/.* dsn=//p')"
  image="$(installed_image)"
  printf '%s%s%s\n' "${COLOR_BOLD}${COLOR_BLUE}" "ssl-service control" "${COLOR_RESET}" >&2
  printf '%sinstall_root:%s %s\n' "${COLOR_DIM}" "${COLOR_RESET}" "${INSTALL_ROOT}" >&2
  printf '%sinstalled:%s %s  %sdocker:%s %s  %scontainer:%s %s\n' \
    "${COLOR_DIM}" "${COLOR_RESET}" "${installed}" \
    "${COLOR_DIM}" "${COLOR_RESET}" "${docker_state}" \
    "${COLOR_DIM}" "${COLOR_RESET}" "${container_state}" >&2
  printf '%smode:%s %s  %simage:%s %s\n' \
    "${COLOR_DIM}" "${COLOR_RESET}" "${mode}" \
    "${COLOR_DIM}" "${COLOR_RESET}" "${image}" >&2
  if [[ "${dsn}" != "unconfigured" ]]; then
    printf '%sdsn:%s %s\n' "${COLOR_DIM}" "${COLOR_RESET}" "${dsn}" >&2
  fi
  printf '\n' >&2
}

pull_image() {
  local image="$1"
  docker pull "${image}"
}

wait_for_container() {
  local retries=60
  local stable_ready_checks=0
  while (( retries > 0 )); do
    if container_admin_ready; then
      stable_ready_checks=$((stable_ready_checks + 1))
      if (( stable_ready_checks >= 2 )); then
        return 0
      fi
    else
      stable_ready_checks=0
    fi
    sleep 1
    retries=$((retries - 1))
  done
  return 1
}

prompt_install_values() {
  local initial_mode="${1:-}"
  local initial_dsn="${2:-}"
  local initial_acme="${3:-}"
  local mode="${initial_mode}"
  local dsn="${initial_dsn}"
  local acme_email="${initial_acme}"

  if [[ -z "${mode}" ]]; then
    mode="$(select_mode)"
  fi
  if [[ -z "${dsn}" ]]; then
    dsn="$(prompt_required "PostgreSQL DSN")"
  fi
  while ! validate_dsn "${dsn}"; do
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
  printf '%s\n%s\n%s\n' "${mode}" "${dsn}" "${acme_email}"
}

stop_runtime() {
  require_root
  if compose_service_exists || [[ -f "${COMPOSE_PATH}" ]]; then
    docker_compose stop || true
  fi
}

start_runtime() {
  require_root
  [[ -f "${COMPOSE_PATH}" ]] || fail "runtime is not installed"
  stop_legacy_runtime
  docker_compose up -d --remove-orphans
  wait_for_container || fail "container did not become healthy in time"
}

restart_runtime() {
  require_root
  [[ -f "${COMPOSE_PATH}" ]] || fail "runtime is not installed"
  stop_legacy_runtime
  docker_compose restart ssl-service
  wait_for_container || fail "container did not become healthy in time"
}

remove_legacy_runtime() {
  rm -rf /opt/ssl-proxy /etc/ssl-proxy /var/lib/ssl-proxy /var/log/ssl-proxy
  rm -f /usr/local/bin/ssl-proxy /usr/local/bin/domain-manage
  if [[ -f /etc/systemd/system/caddy.service ]] && grep -Fq "/var/lib/ssl-proxy/generated/Caddyfile" /etc/systemd/system/caddy.service; then
    rm -f /etc/systemd/system/caddy.service
  fi
  if [[ -f /etc/systemd/system/ssl-proxy-controller.service ]] && grep -Fq "/etc/ssl-proxy/config.yaml" /etc/systemd/system/ssl-proxy-controller.service; then
    rm -f /etc/systemd/system/ssl-proxy-controller.service
  fi
  if [[ -f /etc/systemd/system/ssl-proxy-update.service ]] && grep -Fq "ssl-proxy update" /etc/systemd/system/ssl-proxy-update.service; then
    rm -f /etc/systemd/system/ssl-proxy-update.service
  fi
  if [[ -f /etc/systemd/system/ssl-proxy-update.timer ]] && grep -Fq "ssl-proxy-update.service" /etc/systemd/system/ssl-proxy-update.timer; then
    rm -f /etc/systemd/system/ssl-proxy-update.timer
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed caddy.service ssl-proxy-controller.service ssl-proxy-update.service ssl-proxy-update.timer >/dev/null 2>&1 || true
}

stop_legacy_runtime() {
  systemctl disable --now caddy.service ssl-proxy-controller.service ssl-proxy-update.timer >/dev/null 2>&1 || true
}

perform_install() {
  local mode="$1"
  local dsn="$2"
  local acme_email="$3"
  local image="$4"

  require_linux
  require_root
  ensure_curl
  ensure_python
  ensure_docker
  ensure_layout
  ensure_tools_venv
  install_managed_scripts
  render_config "${mode}" "${dsn}" "${acme_email}"
  render_compose "${image}"
  write_install_meta "${image}"

  if [[ "${mode}" == "readwrite" ]]; then
    run_schema "${dsn}"
  else
    validate_readonly_schema "${dsn}"
  fi

  pull_image "${image}"
  stop_legacy_runtime
  docker_compose up -d --remove-orphans
  wait_for_container || fail "container did not become healthy in time"
  install_shell_alias
  remove_legacy_runtime
  log "installed successfully"
  log "install_root: ${INSTALL_ROOT}"
  log "config: ${CONFIG_PATH}"
  log "image: ${image}"
  log "refresh shell: source ${BASHRC_PATH}"
}

install_command() {
  require_root
  local mode=""
  local dsn=""
  local acme_email=""
  local force_reconfigure=0
  local overwrite_runtime=1
  local overwrite_config=1

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

  if runtime_exists && [[ "${force_reconfigure}" -ne 1 ]]; then
    if ui_has_tty; then
      ui_yes_no "Existing installation detected. Overwrite runtime files?" "no" || return 0
      overwrite_runtime=1
      if config_exists; then
        if ui_yes_no "Overwrite mode / database connection?" "no"; then
          overwrite_config=1
        else
          overwrite_config=0
        fi
      fi
    else
      fail "existing installation detected; use --force-reconfigure for non-interactive install"
    fi
  fi

  if [[ "${overwrite_config}" -eq 0 ]]; then
    [[ -f "${CONFIG_PATH}" ]] || fail "cannot preserve config because ${CONFIG_PATH} is missing"
    mode="$(get_config_value "mode")"
    dsn="$(get_config_value "postgres.dsn")"
    acme_email="$(get_config_value "acme.email")"
    validate_dsn "${dsn}"
  else
    if ui_has_tty; then
      readarray -t values < <(prompt_install_values "${mode}" "${dsn}" "${acme_email}")
      mode="${values[0]}"
      dsn="${values[1]}"
      acme_email="${values[2]}"
    else
      [[ -n "${mode}" ]] || fail "--mode is required when install runs without a TTY"
      [[ -n "${dsn}" ]] || fail "--dsn is required when install runs without a TTY"
      if [[ "${mode}" == "readwrite" ]]; then
        [[ -n "${acme_email}" ]] || fail "--acme-email is required for readwrite install without a TTY"
      else
        acme_email="${DEFAULT_ACME_EMAIL}"
      fi
      validate_dsn "${dsn}"
    fi
  fi

  perform_install "${mode}" "${dsn}" "${acme_email}" "${DEFAULT_IMAGE}"
}

reconfigure_command() {
  require_root
  config_exists || fail "runtime config not found: ${CONFIG_PATH}"
  local mode="" dsn="" acme_email=""
  if ui_has_tty; then
    readarray -t values < <(prompt_install_values "$(get_config_value "mode")" "$(get_config_value "postgres.dsn")" "")
    mode="${values[0]}"
    dsn="${values[1]}"
    acme_email="${values[2]}"
  else
    fail "reconfigure requires a TTY"
  fi
  render_config "${mode}" "${dsn}" "${acme_email}"
  if [[ "${mode}" == "readwrite" ]]; then
    run_schema "${dsn}"
  else
    validate_readonly_schema "${dsn}"
  fi
  restart_runtime
  log "database configuration updated"
}

status_command() {
  require_root
  local docker_version="unavailable"
  if command -v docker >/dev/null 2>&1; then
    docker_version="$(docker --version 2>/dev/null || printf '%s' "unavailable")"
  fi
  log "$(status_summary)"
  log "docker_version: ${docker_version}"
  if [[ -f "${COMPOSE_PATH}" ]]; then
    docker_compose ps || true
  fi
}

logs_command() {
  require_root
  [[ -f "${COMPOSE_PATH}" ]] || fail "runtime is not installed"
  docker_compose logs -f ssl-service
}

update_command() {
  require_root
  [[ -f "${COMPOSE_PATH}" ]] || fail "runtime is not installed"
  ensure_docker
  ensure_tools_venv
  if config_exists; then
    local mode dsn
    mode="$(get_config_value "mode")"
    dsn="$(get_config_value "postgres.dsn")"
    validate_dsn "${dsn}"
    if [[ "${mode}" == "readwrite" ]]; then
      run_schema "${dsn}"
    else
      validate_readonly_schema "${dsn}"
    fi
  fi
  local image
  image="$(installed_image)"
  pull_image "${image}"
  install_managed_scripts
  install_shell_alias
  render_compose "${image}"
  write_install_meta "${image}"
  stop_legacy_runtime
  docker_compose up -d --remove-orphans
  wait_for_container || fail "container did not become healthy in time"
  remove_legacy_runtime
  log "updated successfully"
}

uninstall_command() {
  require_root
  local yes=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --yes) yes=1 ;;
      *) fail "unknown uninstall flag: $1" ;;
    esac
    shift
  done

  if [[ "${yes}" -ne 1 ]]; then
    ui_yes_no "Proceed with uninstall?" "no" || return 0
  fi

  if compose_service_exists || [[ -f "${COMPOSE_PATH}" ]]; then
    docker_compose down --remove-orphans || true
  fi
  rm -rf "${INSTALL_ROOT}"
  remove_shell_alias
  remove_legacy_runtime
  log "uninstall complete"
}

domain_command() {
  require_root
  local domain_script="${MANAGED_DOMAIN_PATH}"
  if [[ ! -x "${domain_script}" && -x "${REPO_DIR}/scripts/domain-manage.sh" ]]; then
    domain_script="${REPO_DIR}/scripts/domain-manage.sh"
  fi
  [[ -x "${domain_script}" ]] || fail "domain manager not installed"
  SSL_PROXY_CONFIG="${CONFIG_PATH}" \
  SSL_PROXY_DOMAIN_PROGRAM_NAME="ssl-service domain" \
  bash "${domain_script}" "$@"
}

interactive_menu() {
  local selection action default_index=0
  while true; do
    ui_clear_screen
    ui_status_header
    selection="$(ui_menu_select "ssl-service control" "${default_index}" "${STATE_MENU_LABELS[@]}")" || return 0
    action="${STATE_MENU_ACTIONS[selection]}"
    default_index="${selection}"
    case "${action}" in
      install) install_command ;;
      reconfigure) reconfigure_command ;;
      status) status_command ;;
      logs) logs_command ;;
      restart) restart_runtime ;;
      update) update_command ;;
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
    install)
      shift
      install_command "$@"
      ;;
    reconfigure)
      shift
      reconfigure_command "$@"
      ;;
    status)
      shift
      status_command "$@"
      ;;
    logs)
      shift
      logs_command "$@"
      ;;
    start)
      shift
      start_runtime "$@"
      ;;
    stop)
      shift
      stop_runtime "$@"
      ;;
    restart)
      shift
      restart_runtime "$@"
      ;;
    update)
      shift
      update_command "$@"
      ;;
    uninstall)
      shift
      uninstall_command "$@"
      ;;
    domain)
      shift
      domain_command "$@"
      ;;
    "")
      if ui_has_tty; then
        interactive_menu
      else
        usage
        exit 1
      fi
      ;;
    *)
      fail "unknown command: ${command}"
      ;;
  esac
}

main "$@"
