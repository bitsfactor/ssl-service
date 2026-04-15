#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEPLOY_DIR="/root/.ssl-service"
LEGACY_DEPLOY_DIR="/opt/ssl-proxy"
PROGRAM_NAME="${SSL_PROXY_DOMAIN_PROGRAM_NAME:-$(basename "${BASH_SOURCE[0]}")}"
CONFIG_CANDIDATES=(
  "/root/.ssl-service/config/config.yaml"
  "/etc/ssl-proxy/config.yaml"
)
COMPOSE_PATH="${DEPLOY_DIR}/compose.yaml"
UI_INTERACTIVE=0
LAST_DOMAIN=""
LAST_UPSTREAM=""
LAST_ZONE_TARGET=""
DEFAULT_MENU_ACTION=""
UI_LAST_STATUS=0
DOMAIN_MENU_ACTIONS=(
  overview
  list
  list-certs
  list-zones
  status
  check
  logs
  get
  add
  set-target
  clear-target
  enable
  disable
  delete
  purge
  issue-now
  set-zone-token
  sync-now
  shell
  help
  exit
)
DOMAIN_MENU_LABELS=(
  "Node overview"
  "List routes"
  "List certificates"
  "List zones"
  "Status for a domain"
  "Check health for a domain"
  "Logs for a domain"
  "Get raw route row"
  "Add a domain"
  "Set upstream target"
  "Clear upstream target"
  "Enable domain"
  "Disable domain"
  "Delete route"
  "Purge route and certificate"
  "Issue certificate now"
  "Set Cloudflare zone token"
  "Sync now"
  "Open colored shell"
  "Help"
  "Exit"
)

ui_supports_color() {
  [[ -t 2 ]] || return 1
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
  COLOR_MAGENTA=$'\033[35m'
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
  COLOR_MAGENTA=""
  COLOR_CYAN=""
  COLOR_WHITE=""
  COLOR_REVERSE=""
fi

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  if [[ "${UI_INTERACTIVE}" -eq 1 ]]; then
    return 1
  fi
  exit 1
}

usage() {
  cat <<EOF
Usage:
  ${PROGRAM_NAME}                         # interactive menu
  ${PROGRAM_NAME} overview
  ${PROGRAM_NAME} list
  ${PROGRAM_NAME} list-certs
  ${PROGRAM_NAME} list-zones
  ${PROGRAM_NAME} shell
  ${PROGRAM_NAME} prompt-init
  ${PROGRAM_NAME} get <domain>
  ${PROGRAM_NAME} status <domain>
  ${PROGRAM_NAME} check <domain>
  ${PROGRAM_NAME} logs <domain>
  ${PROGRAM_NAME} add <domain> [upstream_target]
  ${PROGRAM_NAME} set-target <domain> <upstream_target>
  ${PROGRAM_NAME} clear-target <domain>
  ${PROGRAM_NAME} set-port <domain> <upstream_port>    # deprecated alias
  ${PROGRAM_NAME} clear-port <domain>                  # deprecated alias
  ${PROGRAM_NAME} enable <domain>
  ${PROGRAM_NAME} disable <domain>
  ${PROGRAM_NAME} delete <domain>
  ${PROGRAM_NAME} purge <domain>
  ${PROGRAM_NAME} issue-now <domain>
  ${PROGRAM_NAME} set-zone-token <domain_or_zone>
  ${PROGRAM_NAME} sync-now

Notes:
  - running without arguments opens the interactive menu.
  - 'overview' shows local node mode and service state.
  - certificate issuance uses DNS-01 with Cloudflare only.
  - upstream_target can be omitted on add, which creates a certificate-only domain.
  - upstream_target accepts '6111', '127.0.0.1:6111', 'localhost:6111', '10.0.0.25:6111', 'backend.internal:6111', or '[2001:db8::10]:6111'.
  - plain ports and localhost-style upstreams are treated as services on the Docker host.
  - the script reads PostgreSQL DSN from /root/.ssl-service/config/config.yaml by default.
  - override config with: SSL_PROXY_CONFIG=/path/to/config.yaml
  - mutating commands accept --sync-now to force an immediate local refresh
  - automatic retry backoff defaults to 3600 seconds after ACME failure
EOF
}

shell_prompt_color() {
  local mode="$1"
  case "${mode}" in
    readwrite) printf '%s' '1;31' ;;
    readonly) printf '%s' '1;34' ;;
    *) printf '%s' '1;35' ;;
  esac
}

shell_prompt_label() {
  local mode="$1"
  case "${mode}" in
    readwrite) printf '%s' 'RW' ;;
    readonly) printf '%s' 'RO' ;;
    *) printf '%s' '??' ;;
  esac
}

prompt_init_command() {
  local mode color label
  mode="$(get_config_mode)"
  color="$(shell_prompt_color "${mode}")"
  label="$(shell_prompt_label "${mode}")"
  cat <<EOF
case \$- in
  *i*) ;;
  *) return 0 2>/dev/null || exit 0 ;;
esac
PS1='\[\033[${color}m\][${label}]\[\033[0m\] \[\033[1;37m\]\u@\h\[\033[0m\]:\[\033[1;33m\]\w\[\033[0m\]\\$ '
if [[ "\${TERM:-}" == xterm* || "\${TERM:-}" == screen* || "\${TERM:-}" == tmux* || "\${TERM:-}" == rxvt* ]]; then
  printf '\033]0;[%s] %s@%s: %s\007' '${label}' "\${USER}" "\${HOSTNAME%%.*}" "\${PWD/#\${HOME}/~}"
fi
EOF
}

ui_mode_color() {
  local mode="$1"
  case "${mode}" in
    readwrite) printf '%s' "${COLOR_RED}" ;;
    readonly) printf '%s' "${COLOR_BLUE}" ;;
    *) printf '%s' "${COLOR_MAGENTA}" ;;
  esac
}

ui_clear_screen() {
  if ui_has_tty; then
    printf '\033[H\033[2J' > /dev/tty
  fi
}

ui_cursor_save() {
  ui_has_tty || return 0
  printf '\033[s' >&2
}

ui_cursor_restore() {
  ui_has_tty || return 0
  printf '\033[u' >&2
}

ui_clear_to_end() {
  ui_has_tty || return 0
  printf '\033[J' >&2
}

ui_print_header() {
  local mode="$1"
  local mode_color
  mode_color="$(ui_mode_color "${mode}")"
  ui_clear_screen
  printf '%s[%s]%s %sssl-service domain manager%s\n' "${mode_color}" "$(shell_prompt_label "${mode}")" "${COLOR_RESET}" "${COLOR_BOLD}" "${COLOR_RESET}" >&2
  printf '%shost:%s %s  %smode:%s %s  %sconfig:%s %s\n' \
    "${COLOR_DIM}" "${COLOR_RESET}" "${HOSTNAME%%.*}" \
    "${COLOR_DIM}" "${COLOR_RESET}" "${mode}" \
    "${COLOR_DIM}" "${COLOR_RESET}" "$(resolve_config_path)" >&2
  printf '%s\n' "--------------------------------------------------------------------------------" >&2
}

ui_print_dashboard_summary() {
  local mode="$1"
  local runtime_status proxy_status root_state
  runtime_status="$(service_state_summary ssl-service)"
  proxy_status="${runtime_status}"
  root_state="no"
  [[ "${EUID}" -eq 0 ]] && root_state="yes"

  printf '%sCurrent State%s\n' "${COLOR_BOLD}" "${COLOR_RESET}" >&2
  printf '  mode=%s%s%s  container=%s  proxy=%s  root=%s\n' \
    "$(ui_mode_color "${mode}")" "${mode}" "${COLOR_RESET}" \
    "${runtime_status}" \
    "${proxy_status}" \
    "${root_state}" >&2
  if [[ -n "${LAST_DOMAIN}" || -n "${LAST_UPSTREAM}" || -n "${LAST_ZONE_TARGET}" ]]; then
    printf '  context:' >&2
    [[ -n "${LAST_DOMAIN}" ]] && printf ' domain=%s' "${LAST_DOMAIN}" >&2
    [[ -n "${LAST_UPSTREAM}" ]] && printf ' upstream=%s' "${LAST_UPSTREAM}" >&2
    [[ -n "${LAST_ZONE_TARGET}" ]] && printf ' zone=%s' "${LAST_ZONE_TARGET}" >&2
    printf '\n' >&2
  fi
  printf '\n' >&2
}

ui_print_menu() {
  local selected="$1"
  printf '%sUse Up/Down arrows and Enter to select.%s\n\n' "${COLOR_DIM}" "${COLOR_RESET}" >&2
  printf '%sOverview%s\n' "${COLOR_BOLD}" "${COLOR_RESET}" >&2
  ui_print_menu_item "${selected}" 0 "Node overview" "overview"
  printf '\n%sInspect%s\n' "${COLOR_BOLD}" "${COLOR_RESET}" >&2
  ui_print_menu_item "${selected}" 1 "List routes" "list"
  ui_print_menu_item "${selected}" 2 "List certificates" "list-certs"
  ui_print_menu_item "${selected}" 3 "List zones" "list-zones"
  ui_print_menu_item "${selected}" 4 "Status for a domain" "status"
  ui_print_menu_item "${selected}" 5 "Check health for a domain" "check"
  ui_print_menu_item "${selected}" 6 "Logs for a domain" "logs"
  ui_print_menu_item "${selected}" 7 "Get raw route row" "get"
  printf '\n%sChange Routes%s\n' "${COLOR_BOLD}" "${COLOR_RESET}" >&2
  ui_print_menu_item "${selected}" 8 "Add a domain" "add"
  ui_print_menu_item "${selected}" 9 "Set upstream target" "set-target"
  ui_print_menu_item "${selected}" 10 "Clear upstream target" "clear-target"
  ui_print_menu_item "${selected}" 11 "Enable domain" "enable"
  ui_print_menu_item "${selected}" 12 "Disable domain" "disable"
  ui_print_menu_item "${selected}" 13 "Delete route" "delete"
  ui_print_menu_item "${selected}" 14 "Purge route and certificate" "purge"
  printf '\n%sOperations%s\n' "${COLOR_BOLD}" "${COLOR_RESET}" >&2
  ui_print_menu_item "${selected}" 15 "Issue certificate now" "issue-now"
  ui_print_menu_item "${selected}" 16 "Set Cloudflare zone token" "set-zone-token"
  ui_print_menu_item "${selected}" 17 "Sync now" "sync-now"
  ui_print_menu_item "${selected}" 18 "Open colored shell" "shell"
  ui_print_menu_item "${selected}" 19 "Help" "help"
  ui_print_menu_item "${selected}" 20 "Exit" "exit"
}

ui_print_menu_item() {
  local selected="$1"
  local index="$2"
  local label="$3"
  local action="$4"
  if [[ "${selected}" -eq "${index}" ]]; then
    printf '%s%s> %-31s%s %s[%s]%s\n' \
      "${COLOR_WHITE}${COLOR_BOLD}${COLOR_REVERSE}" "" "${label}" "${COLOR_RESET}" \
      "${COLOR_DIM}" "${action}" "${COLOR_RESET}" >&2
  else
    printf '  %-31s %s[%s]%s\n' "${label}" "${COLOR_DIM}" "${action}" "${COLOR_RESET}" >&2
  fi
}

ui_info() {
  printf '%s[i]%s %s\n' "${COLOR_CYAN}" "${COLOR_RESET}" "$*"
}

ui_success() {
  printf '%s[ok]%s %s\n' "${COLOR_GREEN}" "${COLOR_RESET}" "$*"
}

ui_warn() {
  printf '%s[warn]%s %s\n' "${COLOR_YELLOW}" "${COLOR_RESET}" "$*"
}

ui_error() {
  printf '%s[error]%s %s\n' "${COLOR_RED}" "${COLOR_RESET}" "$*" >&2
}

ui_section_title() {
  local title="$1"
  printf '%s%s%s\n' "${COLOR_BOLD}" "${title}" "${COLOR_RESET}"
}

ui_target_banner() {
  local kind="$1"
  local target="$2"
  ui_section_title "${kind}"
  printf '  target: %s\n\n' "${target}"
}

ui_pause() {
  [[ "${UI_INTERACTIVE}" -eq 1 ]] || return 0
  printf '\n'
  read -r -p "Press Enter to continue..." _ < /dev/tty
}

ui_has_tty() {
  [[ -t 2 && -r /dev/tty ]]
}

ui_read_key() {
  local key
  IFS= read -rsn1 key < /dev/tty || return 1
  if [[ "${key}" == $'\x1b' ]]; then
    local next rest
    IFS= read -rsn1 -t 0.05 next < /dev/tty || true
    if [[ "${next}" == "[" ]]; then
      IFS= read -rsn1 -t 0.05 rest < /dev/tty || true
      key+="${next}${rest}"
    else
      key+="${next}"
    fi
  fi
  printf '%s' "${key}"
}

ui_menu_index_for_action() {
  case "${1:-}" in
    20|overview) printf '%s' "0" ;;
    1|list|routes) printf '%s' "1" ;;
    2|list-certs|certs) printf '%s' "2" ;;
    3|list-zones|zones) printf '%s' "3" ;;
    4|status) printf '%s' "4" ;;
    5|check) printf '%s' "5" ;;
    6|logs) printf '%s' "6" ;;
    7|get) printf '%s' "7" ;;
    8|add) printf '%s' "8" ;;
    9|set-target|target) printf '%s' "9" ;;
    10|clear-target) printf '%s' "10" ;;
    11|enable) printf '%s' "11" ;;
    12|disable) printf '%s' "12" ;;
    13|delete) printf '%s' "13" ;;
    14|purge) printf '%s' "14" ;;
    15|issue-now|issue) printf '%s' "15" ;;
    16|set-zone-token|zone-token|token) printf '%s' "16" ;;
    17|sync-now|sync) printf '%s' "17" ;;
    18|shell) printf '%s' "18" ;;
    19|help) printf '%s' "19" ;;
    0|q|quit|exit) printf '%s' "20" ;;
    *) printf '%s' "0" ;;
  esac
}

ui_menu_pick_action() {
  local selected key mode rendered=0
  selected="$(ui_menu_index_for_action "${1:-}")"
  while true; do
    if [[ "${rendered}" -eq 0 ]]; then
      mode="$(get_config_mode)"
      ui_print_header "${mode}"
      ui_print_dashboard_summary "${mode}"
      ui_cursor_save
      rendered=1
    else
      ui_cursor_restore
      ui_clear_to_end
    fi
    ui_print_menu "${selected}"
    printf '\n' >&2
    key="$(ui_read_key)" || return 1
    case "${key}" in
      $'\x1b[A'|k)
        selected=$(( (selected - 1 + ${#DOMAIN_MENU_ACTIONS[@]}) % ${#DOMAIN_MENU_ACTIONS[@]} ))
        ;;
      $'\x1b[B'|j)
        selected=$(( (selected + 1) % ${#DOMAIN_MENU_ACTIONS[@]} ))
        ;;
      ""|$'\n'|$'\r')
        printf '%s' "${DOMAIN_MENU_ACTIONS[selected]}"
        return 0
        ;;
    esac
  done
}

ui_trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

ui_prompt() {
  local prompt="$1"
  local default_value="${2:-}"
  local value
  if [[ -n "${default_value}" ]]; then
    read -r -p "${prompt} [${default_value}]: " value < /dev/tty || return 1
    if [[ -z "${value}" ]]; then
      value="${default_value}"
    fi
  else
    read -r -p "${prompt}: " value < /dev/tty || return 1
  fi
  ui_trim "${value}"
}

ui_prompt_optional() {
  local prompt="$1"
  local default_value="${2:-}"
  local value
  if [[ -n "${default_value}" ]]; then
    read -r -p "${prompt} [${default_value}] (blank to clear): " value < /dev/tty || return 1
    if [[ -z "${value}" ]]; then
      printf '%s' ""
      return 0
    fi
  else
    read -r -p "${prompt} (blank to leave empty): " value < /dev/tty || return 1
  fi
  ui_trim "${value}"
}

ui_confirm() {
  local prompt="$1"
  if ui_has_tty; then
    local selected
    selected="$(ui_menu_pick_yes_no "${prompt}" "No" "Yes" "No")" || return 1
    [[ "${selected}" == "Yes" ]]
    return $?
  fi
  local answer
  read -r -p "${prompt} [y/N]: " answer < /dev/tty || return 1
  [[ "${answer}" == "y" || "${answer}" == "Y" ]]
}

ui_menu_pick_yes_no() {
  local title="$1"
  local default_label="$2"
  local yes_label="$3"
  local no_label="$4"
  local selected=1 key rendered=0
  if [[ "${default_label}" == "${yes_label}" ]]; then
    selected=0
  fi
  while true; do
    if [[ "${rendered}" -eq 0 ]]; then
      ui_clear_screen
      printf '%s[%s]%s %sssl-service domain manager%s\n' "$(ui_mode_color "$(get_config_mode)")" "$(shell_prompt_label "$(get_config_mode)")" "${COLOR_RESET}" "${COLOR_BOLD}" "${COLOR_RESET}" >&2
      ui_cursor_save
      rendered=1
    else
      ui_cursor_restore
      ui_clear_to_end
    fi
    printf '%s%s%s\n\n' "${COLOR_BOLD}" "${title}" "${COLOR_RESET}" >&2
    if [[ "${selected}" -eq 0 ]]; then
      printf '%s%s> %s%s\n' "${COLOR_WHITE}${COLOR_BOLD}${COLOR_REVERSE}" "" "${yes_label}" "${COLOR_RESET}" >&2
      printf '  %s\n' "${no_label}" >&2
    else
      printf '  %s\n' "${yes_label}" >&2
      printf '%s%s> %s%s\n' "${COLOR_WHITE}${COLOR_BOLD}${COLOR_REVERSE}" "" "${no_label}" "${COLOR_RESET}" >&2
    fi
    key="$(ui_read_key)" || return 1
    case "${key}" in
      $'\x1b[A'|$'\x1b[B'|j|k)
        selected=$((1 - selected))
        ;;
      ""|$'\n'|$'\r')
        if [[ "${selected}" -eq 0 ]]; then
          printf '%s' "${yes_label}"
        else
          printf '%s' "${no_label}"
        fi
        return 0
        ;;
    esac
  done
}

ui_confirm_exact() {
  local prompt="$1"
  local expected="$2"
  local answer
  read -r -p "${prompt} [type '${expected}']: " answer < /dev/tty || return 1
  [[ "$(ui_trim "${answer}")" == "${expected}" ]]
}

ui_domain_input() {
  local prompt="${1:-Domain}"
  local value
  value="$(ui_prompt "${prompt}" "${LAST_DOMAIN}")" || return 1
  [[ -n "${value}" ]] || return 1
  value="$(normalize_domain "${value}")"
  LAST_DOMAIN="${value}"
  printf '%s' "${value}"
}

ui_zone_target_input() {
  local value
  value="$(ui_prompt "Domain or zone" "${LAST_ZONE_TARGET}")" || return 1
  [[ -n "${value}" ]] || return 1
  LAST_ZONE_TARGET="${value}"
  printf '%s' "${value}"
}

ui_upstream_input() {
  local prompt="${1:-Upstream target}"
  local value
  value="$(ui_prompt "${prompt}" "${LAST_UPSTREAM}")" || return 1
  [[ -n "${value}" ]] || return 1
  LAST_UPSTREAM="${value}"
  printf '%s' "${value}"
}

ui_show_output() {
  local status="$1"
  local output="$2"
  if [[ -n "${output}" ]]; then
    printf '%s\n' "${output}"
  fi
  if [[ "${status}" -eq 0 ]]; then
    ui_success "command completed"
  else
    ui_error "command failed with exit code ${status}"
  fi
}

ui_show_route_context() {
  local domain="$1"
  local details_json python_bin
  python_bin="$(resolve_python)"
  details_json="$(get_domain_details_json "${domain}")"
  DETAILS_JSON="${details_json}" "${python_bin}" - <<'PY'
from __future__ import annotations

import json
import os

payload = json.loads(os.environ["DETAILS_JSON"])
details = payload.get("details", {})
if not payload.get("ok"):
  print(f"Current Route\n  lookup: unavailable\n  reason: {payload.get('error', '')}\n")
  raise SystemExit(0)

upstream = details.get("upstream_target") or "(certificate-only)"
enabled = details.get("enabled")
certificate = details.get("certificate_status") or "-"
updated_at = details.get("updated_at") or "-"
print("Current Route")
print(f"  domain: {details.get('domain') or '-'}")
print(f"  enabled: {enabled}")
print(f"  upstream: {upstream}")
print(f"  certificate: {certificate}")
print(f"  updated_at: {updated_at}")
print()
PY
}

ui_pretty_status_output() {
  local output="$1"
  local status="${2:-0}"
  local python_bin
  python_bin="$(resolve_python)"
  STATUS_TEXT="${output}" STATUS_CODE="${status}" "${python_bin}" - <<'PY'
from __future__ import annotations

import os

text = os.environ["STATUS_TEXT"]
status_code = int(os.environ["STATUS_CODE"])
rows = {}
for line in text.splitlines():
  if ":" not in line:
    continue
  key, value = line.split(":", 1)
  rows[key.strip()] = value.strip()

green = "\033[32m"
yellow = "\033[33m"
red = "\033[31m"
cyan = "\033[36m"
bold = "\033[1m"
reset = "\033[0m"

def colorize(value: str, *, yes_words: set[str] | None = None) -> str:
  yes_words = yes_words or {"yes", "active", "true", "readwrite"}
  low = value.lower()
  if low in yes_words:
    return f"{green}{value}{reset}"
  if low in {"no", "false", "inactive", "readonly"}:
    return f"{yellow}{value}{reset}"
  if low:
    return value
  return f"{red}(empty){reset}"

domain = rows.get("domain", "")
print(f"{bold}Domain Summary{reset}")
print(f"  domain: {domain or '(unknown)'}")
print(f"  node_mode: {colorize(rows.get('current_node_mode', ''))}")
print(f"  enabled: {colorize(rows.get('enabled', ''), yes_words={'true'})}")
print(f"  upstream: {rows.get('upstream_target', '') or '(certificate-only)'}")
print(f"  certificate: {colorize(rows.get('certificate_status', ''), yes_words={'active'})}")
print(f"  points_to_this_host: {colorize(rows.get('points_to_this_host', ''), yes_words={'yes'})}")
print(f"  zone_token_present: {colorize(rows.get('zone_token_present', ''), yes_words={'yes'})}")
print(f"  command_status: {'ok' if status_code == 0 else f'failed ({status_code})'}")

if rows.get("certificate_not_after"):
  print(f"{cyan}certificate_not_after:{reset} {rows['certificate_not_after']}")
if rows.get("updated_at"):
  print(f"{cyan}updated_at:{reset} {rows['updated_at']}")
if rows.get("dns_ipv4") or rows.get("dns_ipv6"):
  print(f"{cyan}dns:{reset} v4={rows.get('dns_ipv4', '') or '-'} v6={rows.get('dns_ipv6', '') or '-'}")
if rows.get("database_error"):
  print(f"{red}database_error:{reset} {rows['database_error']}")
if rows.get("dns_error"):
  print(f"{red}dns_error:{reset} {rows['dns_error']}")
if rows.get("last_error"):
  print(f"{red}last_error:{reset} {rows['last_error']}")

print()
print(f"{bold}Raw Output{reset}")
print(text)
PY
}

ui_pretty_check_output() {
  local output="$1"
  local status="${2:-0}"
  local python_bin
  python_bin="$(resolve_python)"
  CHECK_TEXT="${output}" STATUS_CODE="${status}" "${python_bin}" - <<'PY'
from __future__ import annotations

import os

text = os.environ["CHECK_TEXT"]
status_code = int(os.environ["STATUS_CODE"])
green = "\033[32m"
yellow = "\033[33m"
red = "\033[31m"
bold = "\033[1m"
reset = "\033[0m"

print(f"{bold}Health Checks{reset}")
for line in text.splitlines():
  if ":" not in line:
    print(line)
    continue
  key, rest = line.split(":", 1)
  rest = rest.strip()
  color = green if rest.startswith("ok") else red if rest.startswith("fail") else yellow
  print(f"  {key.strip()}: {color}{rest}{reset}")
if status_code != 0:
  print(f"  command_status: {red}failed ({status_code}){reset}")
print()
print(f"{bold}Raw Output{reset}")
print(text)
PY
}

ui_pretty_overview_output() {
  local output="$1"
  local python_bin
  python_bin="$(resolve_python)"
  OVERVIEW_TEXT="${output}" "${python_bin}" - <<'PY'
from __future__ import annotations

import os

text = os.environ["OVERVIEW_TEXT"]
rows = {}
for line in text.splitlines():
  if ":" not in line:
    continue
  key, value = line.split(":", 1)
  rows[key.strip()] = value.strip()

green = "\033[32m"
yellow = "\033[33m"
red = "\033[31m"
blue = "\033[34m"
bold = "\033[1m"
reset = "\033[0m"

def colorize_service(value: str) -> str:
  if value in {"active", "running"}:
    return f"{green}{value}{reset}"
  if value in {"inactive", "failed", "activating", "deactivating", "stopped"}:
    return f"{yellow}{value}{reset}"
  if value in {"bus-denied", "no-systemctl", "no-service-manager", "not-installed"}:
    return f"{red}{value}{reset}"
  return value or f"{red}(empty){reset}"

mode = rows.get("mode", "")
mode_color = red if mode == "readwrite" else blue if mode == "readonly" else yellow
print(f"{bold}Node Overview{reset}")
print(f"  mode: {mode_color}{mode or '(unknown)'}{reset}")
print(f"  config_path: {rows.get('config_path', '') or '(missing)'}")
print(f"  container_status: {colorize_service(rows.get('container_status', ''))}")
print(f"  proxy_runtime: {colorize_service(rows.get('proxy_runtime', ''))}")
print(f"  is_root: {green if rows.get('is_root') == 'yes' else yellow}{rows.get('is_root', '(unknown)')}{reset}")
print(f"  last_domain: {rows.get('last_domain', '') or '-'}")
print(f"  last_upstream: {rows.get('last_upstream', '') or '-'}")
print(f"  last_zone_target: {rows.get('last_zone_target', '') or '-'}")
print()
print(f"{bold}Raw Output{reset}")
print(text)
PY
}

ui_pretty_route_rows_output() {
  local output="$1"
  local status="${2:-0}"
  local kind="${3:-routes}"
  local python_bin
  python_bin="$(resolve_python)"
  ROWS_TEXT="${output}" STATUS_CODE="${status}" ROWS_KIND="${kind}" "${python_bin}" - <<'PY'
from __future__ import annotations

import os
import shlex

text = os.environ["ROWS_TEXT"]
status_code = int(os.environ["STATUS_CODE"])
kind = os.environ["ROWS_KIND"]

green = "\033[32m"
yellow = "\033[33m"
red = "\033[31m"
bold = "\033[1m"
reset = "\033[0m"

if status_code != 0:
  title = {
    "routes": "Routes",
    "certs": "Certificates",
    "zones": "Zones",
  }.get(kind, kind.title())
  print(f"{bold}{title}{reset}")
  print(f"  command_status: {red}failed ({status_code}){reset}")
  if text:
    first = text.splitlines()[0]
    print(f"  error: {red}{first}{reset}")
  print()
  print(f"{bold}Raw Output{reset}")
  print(text)
  raise SystemExit(0)

lines = [line.strip() for line in text.splitlines() if line.strip()]
if lines == ["no rows"] or not lines:
  print(f"{bold}{kind.title()}{reset}")
  print("  no rows")
  print()
  print(f"{bold}Raw Output{reset}")
  print(text)
  raise SystemExit(0)

rows: list[dict[str, str]] = []
for line in lines:
  parsed: dict[str, str] = {}
  for token in shlex.split(line):
    if "=" not in token:
      continue
    key, value = token.split("=", 1)
    parsed[key] = value
  rows.append(parsed)

title = {
  "routes": "Routes",
  "certs": "Certificates",
  "zones": "Zones",
}.get(kind, kind.title())
print(f"{bold}{title}{reset}")

if kind == "zones":
  for row in rows:
    print(f"  {row.get('zone_name', '-')}")
    print(f"    provider: {row.get('provider', '-')}")
    print(f"    zone_id: {row.get('zone_id', '-')}")
    print(f"    updated_at: {row.get('updated_at', '-')}")
else:
  for row in rows:
    name = row.get("domain", "-")
    cert = row.get("certificate_status", "-")
    enabled = row.get("enabled", "-")
    upstream = row.get("upstream_target", "") or "(certificate-only)"
    cert_colored = f"{green}{cert}{reset}" if cert == "active" else f"{yellow}{cert}{reset}" if cert not in {"-", ""} else "-"
    enabled_colored = f"{green}{enabled}{reset}" if enabled == "True" else f"{yellow}{enabled}{reset}" if enabled != "-" else "-"
    summary_bits: list[str] = []
    if kind == "routes":
      summary_bits.append(f"enabled={enabled_colored}")
      summary_bits.append(f"upstream={upstream}")
    summary_bits.append(f"cert={cert_colored}")
    if row.get("certificate_not_after"):
      summary_bits.append(f"not_after={row['certificate_not_after']}")
    if row.get("retry_after"):
      summary_bits.append(f"retry_after={row['retry_after']}")
    if row.get("updated_at"):
      summary_bits.append(f"updated_at={row['updated_at']}")
    print(f"  {name}")
    print(f"    {' | '.join(summary_bits)}")
    if row.get("last_error"):
      print(f"    last_error: {red}{row['last_error']}{reset}")
print()
PY
}

ui_pretty_logs_output() {
  local output="$1"
  local status="${2:-0}"
  local domain="${3:-}"
  local python_bin
  python_bin="$(resolve_python)"
  LOG_TEXT="${output}" STATUS_CODE="${status}" LOG_DOMAIN="${domain}" "${python_bin}" - <<'PY'
from __future__ import annotations

import os

text = os.environ["LOG_TEXT"]
status_code = int(os.environ["STATUS_CODE"])
domain = os.environ["LOG_DOMAIN"]
red = "\033[31m"
yellow = "\033[33m"
cyan = "\033[36m"
bold = "\033[1m"
reset = "\033[0m"

print(f"{bold}Logs{reset}")
print(f"  domain: {domain or '(unknown)'}")
if status_code != 0:
  print(f"  command_status: {red}failed ({status_code}){reset}")
  if text:
    print(f"  error: {red}{text.splitlines()[0]}{reset}")
else:
  lines = [line for line in text.splitlines() if line.strip()]
  if lines:
    print(f"  matches: {len(lines)}")
    print(f"  latest: {cyan}{lines[-1][:80]}{'...' if len(lines[-1]) > 80 else ''}{reset}")
  else:
    print(f"  status: {yellow}no matching log lines found{reset}")
print()
print(f"{bold}Raw Output{reset}")
print(text)
PY
}

ui_run_capture() {
  local output status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  UI_LAST_STATUS="${status}"
  ui_show_output "${status}" "${output}"
  return 0
}

ui_run_capture_pretty() {
  local formatter="$1"
  local formatter_arg="${2:-}"
  shift
  shift
  local output status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  UI_LAST_STATUS="${status}"
  if [[ -n "${formatter}" ]]; then
    output="$("${formatter}" "${output}" "${status}" "${formatter_arg}")"
  fi
  ui_show_output "${status}" "${output}"
  return 0
}

service_state_summary() {
  local _service="${1:-ssl-service}"
  local output status
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 && [[ -f "${COMPOSE_PATH}" ]]; then
    set +e
    output="$(docker compose -f "${COMPOSE_PATH}" ps --status running --services 2>/dev/null)"
    status=$?
    set -e
    if [[ "${status}" -eq 0 ]] && printf '%s\n' "${output}" | grep -Fxq "ssl-service"; then
      printf '%s' "running"
      return 0
    fi
    set +e
    output="$(docker compose -f "${COMPOSE_PATH}" ps --services 2>/dev/null)"
    status=$?
    set -e
    if [[ "${status}" -eq 0 ]] && printf '%s\n' "${output}" | grep -Fxq "ssl-service"; then
      printf '%s' "stopped"
      return 0
    fi
    printf '%s' "not-installed"
    return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    printf '%s' "no-service-manager"
    return 0
  fi
  set +e
  output="$(systemctl is-active "${_service}" 2>&1)"
  status=$?
  set -e
  output="$(ui_trim "${output}")"
  if [[ "${status}" -eq 0 ]]; then
    printf '%s' "${output:-active}"
    return 0
  fi
  case "${output}" in
    *"Failed to connect to bus"*|*"Operation not permitted"*)
      printf '%s' "bus-denied"
      ;;
    inactive|failed|activating|deactivating)
      printf '%s' "${output}"
      ;;
    *)
      printf '%s' "${output:-unknown}"
      ;;
  esac
}

interactive_offer_sync_now() {
  if [[ "${EUID}" -ne 0 ]]; then
    ui_info "run as root if you want to use sync-now immediately"
    return 0
  fi
  if ui_confirm "Run sync-now on this node now?"; then
    ui_run_capture sync_now
  fi
}

ui_run_mutation() {
  local summary="$1"
  local followup="${2:-}"
  shift
  shift
  ui_run_capture "$@"
  if [[ "${UI_LAST_STATUS}" -eq 0 ]]; then
    DEFAULT_MENU_ACTION="4"
    ui_info "${summary}"
    if [[ -n "${followup}" ]]; then
      ui_info "next: ${followup}"
    fi
    interactive_offer_sync_now
  fi
}

interactive_add_domain() {
  local domain upstream
  domain="$(ui_domain_input "New domain")" || { ui_warn "cancelled"; return 0; }
  LAST_DOMAIN="${domain}"
  ui_target_banner "Add Domain" "${domain}"
  ui_show_route_context "${domain}"
  ensure_zone_token_for_domain "${domain}" || return 0
  upstream="$(ui_prompt_optional "Upstream target" "${LAST_UPSTREAM}")" || { ui_warn "cancelled"; return 0; }
  if [[ -n "${upstream}" ]]; then
    LAST_UPSTREAM="${upstream}"
    ui_run_mutation \
      "route created with upstream target" \
      "run menu 4 for status, menu 5 for checks, then confirm DNS points to this host" \
      run_db_tool add "${domain}" "${upstream}"
  else
    ui_run_mutation \
      "created certificate-only route" \
      "run menu 4 for status and menu 15 if you need to re-issue now" \
      run_db_tool add "${domain}"
  fi
}

interactive_set_target() {
  local domain upstream
  domain="$(ui_domain_input)" || { ui_warn "cancelled"; return 0; }
  LAST_DOMAIN="${domain}"
  ui_target_banner "Set Upstream Target" "${domain}"
  ui_show_route_context "${domain}"
  ensure_zone_token_for_domain "${domain}" || return 0
  upstream="$(ui_upstream_input)" || { ui_warn "cancelled"; return 0; }
  LAST_UPSTREAM="${upstream}"
  ui_run_mutation \
    "upstream updated; readonly nodes should pick this up on their next poll" \
    "run menu 4 for status, menu 6 for logs, and sync-now if you want this node refreshed immediately" \
    run_db_tool set-target "${domain}" "${upstream}"
}

interactive_clear_target() {
  local domain
  domain="$(ui_domain_input)" || { ui_warn "cancelled"; return 0; }
  LAST_DOMAIN="${domain}"
  ui_target_banner "Clear Upstream Target" "${domain}"
  ui_show_route_context "${domain}"
  ui_confirm "Clear upstream target for ${domain}?" || { ui_warn "cancelled"; return 0; }
  ui_run_mutation \
    "route is now certificate-only" \
    "run menu 4 to confirm upstream is empty and certificate state is still healthy" \
    run_db_tool clear-target "${domain}"
}

interactive_enable_disable() {
  local action="$1"
  local domain
  domain="$(ui_domain_input)" || { ui_warn "cancelled"; return 0; }
  LAST_DOMAIN="${domain}"
  ui_target_banner "${action^} Domain" "${domain}"
  ui_show_route_context "${domain}"
  ui_confirm "${action^} ${domain}?" || { ui_warn "cancelled"; return 0; }
  ui_run_mutation \
    "route updated" \
    "run menu 4 for status and menu 1 to review the route list" \
    run_db_tool "${action}" "${domain}"
}

interactive_delete_like() {
  local action="$1"
  local domain description
  domain="$(ui_domain_input)" || { ui_warn "cancelled"; return 0; }
  LAST_DOMAIN="${domain}"
  ui_target_banner "${action^} Domain" "${domain}"
  ui_show_route_context "${domain}"
  if [[ "${action}" == "purge" ]]; then
    description="delete the route and certificate records"
  else
    description="delete the route record"
  fi
  ui_warn "This will ${description} for ${domain}."
  ui_confirm_exact "Confirm destructive action for ${domain}" "${domain}" || { ui_warn "cancelled"; return 0; }
  ui_run_mutation "destructive action completed" run_db_tool "${action}" "${domain}"
}

interactive_issue_now() {
  local mode domain
  mode="$(get_config_mode)"
  if [[ "${mode}" != "readwrite" ]]; then
    ui_warn "issue-now is only available on readwrite nodes"
    return 0
  fi
  domain="$(ui_domain_input)" || { ui_warn "cancelled"; return 0; }
  LAST_DOMAIN="${domain}"
  ui_target_banner "Issue Certificate Now" "${domain}"
  ui_show_route_context "${domain}"
  preflight_sync_now || return 0
  ui_run_capture run_db_tool issue-now "${domain}"
  if [[ "${UI_LAST_STATUS}" -eq 0 ]]; then
    ui_run_capture sync_now
    ui_info "certificate issuance has been queued and local controller restarted"
  fi
}

interactive_set_zone_token() {
  local target
  target="$(ui_zone_target_input)" || { ui_warn "cancelled"; return 0; }
  LAST_ZONE_TARGET="${target}"
  ui_target_banner "Set Zone Token" "${target}"
  ensure_zone_token_for_domain "${target}" 1 || return 0
  ui_success "zone token updated"
}

interactive_sync_now() {
  preflight_sync_now || return 0
  ui_run_capture sync_now
}

node_overview_command() {
  local mode config_path runtime_status proxy_status python_bin
  mode="$(get_config_mode)"
  config_path="$(resolve_config_path)"
  python_bin="$(resolve_python)"
  runtime_status="$(service_state_summary ssl-service)"
  proxy_status="$(service_state_summary ssl-service)"
  "${python_bin}" - <<PY
from __future__ import annotations

mode = ${mode@Q}
config_path = ${config_path@Q}
runtime_status = ${runtime_status@Q}
proxy_status = ${proxy_status@Q}
last_domain = ${LAST_DOMAIN@Q}
last_upstream = ${LAST_UPSTREAM@Q}
last_zone_target = ${LAST_ZONE_TARGET@Q}
is_root = ${EUID}

print(f"mode: {mode}")
print(f"config_path: {config_path}")
print(f"container_status: {runtime_status}")
print(f"proxy_runtime: {proxy_status}")
print(f"is_root: {'yes' if is_root == 0 else 'no'}")
print(f"last_domain: {last_domain}")
print(f"last_upstream: {last_upstream}")
print(f"last_zone_target: {last_zone_target}")
PY
}

interactive_menu() {
  local mode choice domain
  mode="$(get_config_mode)"
  UI_INTERACTIVE=1

  while true; do
    choice="$(ui_menu_pick_action "${DEFAULT_MENU_ACTION}")" || return 0

    case "${choice}" in
      overview)
        DEFAULT_MENU_ACTION="20"
        ui_run_capture_pretty ui_pretty_overview_output "" node_overview_command
        ;;
      list)
        DEFAULT_MENU_ACTION="1"
        ui_run_capture_pretty ui_pretty_route_rows_output routes run_db_tool list
        ;;
      list-certs)
        DEFAULT_MENU_ACTION="2"
        ui_run_capture_pretty ui_pretty_route_rows_output certs run_db_tool list-certs
        ;;
      list-zones)
        DEFAULT_MENU_ACTION="3"
        ui_run_capture_pretty ui_pretty_route_rows_output zones run_db_tool list-zones
        ;;
      status)
        domain="$(ui_domain_input)" || { ui_warn "cancelled"; ui_pause; continue; }
        LAST_DOMAIN="${domain}"
        DEFAULT_MENU_ACTION="4"
        ui_target_banner "Status" "${domain}"
        ui_run_capture_pretty ui_pretty_status_output "" status_command "${domain}"
        ;;
      check)
        domain="$(ui_domain_input)" || { ui_warn "cancelled"; ui_pause; continue; }
        LAST_DOMAIN="${domain}"
        DEFAULT_MENU_ACTION="5"
        ui_target_banner "Check" "${domain}"
        ui_run_capture_pretty ui_pretty_check_output "" check_command "${domain}"
        ;;
      logs)
        domain="$(ui_domain_input)" || { ui_warn "cancelled"; ui_pause; continue; }
        LAST_DOMAIN="${domain}"
        DEFAULT_MENU_ACTION="6"
        ui_target_banner "Logs" "${domain}"
        ui_run_capture_pretty ui_pretty_logs_output "${domain}" logs_command "${domain}"
        ;;
      get)
        domain="$(ui_domain_input)" || { ui_warn "cancelled"; ui_pause; continue; }
        LAST_DOMAIN="${domain}"
        DEFAULT_MENU_ACTION="7"
        ui_target_banner "Get Route" "${domain}"
        ui_run_capture run_db_tool get "${domain}"
        ;;
      add) DEFAULT_MENU_ACTION=""; interactive_add_domain ;;
      set-target) DEFAULT_MENU_ACTION=""; interactive_set_target ;;
      clear-target) DEFAULT_MENU_ACTION=""; interactive_clear_target ;;
      enable) DEFAULT_MENU_ACTION=""; interactive_enable_disable enable ;;
      disable) DEFAULT_MENU_ACTION=""; interactive_enable_disable disable ;;
      delete) DEFAULT_MENU_ACTION=""; interactive_delete_like delete ;;
      purge) DEFAULT_MENU_ACTION=""; interactive_delete_like purge ;;
      issue-now) DEFAULT_MENU_ACTION=""; interactive_issue_now ;;
      set-zone-token) DEFAULT_MENU_ACTION=""; interactive_set_zone_token ;;
      sync-now) DEFAULT_MENU_ACTION=""; interactive_sync_now ;;
      shell) shell_command ;;
      help) usage ;;
      exit)
        return 0
        ;;
      *)
        ui_warn "invalid choice"
        ;;
    esac
    ui_pause
  done
}

shell_command() {
  local bash_bin rcfile
  bash_bin="$(command -v bash)"
  [[ -n "${bash_bin}" ]] || fail "bash is required"
  rcfile="$(mktemp)"
  trap 'rm -f "${rcfile}"' EXIT
  prompt_init_command > "${rcfile}"
  exec "${bash_bin}" --rcfile "${rcfile}" -i
}

resolve_config_path() {
  if [[ -n "${SSL_PROXY_CONFIG:-}" ]]; then
    [[ -f "${SSL_PROXY_CONFIG}" ]] || fail "config not found: ${SSL_PROXY_CONFIG}"
    printf '%s' "${SSL_PROXY_CONFIG}"
    return 0
  fi

  local candidate
  for candidate in "${CONFIG_CANDIDATES[@]}"; do
    if [[ -f "${candidate}" ]]; then
      printf '%s' "${candidate}"
      return 0
    fi
  done

  fail "could not find config.yaml"
}

resolve_python() {
  if [[ -x "${DEPLOY_DIR}/.tools-venv/bin/python" ]]; then
    printf '%s' "${DEPLOY_DIR}/.tools-venv/bin/python"
    return 0
  fi
  if [[ -x "${DEPLOY_DIR}/.venv/bin/python" ]]; then
    printf '%s' "${DEPLOY_DIR}/.venv/bin/python"
    return 0
  fi
  if [[ -x "${REPO_DIR}/.tools-venv/bin/python" ]]; then
    printf '%s' "${REPO_DIR}/.tools-venv/bin/python"
    return 0
  fi
  if [[ -x "${REPO_DIR}/.venv/bin/python" ]]; then
    printf '%s' "${REPO_DIR}/.venv/bin/python"
    return 0
  fi
  if [[ -x "${LEGACY_DEPLOY_DIR}/.tools-venv/bin/python" ]]; then
    printf '%s' "${LEGACY_DEPLOY_DIR}/.tools-venv/bin/python"
    return 0
  fi
  if [[ -x "${LEGACY_DEPLOY_DIR}/.venv/bin/python" ]]; then
    printf '%s' "${LEGACY_DEPLOY_DIR}/.venv/bin/python"
    return 0
  fi
  command -v python3 >/dev/null 2>&1 || fail "python3 is required"
  printf '%s' "python3"
}

get_config_mode() {
  local python_bin config_path
  python_bin="$(resolve_python)"
  config_path="$(resolve_config_path)"

  SSL_PROXY_CONFIG="${config_path}" "${python_bin}" - <<'PY'
from __future__ import annotations

import os
from pathlib import Path

import yaml

data = yaml.safe_load(Path(os.environ["SSL_PROXY_CONFIG"]).read_text()) or {}
mode = str(data["mode"]).strip().lower()
if mode not in {"readonly", "readwrite"}:
  raise SystemExit(f"unsupported mode: {data['mode']}")
print(mode)
PY
}

ensure_zone_token_for_domain() {
  [[ $# -ge 1 ]] || fail "domain is required"
  local domain token output force_prompt="${2:-0}" zone_lookup_output
  domain="$(normalize_domain "$1")"

  if [[ "${force_prompt}" -ne 1 ]]; then
    set +e
    zone_lookup_output="$(run_db_tool get-zone-for-domain "${domain}" 2>&1)"
    local zone_lookup_status=$?
    set -e
    if [[ "${zone_lookup_status}" -eq 0 ]]; then
      return 0
    fi
    if [[ "${UI_INTERACTIVE}" -eq 1 ]] && [[ "${zone_lookup_output}" == *"database connection failed:"* ]]; then
      ui_error "could not verify existing zone token: ${zone_lookup_output}"
      return 1
    fi
  fi

  while true; do
    if ! read -r -s -p "Cloudflare API token for zone managing ${domain}: " token < /dev/tty; then
      printf '\n'
      ui_warn "token entry cancelled"
      return 1
    fi
    printf '\n'
    token="$(ui_trim "${token}")"
    [[ -n "${token}" ]] || {
      if [[ "${UI_INTERACTIVE}" -eq 1 ]]; then
        ui_warn "token is required"
        return 1
      fi
      log "value is required"
      continue
    }
    if output="$(run_db_tool upsert-zone-token "${domain}" "${token}" 2>&1)"; then
      printf '%s\n' "${output}"
      return 0
    fi
    printf '%s\n' "${output}" >&2
    [[ "${UI_INTERACTIVE}" -eq 1 ]] && return 1
  done
}

normalize_domain() {
  [[ $# -ge 1 ]] || fail "domain is required"
  local python_bin
  python_bin="$(resolve_python)"
  "${python_bin}" - "$1" <<'PY'
from __future__ import annotations

import sys


def validate_domain(domain: str) -> str:
  candidate = domain.strip().lower().rstrip(".")
  if not candidate:
    raise SystemExit("domain is required")
  wildcard = candidate.startswith("*.")
  if wildcard:
    raise SystemExit("wildcard domains are not supported")
  base = candidate[2:] if wildcard else candidate
  labels = base.split(".")
  if len(labels) < 2:
    raise SystemExit("domain must contain at least one dot")
  for label in labels:
    if not label or len(label) > 63:
      raise SystemExit(f"invalid domain label: {label!r}")
    if label.startswith("-") or label.endswith("-"):
      raise SystemExit(f"invalid domain label: {label!r}")
    if not all(ch.isalnum() or ch == "-" for ch in label):
      raise SystemExit(f"invalid domain label: {label!r}")
  print(candidate)


if __name__ == "__main__":
  if len(sys.argv) < 2:
    raise SystemExit("domain is required")
  validate_domain(sys.argv[1])
PY
}

get_domain_details() {
  local python_bin config_path
  python_bin="$(resolve_python)"
  config_path="$(resolve_config_path)"

  SSL_PROXY_CONFIG="${config_path}" \
  "${python_bin}" - "$@" <<'PY'
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import psycopg
import yaml
from psycopg.rows import dict_row


def load_dsn(config_path: str) -> str:
  data = yaml.safe_load(Path(config_path).read_text()) or {}
  return data["postgres"]["dsn"]


def candidate_zones(name: str) -> list[str]:
  labels = name.strip().lower().rstrip(".").split(".")
  return [".".join(labels[index:]) for index in range(len(labels) - 2, -1, -1) if len(labels[index:]) >= 2]


def cloudflare_request(token: str, method: str, path: str, payload: dict | None = None) -> dict:
  request = urllib.request.Request(
    f"https://api.cloudflare.com/client/v4{path}",
    method=method,
    headers={
      "Authorization": f"Bearer {token}",
      "Content-Type": "application/json",
    },
    data=None if payload is None else json.dumps(payload).encode("utf-8"),
  )
  try:
    with urllib.request.urlopen(request, timeout=15) as response:
      return json.loads(response.read().decode("utf-8"))
  except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", errors="replace")
    raise SystemExit(f"Cloudflare API request failed: HTTP {exc.code}: {body}") from exc
  except urllib.error.URLError as exc:
    raise SystemExit(f"Cloudflare API request failed: {exc}") from exc


def discover_cloudflare_zone(domain_or_zone: str, token: str) -> tuple[str, str]:
  for candidate in candidate_zones(domain_or_zone):
    query = urllib.parse.urlencode({"name": candidate, "per_page": 1})
    payload = cloudflare_request(token, "GET", f"/zones?{query}")
    if payload.get("success") and payload.get("result"):
      zone = payload["result"][0]
      return str(zone["name"]).lower(), str(zone["id"])
  raise SystemExit(f"could not find a Cloudflare zone for: {domain_or_zone}")


def validate_cloudflare_zone_token(domain_or_zone: str, token: str) -> tuple[str, str]:
  zone_name, zone_id = discover_cloudflare_zone(domain_or_zone, token)
  suffix = hex(int(time.time() * 1000000))[2:]
  record_name = f"_ssl-proxy-token-check-{suffix}.{zone_name}"
  payload = cloudflare_request(
    token,
    "POST",
    f"/zones/{zone_id}/dns_records",
    {
      "type": "TXT",
      "name": record_name,
      "content": f"ssl-proxy-verify-{suffix}",
      "ttl": 60,
    },
  )
  if not payload.get("success") or not payload.get("result"):
    raise SystemExit(f"Cloudflare token could not create a DNS record for zone: {zone_name}")
  record_id = str(payload["result"]["id"])
  try:
    cloudflare_request(token, "DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
  except SystemExit as exc:
    raise SystemExit(f"Cloudflare token validation partially failed: created a test record but could not delete it: {exc}") from exc
  return zone_name, zone_id


def validate_domain(domain: str) -> str:
  candidate = domain.strip().lower().rstrip(".")
  if not candidate:
    raise SystemExit("domain is required")
  wildcard = candidate.startswith("*.")
  if wildcard:
    raise SystemExit("wildcard domains are not supported")
  base = candidate[2:] if wildcard else candidate
  labels = base.split(".")
  if len(labels) < 2:
    raise SystemExit("domain must contain at least one dot")
  for label in labels:
    if not label or len(label) > 63:
      raise SystemExit(f"invalid domain label: {label!r}")
    if label.startswith("-") or label.endswith("-"):
      raise SystemExit(f"invalid domain label: {label!r}")
    if not all(ch.isalnum() or ch == "-" for ch in label):
      raise SystemExit(f"invalid domain label: {label!r}")
  return candidate


def main(argv: list[str]) -> int:
  if len(argv) < 2:
    raise SystemExit("domain is required")
  domain = validate_domain(argv[1])
  dsn = load_dsn(os.environ["SSL_PROXY_CONFIG"])

  try:
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
      with conn.cursor() as cur:
        cur.execute(
          """
          SELECT
            r.domain,
            COALESCE(r.upstream_target, CASE WHEN r.upstream_port IS NULL THEN NULL ELSE 'host.docker.internal:' || r.upstream_port::text END) AS upstream_target,
            r.enabled,
            r.updated_at,
            c.status AS certificate_status,
            c.not_after AS certificate_not_after,
            c.retry_after,
            c.last_error
          FROM routes r
          LEFT JOIN certificates c ON c.domain = r.domain
          WHERE r.domain = %s
          """,
          (domain,),
        )
        row = cur.fetchone()
  except psycopg.Error as exc:
    raise SystemExit(f"database connection failed: {exc}") from exc

  if row is None:
    raise SystemExit("domain not found")

  print(yaml.safe_dump(dict(row), sort_keys=False))
  return 0


if __name__ == "__main__":
  raise SystemExit(main(sys.argv))
PY
}

get_domain_details_json() {
  local python_bin config_path
  python_bin="$(resolve_python)"
  config_path="$(resolve_config_path)"

  SSL_PROXY_CONFIG="${config_path}" \
  "${python_bin}" - "$@" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import psycopg
import yaml
from psycopg.rows import dict_row


def load_dsn(config_path: str) -> str:
  data = yaml.safe_load(Path(config_path).read_text()) or {}
  return data["postgres"]["dsn"]


def validate_domain(domain: str) -> str:
  candidate = domain.strip().lower().rstrip(".")
  if not candidate:
    raise SystemExit("domain is required")
  wildcard = candidate.startswith("*.")
  if wildcard:
    raise SystemExit("wildcard domains are not supported")
  base = candidate[2:] if wildcard else candidate
  labels = base.split(".")
  if len(labels) < 2:
    raise SystemExit("domain must contain at least one dot")
  for label in labels:
    if not label or len(label) > 63:
      raise SystemExit(f"invalid domain label: {label!r}")
    if label.startswith("-") or label.endswith("-"):
      raise SystemExit(f"invalid domain label: {label!r}")
    if not all(ch.isalnum() or ch == "-" for ch in label):
      raise SystemExit(f"invalid domain label: {label!r}")
  return candidate


def main(argv: list[str]) -> int:
  if len(argv) < 2:
    raise SystemExit("domain is required")
  domain = validate_domain(argv[1])
  dsn = load_dsn(os.environ["SSL_PROXY_CONFIG"])

  try:
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
      with conn.cursor() as cur:
        cur.execute(
          """
          SELECT
            r.domain,
            COALESCE(r.upstream_target, CASE WHEN r.upstream_port IS NULL THEN NULL ELSE 'host.docker.internal:' || r.upstream_port::text END) AS upstream_target,
            r.enabled,
            r.updated_at,
            c.status AS certificate_status,
            c.not_after AS certificate_not_after,
            c.retry_after,
            c.last_error
          FROM routes r
          LEFT JOIN certificates c ON c.domain = r.domain
          WHERE r.domain = %s
          """,
          (domain,),
        )
        row = cur.fetchone()
  except psycopg.Error as exc:
    print(json.dumps({"ok": False, "error": f"database connection failed: {exc}", "details": {}}))
    return 0

  if row is None:
    print(json.dumps({"ok": False, "error": "domain not found", "details": {}}))
    return 0

  print(json.dumps({"ok": True, "error": "", "details": dict(row)}, default=str))
  return 0


if __name__ == "__main__":
  raise SystemExit(main(sys.argv))
PY
}

get_zone_token_status_json() {
  local python_bin config_path
  python_bin="$(resolve_python)"
  config_path="$(resolve_config_path)"

  SSL_PROXY_CONFIG="${config_path}" \
  "${python_bin}" - "$@" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import psycopg
import yaml
from psycopg.rows import dict_row


def load_dsn(config_path: str) -> str:
  data = yaml.safe_load(Path(config_path).read_text()) or {}
  return data["postgres"]["dsn"]


def candidate_zones(name: str) -> list[str]:
  labels = name.strip().lower().rstrip(".").split(".")
  return [".".join(labels[index:]) for index in range(len(labels) - 2, -1, -1) if len(labels[index:]) >= 2]


def main(argv: list[str]) -> int:
  if len(argv) < 2:
    raise SystemExit("domain is required")
  domain = argv[1].strip().lower().rstrip(".")
  dsn = load_dsn(os.environ["SSL_PROXY_CONFIG"])
  candidates = candidate_zones(domain)
  if not candidates:
    print(json.dumps({"present": False, "zone_name": "", "provider": "", "error": ""}))
    return 0
  try:
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
      with conn.cursor() as cur:
        cur.execute(
          """
          SELECT zone_name, provider
          FROM dns_zone_tokens
          WHERE zone_name = ANY(%s)
          ORDER BY char_length(zone_name) DESC
          LIMIT 1
          """,
          (candidates,),
        )
        row = cur.fetchone()
  except psycopg.Error as exc:
    print(json.dumps({"present": False, "zone_name": "", "provider": "", "error": f"database connection failed: {exc}"}))
    return 0

  if row is None:
    print(json.dumps({"present": False, "zone_name": "", "provider": "", "error": ""}))
    return 0
  print(json.dumps({"present": True, "zone_name": row["zone_name"], "provider": row["provider"], "error": ""}))
  return 0


if __name__ == "__main__":
  raise SystemExit(main(sys.argv))
PY
}

resolve_dns_json() {
  local python_bin
  python_bin="$(resolve_python)"
  "${python_bin}" - "$@" <<'PY'
from __future__ import annotations

import json
import socket
import subprocess
import sys


def resolve_cname(domain: str) -> list[str]:
  commands = [
    ["dig", "+short", "CNAME", domain],
    ["nslookup", "-type=CNAME", domain],
  ]
  for command in commands:
    try:
      completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
      continue
    if command[0] == "dig":
      values = [line.strip().rstrip(".") for line in completed.stdout.splitlines() if line.strip()]
      if values:
        return values
      continue
    values: list[str] = []
    for line in completed.stdout.splitlines():
      marker = "canonical name ="
      if marker in line:
        values.append(line.split(marker, 1)[1].strip().rstrip("."))
    if values:
      return values
  return []


def main(argv: list[str]) -> int:
  if len(argv) < 2:
    raise SystemExit("domain is required")
  domain = argv[1]
  ipv4: set[str] = set()
  ipv6: set[str] = set()
  cname = resolve_cname(domain)

  try:
    infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    for item in infos:
      family = item[0]
      address = item[4][0]
      if family == socket.AF_INET:
        ipv4.add(address)
      elif family == socket.AF_INET6:
        ipv6.add(address)
  except socket.gaierror as exc:
    print(json.dumps({"error": str(exc), "ipv4": [], "ipv6": [], "cname": cname}))
    return 0

  print(json.dumps({"error": "", "ipv4": sorted(ipv4), "ipv6": sorted(ipv6), "cname": cname}))
  return 0


if __name__ == "__main__":
  raise SystemExit(main(sys.argv))
PY
}

get_public_ips_json() {
  local python_bin
  python_bin="$(resolve_python)"
  "${python_bin}" - <<'PY'
from __future__ import annotations

import json
import ipaddress
import socket
import urllib.request


def fetch(url: str) -> str:
  try:
    with urllib.request.urlopen(url, timeout=3) as response:
      return response.read().decode().strip()
  except Exception:
    return ""


def first_local_ip(family: int) -> str:
  try:
    hostname = socket.gethostname()
    infos = socket.getaddrinfo(hostname, None, family=family, proto=socket.IPPROTO_TCP)
  except socket.gaierror:
    return ""

  for item in infos:
    address = item[4][0]
    if family == socket.AF_INET6 and "%" in address:
      address = address.split("%", 1)[0]
    if address.startswith("127.") or address == "::1":
      continue
    return address
  return ""

public_ipv4 = fetch("https://api.ipify.org")
public_ipv6 = fetch("https://api6.ipify.org")

payload = {
  "ipv4": public_ipv4 or first_local_ip(socket.AF_INET),
  "ipv6": public_ipv6 or first_local_ip(socket.AF_INET6),
}
sources = {
  "ipv4": "public" if public_ipv4 else "local",
  "ipv6": "public" if public_ipv6 else "local",
}
payload["source_ipv4"] = sources["ipv4"]
payload["source_ipv6"] = sources["ipv6"]
print(json.dumps(payload))
PY
}

status_command() {
  [[ $# -ge 1 ]] || fail "domain is required"
  local domain details_json dns_json public_json zone_json python_bin mode
  domain="$(normalize_domain "$1")"
  python_bin="$(resolve_python)"
  mode="$(get_config_mode)"
  details_json="$(get_domain_details_json "${domain}")"
  dns_json="$(resolve_dns_json "${domain}")"
  public_json="$(get_public_ips_json)"
  zone_json="$(get_zone_token_status_json "${domain}")"

  SSL_PROXY_MODE="${mode}" DETAILS_JSON="${details_json}" DNS_JSON="${dns_json}" PUBLIC_JSON="${public_json}" ZONE_JSON="${zone_json}" "${python_bin}" - <<'PY'
from __future__ import annotations

import json
import ipaddress
import os
import sys

mode = os.environ["SSL_PROXY_MODE"]
details_payload = json.loads(os.environ["DETAILS_JSON"])
details = details_payload.get("details", {})
dns = json.loads(os.environ["DNS_JSON"])
public = json.loads(os.environ["PUBLIC_JSON"])
zone = json.loads(os.environ["ZONE_JSON"])

resolved = set(dns.get("ipv4", [])) | set(dns.get("ipv6", []))
local_ips = {ip for ip in [public.get("ipv4", ""), public.get("ipv6", "")] if ip}
public_sources = {public.get("source_ipv4", ""), public.get("source_ipv6", "")}

def is_public_ip(value: str) -> bool:
  try:
    address = ipaddress.ip_address(value)
  except ValueError:
    return False
  return address.is_global

if not local_ips:
  points_to_this_host = "unknown"
elif resolved & local_ips:
  points_to_this_host = "yes"
elif "public" not in public_sources and not any(is_public_ip(ip) for ip in local_ips):
  points_to_this_host = "unknown"
else:
  points_to_this_host = "no"

print(f'current_node_mode: {mode}')
print(f'database_lookup_ok: {"yes" if details_payload.get("ok") else "no"}')
print(f'database_error: {details_payload.get("error", "")}')
print(f'domain: {details.get("domain") or ""}')
print(f'enabled: {details.get("enabled", "")}')
upstream = details.get("upstream_target")
print(f'upstream_target: {"" if upstream is None else upstream}')
print(f'updated_at: {details.get("updated_at", "")}')
print(f'certificate_status: {details.get("certificate_status") or ""}')
not_after = details.get("certificate_not_after")
print(f'certificate_not_after: {not_after or ""}')
retry_after = details.get("retry_after")
print(f'retry_after: {retry_after or ""}')
print(f'last_error: {details.get("last_error") or ""}')
print(f'dns_zone: {zone.get("zone_name", "")}')
print(f'dns_provider: {zone.get("provider", "")}')
print(f'zone_token_present: {"yes" if zone.get("present") else "no"}')
print(f'dns_error: {dns.get("error", "")}')
print(f'dns_cname: {", ".join(dns.get("cname", []))}')
print(f'dns_ipv4: {", ".join(dns.get("ipv4", []))}')
print(f'dns_ipv6: {", ".join(dns.get("ipv6", []))}')
print(f'local_public_ipv4: {public.get("ipv4", "")}')
print(f'local_public_ipv6: {public.get("ipv6", "")}')
print(f'local_public_ipv4_source: {public.get("source_ipv4", "")}')
print(f'local_public_ipv6_source: {public.get("source_ipv6", "")}')
print(f'points_to_this_host: {points_to_this_host}')
if not details_payload.get("ok"):
  sys.exit(1)
PY
}

check_command() {
  [[ $# -ge 1 ]] || fail "domain is required"
  local domain details_json dns_json public_json zone_json python_bin mode
  domain="$(normalize_domain "$1")"
  python_bin="$(resolve_python)"
  mode="$(get_config_mode)"
  details_json="$(get_domain_details_json "${domain}")"
  dns_json="$(resolve_dns_json "${domain}")"
  public_json="$(get_public_ips_json)"
  zone_json="$(get_zone_token_status_json "${domain}")"

  SSL_PROXY_MODE="${mode}" DETAILS_JSON="${details_json}" DNS_JSON="${dns_json}" PUBLIC_JSON="${public_json}" ZONE_JSON="${zone_json}" "${python_bin}" - <<'PY'
from __future__ import annotations

import json
import ipaddress
import os
import sys

mode = os.environ["SSL_PROXY_MODE"]
details_payload = json.loads(os.environ["DETAILS_JSON"])
details = details_payload.get("details", {})
dns = json.loads(os.environ["DNS_JSON"])
public = json.loads(os.environ["PUBLIC_JSON"])
zone = json.loads(os.environ["ZONE_JSON"])

resolved = set(dns.get("ipv4", [])) | set(dns.get("ipv6", []))
local_ips = {ip for ip in [public.get("ipv4", ""), public.get("ipv6", "")] if ip}
public_sources = {public.get("source_ipv4", ""), public.get("source_ipv6", "")}

def is_public_ip(value: str) -> bool:
  try:
    address = ipaddress.ip_address(value)
  except ValueError:
    return False
  return address.is_global

if not local_ips:
  points_to_this_host = None
elif resolved & local_ips:
  points_to_this_host = True
elif "public" not in public_sources and not any(is_public_ip(ip) for ip in local_ips):
  points_to_this_host = None
else:
  points_to_this_host = False

checks = [
  ("node_mode", mode == "readwrite", f"mode={mode}"),
  ("db_lookup", bool(details_payload.get("ok")), details_payload.get("error", "")),
  ("route_enabled", bool(details.get("enabled")), "" if details_payload.get("ok") else "skipped"),
  ("zone_token", bool(zone.get("present")), ""),
  ("dns_resolves", not bool(dns.get("error")), dns.get("error", "")),
]

failed = False
for name, ok, extra in checks:
  suffix = f" {extra}" if extra else ""
  print(f'check_{name}: {"ok" if ok else "fail"}{suffix}')
  if not ok:
    failed = True

if failed:
  sys.exit(1)
PY
}

logs_command() {
  [[ $# -ge 1 ]] || fail "domain is required"
  local domain
  domain="$(normalize_domain "$1")"
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  [[ -f "${COMPOSE_PATH}" ]] || fail "compose file not found: ${COMPOSE_PATH}"
  docker compose -f "${COMPOSE_PATH}" logs --tail 300 ssl-service | grep -F "${domain}" || true
}

run_db_tool() {
  local python_bin config_path
  python_bin="$(resolve_python)"
  config_path="$(resolve_config_path)"

  SSL_PROXY_CONFIG="${config_path}" \
  "${python_bin}" - "$@" <<'PY'
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import psycopg
import yaml
from psycopg.rows import dict_row


def load_dsn(config_path: str) -> str:
  data = yaml.safe_load(Path(config_path).read_text()) or {}
  return data["postgres"]["dsn"]


def candidate_zones(name: str) -> list[str]:
  labels = name.strip().lower().rstrip(".").split(".")
  return [".".join(labels[index:]) for index in range(len(labels) - 2, -1, -1) if len(labels[index:]) >= 2]


def cloudflare_request(token: str, method: str, path: str, payload: dict | None = None) -> dict:
  request = urllib.request.Request(
    f"https://api.cloudflare.com/client/v4{path}",
    method=method,
    headers={
      "Authorization": f"Bearer {token}",
      "Content-Type": "application/json",
    },
    data=None if payload is None else json.dumps(payload).encode("utf-8"),
  )
  try:
    with urllib.request.urlopen(request, timeout=15) as response:
      return json.loads(response.read().decode("utf-8"))
  except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", errors="replace")
    raise SystemExit(f"Cloudflare API request failed: HTTP {exc.code}: {body}") from exc
  except urllib.error.URLError as exc:
    raise SystemExit(f"Cloudflare API request failed: {exc}") from exc


def discover_cloudflare_zone(domain_or_zone: str, token: str) -> tuple[str, str]:
  for candidate in candidate_zones(domain_or_zone):
    query = urllib.parse.urlencode({"name": candidate, "per_page": 1})
    payload = cloudflare_request(token, "GET", f"/zones?{query}")
    if payload.get("success") and payload.get("result"):
      zone = payload["result"][0]
      return str(zone["name"]).lower(), str(zone["id"])
  raise SystemExit(f"could not find a Cloudflare zone for: {domain_or_zone}")


def validate_cloudflare_zone_token(domain_or_zone: str, token: str) -> tuple[str, str]:
  zone_name, zone_id = discover_cloudflare_zone(domain_or_zone, token)
  record_name = f"_ssl-proxy-token-check.{zone_name}"
  payload = cloudflare_request(
    token,
    "POST",
    f"/zones/{zone_id}/dns_records",
    {
      "type": "TXT",
      "name": record_name,
      "content": "ssl-proxy-verify",
      "ttl": 60,
    },
  )
  if not payload.get("success") or not payload.get("result"):
    raise SystemExit(f"Cloudflare token could not create a DNS record for zone: {zone_name}")
  record_id = str(payload["result"]["id"])
  try:
    cloudflare_request(token, "DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
  except SystemExit as exc:
    raise SystemExit(f"Cloudflare token validation partially failed: created a test record but could not delete it: {exc}") from exc
  return zone_name, zone_id


def validate_domain(domain: str) -> str:
  candidate = domain.strip().lower().rstrip(".")
  if not candidate:
    raise SystemExit("domain is required")

  wildcard = candidate.startswith("*.")
  if wildcard:
    raise SystemExit("wildcard domains are not supported")
  base = candidate[2:] if wildcard else candidate
  labels = base.split(".")
  if len(labels) < 2:
    raise SystemExit("domain must contain at least one dot")
  for label in labels:
    if not label or len(label) > 63:
      raise SystemExit(f"invalid domain label: {label!r}")
    if label.startswith("-") or label.endswith("-"):
      raise SystemExit(f"invalid domain label: {label!r}")
    if not all(ch.isalnum() or ch == "-" for ch in label):
      raise SystemExit(f"invalid domain label: {label!r}")
  return candidate


def normalize_upstream_target(value: str) -> str:
  candidate = value.strip()
  if not candidate:
    raise SystemExit("upstream_target must not be empty")
  if any(ch.isspace() for ch in candidate) or "/" in candidate:
    raise SystemExit("upstream_target must not contain spaces or slashes")

  if candidate.isdigit():
    port = int(candidate)
    if port < 1 or port > 65535:
      raise SystemExit("upstream_target port must be between 1 and 65535")
    return f"host.docker.internal:{port}"

  if candidate.startswith("["):
    if "]:" not in candidate:
      raise SystemExit("IPv6 upstream_target must use [addr]:port format")
    host, port_text = candidate[1:].split("]:", 1)
    try:
      host = str(ipaddress.ip_address(host))
    except ValueError as exc:
      raise SystemExit(f"invalid IPv6 upstream_target host: {host}") from exc
    host = f"[{host}]"
  else:
    if candidate.count(":") > 1:
      raise SystemExit("IPv6 upstream_target must use [addr]:port format")
    if ":" not in candidate:
      raise SystemExit("upstream_target must be a port or host:port")
    host, port_text = candidate.rsplit(":", 1)
    if not host:
      raise SystemExit("upstream_target host must not be empty")
    try:
      host = str(ipaddress.ip_address(host))
    except ValueError:
      if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise SystemExit("upstream_target host contains invalid characters")
      for label in host.split("."):
        if not label:
          raise SystemExit("upstream_target host contains an empty label")
        if label.startswith("-") or label.endswith("-"):
          raise SystemExit("upstream_target host contains an invalid label")
      host = host.lower()

  if not port_text.isdigit():
    raise SystemExit("upstream_target port must be numeric")
  port = int(port_text)
  if port < 1 or port > 65535:
    raise SystemExit("upstream_target port must be between 1 and 65535")
  if host in {"127.0.0.1", "localhost", "[::1]"}:
    host = "host.docker.internal"
  return f"{host}:{port}"


def print_rows(rows):
  if not rows:
    print("no rows")
    return
  for row in rows:
    upstream = "" if row["upstream_target"] is None else str(row["upstream_target"])
    cert_status = row.get("certificate_status")
    cert_not_after = row.get("certificate_not_after")
    retry_after = row.get("retry_after")
    cert_bits = []
    if cert_status is not None:
      cert_bits.append(f"certificate_status={cert_status}")
    if cert_not_after is not None:
      cert_bits.append(f"certificate_not_after={cert_not_after.isoformat()}")
    if retry_after is not None:
      cert_bits.append(f"retry_after={retry_after.isoformat()}")
    if row.get("last_error"):
      cert_bits.append(f'last_error="{row["last_error"]}"')
    cert_suffix = ""
    if cert_bits:
      cert_suffix = " " + " ".join(cert_bits)
    print(
      f'domain={row["domain"]} upstream_target={upstream} enabled={row["enabled"]} updated_at={row["updated_at"].isoformat()}{cert_suffix}'
    )


def print_zone_rows(rows):
  if not rows:
    print("no rows")
    return
  for row in rows:
    print(
      f'zone_name={row["zone_name"]} provider={row["provider"]} zone_id={row["zone_id"]} updated_at={row["updated_at"].isoformat()}'
    )


def main(argv: list[str]) -> int:
  if len(argv) < 2:
    raise SystemExit("missing subcommand")

  subcommand = argv[1]
  dsn = load_dsn(config_path=os.environ["SSL_PROXY_CONFIG"])

  try:
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
      with conn.cursor() as cur:
        if subcommand == "list":
          cur.execute(
            """
            SELECT
              r.domain,
              COALESCE(r.upstream_target, CASE WHEN r.upstream_port IS NULL THEN NULL ELSE 'host.docker.internal:' || r.upstream_port::text END) AS upstream_target,
              r.enabled,
              r.updated_at,
              c.status AS certificate_status,
              c.not_after AS certificate_not_after,
              c.retry_after,
              c.last_error
            FROM routes r
            LEFT JOIN certificates c ON c.domain = r.domain
            ORDER BY domain ASC
            """
          )
          print_rows(cur.fetchall())
          return 0

        if subcommand == "list-certs":
          cur.execute(
            """
            SELECT
              c.domain,
              NULL::text AS upstream_target,
              TRUE AS enabled,
              c.updated_at,
              c.status AS certificate_status,
              c.not_after AS certificate_not_after,
              c.retry_after,
              c.last_error
            FROM certificates c
            ORDER BY c.domain ASC
            """
          )
          print_rows(cur.fetchall())
          return 0

        if subcommand == "list-zones":
          cur.execute(
            """
            SELECT zone_name, provider, zone_id, updated_at
            FROM dns_zone_tokens
            ORDER BY zone_name ASC
            """
          )
          print_zone_rows(cur.fetchall())
          return 0

        if len(argv) < 3:
          raise SystemExit("domain is required")

        if subcommand == "get-zone":
          zone_name = argv[2].strip().lower().rstrip(".")
          cur.execute(
            """
            SELECT zone_name, provider, zone_id, updated_at
            FROM dns_zone_tokens
            WHERE zone_name = %s
            """,
            (zone_name,),
          )
          row = cur.fetchone()
          if row is None:
            raise SystemExit("zone not found")
          print_zone_rows([row])
          return 0

        if subcommand == "get-zone-for-domain":
          domain = validate_domain(argv[2])
          cur.execute(
            """
            SELECT zone_name, provider, zone_id, updated_at
            FROM dns_zone_tokens
            WHERE %s = zone_name OR %s LIKE '%%.' || zone_name
            ORDER BY char_length(zone_name) DESC
            LIMIT 1
            """,
            (domain, domain),
          )
          row = cur.fetchone()
          if row is None:
            raise SystemExit("zone token not found for domain")
          print_zone_rows([row])
          return 0

        if subcommand == "upsert-zone-token":
          domain_or_zone = argv[2].strip().lower().rstrip(".")
          if len(argv) < 4:
            raise SystemExit("Cloudflare API token is required")
          zone_name, zone_id = validate_cloudflare_zone_token(domain_or_zone, argv[3].strip())
          cur.execute(
            """
            INSERT INTO dns_zone_tokens (zone_name, provider, zone_id, api_token)
            VALUES (%s, 'cloudflare', %s, %s)
            ON CONFLICT (zone_name) DO UPDATE
            SET provider = EXCLUDED.provider,
                zone_id = EXCLUDED.zone_id,
                api_token = EXCLUDED.api_token
            RETURNING zone_name, provider, zone_id, updated_at
            """,
            (zone_name, zone_id, argv[3].strip()),
          )
          print_zone_rows([cur.fetchone()])
          conn.commit()
          return 0

        domain = validate_domain(argv[2])

        if subcommand == "get":
          cur.execute(
            """
            SELECT
              r.domain,
              COALESCE(r.upstream_target, CASE WHEN r.upstream_port IS NULL THEN NULL ELSE 'host.docker.internal:' || r.upstream_port::text END) AS upstream_target,
              r.enabled,
              r.updated_at,
              c.status AS certificate_status,
              c.not_after AS certificate_not_after,
              c.retry_after,
              c.last_error
            FROM routes r
            LEFT JOIN certificates c ON c.domain = r.domain
            WHERE r.domain = %s
            """,
            (domain,),
          )
          row = cur.fetchone()
          if row is None:
            raise SystemExit("domain not found")
          print_rows([row])
          return 0

        if subcommand == "add":
          upstream_target = None
          if len(argv) >= 4 and argv[3] != "":
            upstream_target = normalize_upstream_target(argv[3])
          cur.execute(
            """
            INSERT INTO routes (domain, upstream_target, enabled)
            VALUES (%s, %s, TRUE)
            ON CONFLICT (domain) DO UPDATE
            SET upstream_target = EXCLUDED.upstream_target,
                upstream_port = NULL,
                enabled = TRUE
            RETURNING domain, upstream_target, enabled, updated_at, NULL::text AS certificate_status,
                      NULL::timestamptz AS certificate_not_after, NULL::timestamptz AS retry_after, NULL::text AS last_error
            """,
            (domain, upstream_target),
          )
          print_rows([cur.fetchone()])
          conn.commit()
          return 0

        if subcommand == "set-target":
          if len(argv) < 4:
            raise SystemExit("upstream_target is required")
          cur.execute(
            """
            UPDATE routes
            SET upstream_target = %s
              , upstream_port = NULL
            WHERE domain = %s
            RETURNING domain, upstream_target, enabled, updated_at, NULL::text AS certificate_status,
                      NULL::timestamptz AS certificate_not_after, NULL::timestamptz AS retry_after, NULL::text AS last_error
            """,
            (normalize_upstream_target(argv[3]), domain),
          )
          row = cur.fetchone()
          if row is None:
            raise SystemExit("domain not found")
          print_rows([row])
          conn.commit()
          return 0

        if subcommand == "clear-target":
          cur.execute(
            """
            UPDATE routes
            SET upstream_target = NULL,
                upstream_port = NULL
            WHERE domain = %s
            RETURNING domain, upstream_target, enabled, updated_at, NULL::text AS certificate_status,
                      NULL::timestamptz AS certificate_not_after, NULL::timestamptz AS retry_after, NULL::text AS last_error
            """,
            (domain,),
          )
          row = cur.fetchone()
          if row is None:
            raise SystemExit("domain not found")
          print_rows([row])
          conn.commit()
          return 0

        if subcommand == "enable":
          cur.execute(
            """
            UPDATE routes
            SET enabled = TRUE
            WHERE domain = %s
            RETURNING domain,
                      COALESCE(upstream_target, CASE WHEN upstream_port IS NULL THEN NULL ELSE 'host.docker.internal:' || upstream_port::text END) AS upstream_target,
                      enabled,
                      updated_at,
                      NULL::text AS certificate_status,
                      NULL::timestamptz AS certificate_not_after, NULL::timestamptz AS retry_after, NULL::text AS last_error
            """,
            (domain,),
          )
          row = cur.fetchone()
          if row is None:
            raise SystemExit("domain not found")
          print_rows([row])
          conn.commit()
          return 0

        if subcommand == "disable":
          cur.execute(
            """
            UPDATE routes
            SET enabled = FALSE
            WHERE domain = %s
            RETURNING domain,
                      COALESCE(upstream_target, CASE WHEN upstream_port IS NULL THEN NULL ELSE 'host.docker.internal:' || upstream_port::text END) AS upstream_target,
                      enabled,
                      updated_at,
                      NULL::text AS certificate_status,
                      NULL::timestamptz AS certificate_not_after, NULL::timestamptz AS retry_after, NULL::text AS last_error
            """,
            (domain,),
          )
          row = cur.fetchone()
          if row is None:
            raise SystemExit("domain not found")
          print_rows([row])
          conn.commit()
          return 0

        if subcommand == "delete":
          cur.execute("DELETE FROM routes WHERE domain = %s RETURNING domain", (domain,))
          row = cur.fetchone()
          if row is None:
            raise SystemExit("domain not found")
          conn.commit()
          print(f'deleted domain={row["domain"]}')
          return 0

        if subcommand == "purge":
          cur.execute("DELETE FROM certificates WHERE domain = %s RETURNING domain", (domain,))
          certificate_row = cur.fetchone()
          cur.execute("DELETE FROM routes WHERE domain = %s RETURNING domain", (domain,))
          route_row = cur.fetchone()
          if route_row is None and certificate_row is None:
            raise SystemExit("domain not found")
          conn.commit()
          print(f"purged domain={domain}")
          return 0

        if subcommand == "issue-now":
          cur.execute("SELECT domain, enabled FROM routes WHERE domain = %s", (domain,))
          route_row = cur.fetchone()
          if route_row is None:
            raise SystemExit("domain not found in routes")
          if not route_row["enabled"]:
            raise SystemExit("domain is disabled; enable it before issue-now")
          cur.execute(
            """
            UPDATE certificates
            SET retry_after = NULL, updated_at = NOW()
            WHERE domain = %s
            RETURNING domain
            """,
            (domain,),
          )
          conn.commit()
          print(f"issue-now queued for domain={domain}")
          return 0

        raise SystemExit(f"unknown subcommand: {subcommand}")
  except psycopg.Error as exc:
    raise SystemExit(f"database connection failed: {exc}") from exc


if __name__ == "__main__":
  raise SystemExit(main(sys.argv))
PY
}

sync_now() {
  command -v docker >/dev/null 2>&1 || fail "docker is required for sync-now"
  [[ "${EUID}" -eq 0 ]] || fail "sync-now requires root"
  [[ -f "${COMPOSE_PATH}" ]] || fail "compose file not found: ${COMPOSE_PATH}"
  docker compose -f "${COMPOSE_PATH}" restart ssl-service >/dev/null
  log "container restarted"
}

preflight_sync_now() {
  command -v docker >/dev/null 2>&1 || fail "docker is required for sync-now"
  [[ "${EUID}" -eq 0 ]] || fail "sync-now requires root"
  [[ -f "${COMPOSE_PATH}" ]] || fail "compose file not found: ${COMPOSE_PATH}"
}

main() {
  local subcommand="${1:-}"
  local sync_flag=0
  if [[ -z "${subcommand}" ]]; then
    if ui_has_tty; then
      interactive_menu
      return 0
    fi
    usage
    return 1
  fi
  shift || true

  while [[ $# -gt 0 ]]; do
    case "${!#}" in
      --sync-now)
        sync_flag=1
        set -- "${@:1:$(($#-1))}"
        ;;
      *)
        break
        ;;
    esac
  done

  case "${subcommand}" in
    overview)
      node_overview_command
      ;;
    shell)
      shell_command
      ;;
    prompt-init)
      prompt_init_command
      ;;
    list|list-certs)
      run_db_tool "${subcommand}"
      ;;
    status)
      [[ $# -ge 1 ]] || fail "domain is required"
      status_command "$1"
      ;;
    check)
      [[ $# -ge 1 ]] || fail "domain is required"
      check_command "$1"
      ;;
    logs)
      [[ $# -ge 1 ]] || fail "domain is required"
      logs_command "$1"
      ;;
    get|enable|disable|delete|purge|clear-target|clear-port|issue-now|get-zone|get-zone-for-domain)
      [[ $# -ge 1 ]] || fail "domain is required"
      local normalized_domain
      normalized_domain="$(normalize_domain "$1")"
      if [[ "${subcommand}" == "issue-now" && "$(get_config_mode)" != "readwrite" ]]; then
        fail "issue-now is only available on readwrite nodes"
      fi
      if [[ "${subcommand}" == "issue-now" || "${sync_flag}" -eq 1 ]]; then
        preflight_sync_now
      fi
      run_db_tool "$subcommand" "${normalized_domain}"
      if [[ "${subcommand}" == "issue-now" || "${sync_flag}" -eq 1 ]]; then
        sync_now
      fi
      ;;
    add)
      [[ $# -ge 1 ]] || fail "domain is required"
      local normalized_domain
      normalized_domain="$(normalize_domain "$1")"
      ensure_zone_token_for_domain "${normalized_domain}"
      if [[ "${sync_flag}" -eq 1 ]]; then
        preflight_sync_now
      fi
      if [[ $# -ge 2 ]]; then
        run_db_tool add "${normalized_domain}" "$2"
      else
        run_db_tool add "${normalized_domain}"
      fi
      if [[ "${sync_flag}" -eq 1 ]]; then
        sync_now
      fi
      ;;
    set-target|set-port)
      [[ $# -ge 2 ]] || fail "domain and upstream_target are required"
      local normalized_domain
      normalized_domain="$(normalize_domain "$1")"
      ensure_zone_token_for_domain "${normalized_domain}"
      if [[ "${sync_flag}" -eq 1 ]]; then
        preflight_sync_now
      fi
      run_db_tool set-target "${normalized_domain}" "$2"
      if [[ "${sync_flag}" -eq 1 ]]; then
        sync_now
      fi
      ;;
    list-zones)
      run_db_tool list-zones
      ;;
    set-zone-token)
      [[ $# -ge 1 ]] || fail "domain or zone is required"
      ensure_zone_token_for_domain "$1" 1
      ;;
    sync-now)
      sync_now
      ;;
    ""|-h|--help|help)
      usage
      ;;
    *)
      fail "unknown command: ${subcommand}"
      ;;
  esac
}

main "$@"
