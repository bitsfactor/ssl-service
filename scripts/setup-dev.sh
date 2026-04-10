#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_DIR}/.venv"
TOOLS_VENV_DIR="${REPO_DIR}/.tools-venv"
ACME_VENV_DIR="${REPO_DIR}/.acme-venv"

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
  setup-dev.sh bootstrap
  setup-dev.sh test
  setup-dev.sh run-once [--config <path>]
  setup-dev.sh domain <domain-command> [args...]

Notes:
  - run this script from the source tree
  - bootstrap creates local development venvs inside the repo
EOF
}

ensure_repo_root() {
  [[ -f "${REPO_DIR}/pyproject.toml" ]] || fail "run setup-dev.sh from the source tree"
}

ensure_python() {
  command -v python3 >/dev/null 2>&1 || fail "python3 is required"
  python3 -m venv --help >/dev/null 2>&1 || fail "python3-venv is required"
}

bootstrap_command() {
  ensure_repo_root
  ensure_python

  if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${VENV_DIR}"
  fi
  "${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${VENV_DIR}/bin/pip" install -e "${REPO_DIR}" >/dev/null

  if [[ ! -x "${TOOLS_VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${TOOLS_VENV_DIR}"
  fi
  "${TOOLS_VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${TOOLS_VENV_DIR}/bin/pip" install -e "${REPO_DIR}[test]" >/dev/null

  if [[ ! -x "${ACME_VENV_DIR}/bin/python" ]]; then
    python3 -m venv "${ACME_VENV_DIR}"
  fi
  "${ACME_VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${ACME_VENV_DIR}/bin/pip" install --upgrade "certbot>=2.11,<3.0" "certbot-dns-cloudflare>=2.11,<3.0" >/dev/null

  log "development environment ready"
}

test_command() {
  ensure_repo_root
  [[ -x "${TOOLS_VENV_DIR}/bin/python" ]] || bootstrap_command
  "${TOOLS_VENV_DIR}/bin/python" -m pytest "$@"
}

run_once_command() {
  ensure_repo_root
  [[ -x "${VENV_DIR}/bin/python" ]] || bootstrap_command

  local config_path="${REPO_DIR}/config.yaml"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)
        shift
        [[ $# -gt 0 ]] || fail "--config requires a value"
        config_path="$1"
        ;;
      *)
        fail "unknown flag: $1"
        ;;
    esac
    shift
  done

  "${VENV_DIR}/bin/python" -m ssl_proxy_controller --config "${config_path}" --once
}

domain_command() {
  ensure_repo_root
  [[ -x "${TOOLS_VENV_DIR}/bin/python" ]] || bootstrap_command
  SSL_PROXY_CONFIG="${REPO_DIR}/config.yaml" bash "${REPO_DIR}/scripts/domain-manage.sh" "$@"
}

main() {
  local command="${1:-}"
  case "${command}" in
    bootstrap)
      shift
      bootstrap_command "$@"
      ;;
    test)
      shift
      test_command "$@"
      ;;
    run-once)
      shift
      run_once_command "$@"
      ;;
    domain)
      shift
      domain_command "$@"
      ;;
    -h|--help|help|"")
      usage
      ;;
    *)
      fail "unknown command: ${command}"
      ;;
  esac
}

main "$@"
