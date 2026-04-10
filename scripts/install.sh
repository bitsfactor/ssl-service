#!/usr/bin/env bash
set -euo pipefail

GITHUB_CONTENT_BASE_URL="${SSL_SERVICE_GITHUB_CONTENT_BASE_URL:-https://github.com/bitsfactor/ssl-service/raw/${SSL_SERVICE_INSTALL_REF:-main}}"
TMP_DIR=""

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "run this installer as root"
}

ensure_curl() {
  if command -v curl >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y curl ca-certificates
    return 0
  fi
  fail "curl is required"
}

main() {
  require_root
  ensure_curl

  if [[ $# -eq 0 && ! -t 0 ]]; then
    fail "interactive bootstrap requires a TTY; run setup.sh in a real terminal"
  fi

  TMP_DIR="$(mktemp -d)"
  trap cleanup EXIT

  local target="${TMP_DIR}/setup.sh"
  log "Downloading setup.sh"
  curl -fsSL "${GITHUB_CONTENT_BASE_URL}/scripts/setup.sh" -o "${target}"
  chmod 0755 "${target}"
  exec bash "${target}" "$@"
}

main "$@"
