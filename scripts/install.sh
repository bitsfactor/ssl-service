#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${SSL_SERVICE_REPO_URL:-https://github.com/bitsfactor/ssl-service.git}"
INSTALL_REF="${SSL_SERVICE_INSTALL_REF:-main}"
SOURCE_ROOT="${SSL_SERVICE_SOURCE_ROOT:-/root/ssl-service}"

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || fail "run this installer as root"
}

ensure_git() {
  if command -v git >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y git ca-certificates
    return 0
  fi
  fail "git is required"
}

normalize_repo_url() {
  local url="$1"
  url="${url%.git}"
  case "${url}" in
    git@github.com:*)
      printf '%s' "https://github.com/${url#git@github.com:}"
      ;;
    ssh://git@github.com/*)
      printf '%s' "https://github.com/${url#ssh://git@github.com/}"
      ;;
    https://github.com/*)
      printf '%s' "${url}"
      ;;
    *)
      printf '%s' "${url}"
      ;;
  esac
}

is_git_checkout() {
  [[ -d "${SOURCE_ROOT}/.git" ]] && git -C "${SOURCE_ROOT}" rev-parse --show-toplevel >/dev/null 2>&1
}

checkout_has_local_changes() {
  [[ -n "$(git -C "${SOURCE_ROOT}" status --short 2>/dev/null)" ]]
}

sync_source_checkout() {
  local origin_url expected_origin
  origin_url="$(git -C "${SOURCE_ROOT}" remote get-url origin 2>/dev/null || true)"
  [[ -n "${origin_url}" ]] || fail "existing checkout has no origin remote: ${SOURCE_ROOT}"
  expected_origin="$(normalize_repo_url "${REPO_URL}")"

  if [[ "$(normalize_repo_url "${origin_url}")" != "${expected_origin}" ]]; then
    fail "existing checkout points to ${origin_url}, expected ${REPO_URL}"
  fi

  if checkout_has_local_changes; then
    log "Existing checkout at ${SOURCE_ROOT} has local changes; skipping git update and using current checkout"
    return 0
  fi

  log "Updating ssl-service source in ${SOURCE_ROOT}"
  git -C "${SOURCE_ROOT}" fetch --depth 1 origin "${INSTALL_REF}"
  git -C "${SOURCE_ROOT}" checkout -B "${INSTALL_REF}" FETCH_HEAD
}

ensure_source_checkout() {
  if [[ -x "${SOURCE_ROOT}/scripts/setup.sh" ]] && is_git_checkout; then
    sync_source_checkout
    return 0
  fi

  if [[ -e "${SOURCE_ROOT}" ]]; then
    fail "source root exists but is not a usable ssl-service checkout: ${SOURCE_ROOT}"
  fi

  mkdir -p "$(dirname "${SOURCE_ROOT}")"
  log "Cloning ssl-service source to ${SOURCE_ROOT}"
  git clone --depth 1 --branch "${INSTALL_REF}" "${REPO_URL}" "${SOURCE_ROOT}"
  chmod 0755 "${SOURCE_ROOT}/scripts/setup.sh" "${SOURCE_ROOT}/scripts/install.sh"
}

main() {
  require_root
  ensure_git

  if [[ $# -eq 0 && ! -t 0 ]]; then
    fail "interactive bootstrap requires a TTY; run install.sh in a real terminal"
  fi

  ensure_source_checkout
  exec bash "${SOURCE_ROOT}/scripts/setup.sh" "$@"
}

main "$@"
