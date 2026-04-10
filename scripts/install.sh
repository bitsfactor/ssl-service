#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="leoleoaabbcc"
REPO_NAME="ssl-server"
REPO_REF="${SSL_SERVER_INSTALL_REF:-main}"
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
    apt-get install -y curl
    return 0
  fi
  fail "curl is required"
}

ensure_tar() {
  if command -v tar >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y tar
    return 0
  fi
  fail "tar is required"
}

download_repo() {
  local archive_url archive_path
  archive_url="https://codeload.github.com/${REPO_OWNER}/${REPO_NAME}/tar.gz/refs/heads/${REPO_REF}"
  archive_path="${TMP_DIR}/repo.tar.gz"
  curl -fsSL "${archive_url}" -o "${archive_path}"
  tar -xzf "${archive_path}" -C "${TMP_DIR}"
}

resolve_source_dir() {
  local candidate
  candidate="$(find "${TMP_DIR}" -maxdepth 1 -mindepth 1 -type d -name "${REPO_NAME}-*" | head -n 1)"
  [[ -n "${candidate}" ]] || fail "failed to unpack repository"
  printf '%s' "${candidate}"
}

main() {
  require_root
  ensure_curl
  ensure_tar

  if [[ $# -eq 0 && ! -t 0 ]]; then
    fail "interactive bootstrap requires a TTY; clone the repo and run 'bash scripts/setup.sh install', or pass install flags explicitly"
  fi

  TMP_DIR="$(mktemp -d)"
  trap cleanup EXIT

  log "Downloading ${REPO_OWNER}/${REPO_NAME}@${REPO_REF}"
  download_repo

  local source_dir
  source_dir="$(resolve_source_dir)"
  cd "${source_dir}"

  exec bash ./scripts/setup.sh install "$@"
}

main "$@"
