#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEPLOY_DIR="/opt/ssl-proxy"
PROGRAM_NAME="$(basename "${BASH_SOURCE[0]}")"
CONFIG_CANDIDATES=(
  "/etc/ssl-proxy/config.yaml"
)

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
  ${PROGRAM_NAME} list
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
  ${PROGRAM_NAME} issue-now <domain> [--force]
  ${PROGRAM_NAME} sync-now

Notes:
  - upstream_target can be omitted on add, which creates a certificate-only domain.
  - upstream_target accepts '6111', '127.0.0.1:6111', '10.0.0.25:6111', 'backend.internal:6111', or '[2001:db8::10]:6111'.
  - the script reads PostgreSQL DSN from /etc/ssl-proxy/config.yaml by default.
  - override config with: SSL_PROXY_CONFIG=/path/to/config.yaml
  - mutating commands accept --sync-now to force an immediate local refresh
  - automatic retry backoff defaults to 3600 seconds after ACME failure
EOF
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
  if [[ -x "${DEPLOY_DIR}/.venv/bin/python" ]]; then
    printf '%s' "${DEPLOY_DIR}/.venv/bin/python"
    return 0
  fi
  if [[ -x "${REPO_DIR}/.venv/bin/python" ]]; then
    printf '%s' "${REPO_DIR}/.venv/bin/python"
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
    raise SystemExit("wildcard domains are not supported with the current HTTP-01 flow")
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
import os
import re
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
    raise SystemExit("wildcard domains are not supported with the current HTTP-01 flow")
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
    with psycopg.connect(dsn, row_factory=dict_row, sslmode="require") as conn:
      with conn.cursor() as cur:
        cur.execute(
          """
          SELECT
            r.domain,
            COALESCE(r.upstream_target, CASE WHEN r.upstream_port IS NULL THEN NULL ELSE '127.0.0.1:' || r.upstream_port::text END) AS upstream_target,
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
    raise SystemExit("wildcard domains are not supported with the current HTTP-01 flow")
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
    with psycopg.connect(dsn, row_factory=dict_row, sslmode="require") as conn:
      with conn.cursor() as cur:
        cur.execute(
          """
          SELECT
            r.domain,
            COALESCE(r.upstream_target, CASE WHEN r.upstream_port IS NULL THEN NULL ELSE '127.0.0.1:' || r.upstream_port::text END) AS upstream_target,
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

probe_http_json() {
  local python_bin
  python_bin="$(resolve_python)"
  "${python_bin}" - "$@" <<'PY'
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, req, fp, code, msg, headers, newurl):
    return None


def main(argv: list[str]) -> int:
  if len(argv) < 2:
    raise SystemExit("domain is required")
  domain = argv[1]
  url = f"http://{domain}/.well-known/acme-challenge/ssl-proxy-healthcheck"
  opener = urllib.request.build_opener(NoRedirectHandler)
  request = urllib.request.Request(url, method="GET")
  try:
    with opener.open(request, timeout=5) as response:
      print(json.dumps({
        "reachable": True,
        "status_code": response.getcode(),
        "redirect_location": "",
        "error": "",
      }))
      return 0
  except urllib.error.HTTPError as exc:
    redirect_location = exc.headers.get("Location", "")
    reachable = exc.code in {200, 403}
    if exc.code in {301, 302, 307, 308} and redirect_location.startswith(f"https://{domain}/"):
      reachable = True
    print(json.dumps({
      "reachable": reachable,
      "status_code": exc.code,
      "redirect_location": redirect_location,
      "error": "",
    }))
    return 0
  except Exception as exc:
    print(json.dumps({
      "reachable": False,
      "status_code": 0,
      "redirect_location": "",
      "error": str(exc),
    }))
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

domain_points_to_this_host() {
  [[ $# -ge 1 ]] || fail "domain is required"
  local domain dns_json public_json python_bin
  domain="$(normalize_domain "$1")"
  python_bin="$(resolve_python)"
  dns_json="$(resolve_dns_json "${domain}")"
  public_json="$(get_public_ips_json)"

  DNS_JSON="${dns_json}" PUBLIC_JSON="${public_json}" "${python_bin}" - <<'PY'
from __future__ import annotations

import json
import ipaddress
import os

dns = json.loads(os.environ["DNS_JSON"])
public = json.loads(os.environ["PUBLIC_JSON"])

resolved = set(dns.get("ipv4", [])) | set(dns.get("ipv6", []))
local_ips = {ip for ip in [public.get("ipv4", ""), public.get("ipv6", "")] if ip}
public_sources = {public.get("source_ipv4", ""), public.get("source_ipv6", "")}
has_public_view = "public" in public_sources

def is_public_ip(value: str) -> bool:
  try:
    address = ipaddress.ip_address(value)
  except ValueError:
    return False
  return address.is_global

if dns.get("error"):
  print("dns_error")
elif not local_ips:
  print("unknown")
elif resolved & local_ips:
  print("yes")
elif not has_public_view and not any(is_public_ip(ip) for ip in local_ips):
  print("unknown")
else:
  print("no")
PY
}

status_command() {
  [[ $# -ge 1 ]] || fail "domain is required"
  local domain details_json dns_json public_json http_json python_bin mode
  domain="$(normalize_domain "$1")"
  python_bin="$(resolve_python)"
  mode="$(get_config_mode)"
  details_json="$(get_domain_details_json "${domain}")"
  dns_json="$(resolve_dns_json "${domain}")"
  public_json="$(get_public_ips_json)"
  http_json="$(probe_http_json "${domain}")"

  SSL_PROXY_MODE="${mode}" DETAILS_JSON="${details_json}" DNS_JSON="${dns_json}" PUBLIC_JSON="${public_json}" HTTP_JSON="${http_json}" "${python_bin}" - <<'PY'
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
http = json.loads(os.environ["HTTP_JSON"])

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
print(f'dns_error: {dns.get("error", "")}')
print(f'dns_cname: {", ".join(dns.get("cname", []))}')
print(f'dns_ipv4: {", ".join(dns.get("ipv4", []))}')
print(f'dns_ipv6: {", ".join(dns.get("ipv6", []))}')
print(f'local_public_ipv4: {public.get("ipv4", "")}')
print(f'local_public_ipv6: {public.get("ipv6", "")}')
print(f'local_public_ipv4_source: {public.get("source_ipv4", "")}')
print(f'local_public_ipv6_source: {public.get("source_ipv6", "")}')
print(f'points_to_this_host: {points_to_this_host}')
print(f'acme_http_reachable: {"yes" if http.get("reachable") else "no"}')
print(f'acme_http_status_code: {http.get("status_code", 0)}')
print(f'acme_http_redirect_location: {http.get("redirect_location", "")}')
print(f'acme_http_error: {http.get("error", "")}')
if not details_payload.get("ok"):
  sys.exit(1)
PY
}

check_command() {
  [[ $# -ge 1 ]] || fail "domain is required"
  local domain details_json dns_json public_json http_json python_bin mode
  domain="$(normalize_domain "$1")"
  python_bin="$(resolve_python)"
  mode="$(get_config_mode)"
  details_json="$(get_domain_details_json "${domain}")"
  dns_json="$(resolve_dns_json "${domain}")"
  public_json="$(get_public_ips_json)"
  http_json="$(probe_http_json "${domain}")"

  SSL_PROXY_MODE="${mode}" DETAILS_JSON="${details_json}" DNS_JSON="${dns_json}" PUBLIC_JSON="${public_json}" HTTP_JSON="${http_json}" "${python_bin}" - <<'PY'
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
http = json.loads(os.environ["HTTP_JSON"])

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
  ("dns_resolves", not bool(dns.get("error")), dns.get("error", "")),
  ("points_to_this_host", points_to_this_host is True, "unknown" if points_to_this_host is None else ""),
  ("acme_http_reachable", bool(http.get("reachable")), http.get("error") or str(http.get("status_code", 0))),
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
  command -v journalctl >/dev/null 2>&1 || fail "journalctl is required"
  journalctl -u ssl-proxy-controller.service -u caddy.service -n 300 --no-pager | grep -F "${domain}" || true
}

run_db_tool() {
  local python_bin config_path
  python_bin="$(resolve_python)"
  config_path="$(resolve_config_path)"

  SSL_PROXY_CONFIG="${config_path}" \
  "${python_bin}" - "$@" <<'PY'
from __future__ import annotations

import ipaddress
import os
import re
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
    raise SystemExit("wildcard domains are not supported with the current HTTP-01 flow")
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
    return f"127.0.0.1:{port}"

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


def main(argv: list[str]) -> int:
  if len(argv) < 2:
    raise SystemExit("missing subcommand")

  subcommand = argv[1]
  dsn = load_dsn(config_path=os.environ["SSL_PROXY_CONFIG"])

  try:
    with psycopg.connect(dsn, row_factory=dict_row, sslmode="require") as conn:
      with conn.cursor() as cur:
        if subcommand == "list":
          cur.execute(
            """
            SELECT
              r.domain,
              COALESCE(r.upstream_target, CASE WHEN r.upstream_port IS NULL THEN NULL ELSE '127.0.0.1:' || r.upstream_port::text END) AS upstream_target,
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

        if len(argv) < 3:
          raise SystemExit("domain is required")

        domain = validate_domain(argv[2])

        if subcommand == "get":
          cur.execute(
            """
            SELECT
              r.domain,
              COALESCE(r.upstream_target, CASE WHEN r.upstream_port IS NULL THEN NULL ELSE '127.0.0.1:' || r.upstream_port::text END) AS upstream_target,
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
                      COALESCE(upstream_target, CASE WHEN upstream_port IS NULL THEN NULL ELSE '127.0.0.1:' || upstream_port::text END) AS upstream_target,
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
                      COALESCE(upstream_target, CASE WHEN upstream_port IS NULL THEN NULL ELSE '127.0.0.1:' || upstream_port::text END) AS upstream_target,
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
          cur.execute("DELETE FROM routes WHERE domain = %s RETURNING domain", (domain,))
          route_row = cur.fetchone()
          cur.execute("DELETE FROM certificates WHERE domain = %s RETURNING domain", (domain,))
          certificate_row = cur.fetchone()
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
  command -v systemctl >/dev/null 2>&1 || fail "systemctl is required for sync-now"
  [[ "${EUID}" -eq 0 ]] || fail "sync-now requires root"
  systemctl restart ssl-proxy-controller.service
  log "controller restarted"
}

preflight_sync_now() {
  command -v systemctl >/dev/null 2>&1 || fail "systemctl is required for sync-now"
  [[ "${EUID}" -eq 0 ]] || fail "sync-now requires root"
}

main() {
  local subcommand="${1:-}"
  local sync_flag=0
  local force_flag=0
  shift || true

  while [[ $# -gt 0 ]]; do
    case "${!#}" in
      --sync-now)
        sync_flag=1
        set -- "${@:1:$(($#-1))}"
        ;;
      --force)
        if [[ "${subcommand}" == "issue-now" ]]; then
          force_flag=1
          set -- "${@:1:$(($#-1))}"
        else
          break
        fi
        ;;
      *)
        break
        ;;
    esac
  done

  case "${subcommand}" in
    list)
      run_db_tool list
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
    get|enable|disable|delete|purge|clear-target|clear-port|issue-now)
      [[ $# -ge 1 ]] || fail "domain is required"
      if [[ "${subcommand}" == "issue-now" && "$(get_config_mode)" != "readwrite" ]]; then
        fail "issue-now is only available on readwrite nodes"
      fi
      if [[ "${subcommand}" == "issue-now" || "${sync_flag}" -eq 1 ]]; then
        preflight_sync_now
      fi
      if [[ "${subcommand}" == "issue-now" && "${force_flag}" -ne 1 ]]; then
        local dns_state
        dns_state="$(domain_points_to_this_host "$1")"
        if [[ "${dns_state}" == "unknown" ]]; then
          fail "could not determine this host's public IPs; run '${PROGRAM_NAME} status $1' to inspect DNS, or use --force"
        fi
        if [[ "${dns_state}" == "dns_error" ]]; then
          fail "dns resolution failed; run '${PROGRAM_NAME} status $1' to inspect DNS, or use --force"
        fi
        if [[ "${dns_state}" != "yes" ]]; then
          fail "domain does not currently point to this host; run '${PROGRAM_NAME} status $1' to inspect DNS, or use --force"
        fi
      fi
      run_db_tool "$subcommand" "$1"
      if [[ "${subcommand}" == "issue-now" || "${sync_flag}" -eq 1 ]]; then
        sync_now
      fi
      ;;
    add)
      [[ $# -ge 1 ]] || fail "domain is required"
      if [[ "${sync_flag}" -eq 1 ]]; then
        preflight_sync_now
      fi
      if [[ $# -ge 2 ]]; then
        run_db_tool add "$1" "$2"
      else
        run_db_tool add "$1"
      fi
      if [[ "${sync_flag}" -eq 1 ]]; then
        sync_now
      fi
      ;;
    set-target|set-port)
      [[ $# -ge 2 ]] || fail "domain and upstream_target are required"
      if [[ "${sync_flag}" -eq 1 ]]; then
        preflight_sync_now
      fi
      run_db_tool set-target "$1" "$2"
      if [[ "${sync_flag}" -eq 1 ]]; then
        sync_now
      fi
      ;;
    clear-target|clear-port)
      [[ $# -ge 1 ]] || fail "domain is required"
      if [[ "${sync_flag}" -eq 1 ]]; then
        preflight_sync_now
      fi
      run_db_tool clear-target "$1"
      if [[ "${sync_flag}" -eq 1 ]]; then
        sync_now
      fi
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
