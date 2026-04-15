from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .db import CertificateRecord, RouteRecord

DOCKER_HOST_GATEWAY_NAME = "host.docker.internal"


@dataclass(slots=True)
class RenderResult:
  path: Path
  sha256: str


def validate_upstream_target(upstream_target: str) -> str:
  candidate = upstream_target.strip()
  if not candidate:
    raise ValueError("upstream_target must not be empty")
  if any(ch.isspace() for ch in candidate) or "/" in candidate:
    raise ValueError("upstream_target must not contain spaces or slashes")

  if candidate.startswith("["):
    if "]:" not in candidate:
      raise ValueError("IPv6 upstream_target must use [addr]:port format")
    host, port_text = candidate[1:].split("]:", 1)
    try:
      host = str(ipaddress.ip_address(host))
    except ValueError as exc:
      raise ValueError(f"invalid IPv6 upstream_target host: {host}") from exc
    host = f"[{host}]"
  else:
    if candidate.count(":") != 1:
      raise ValueError("upstream_target must use host:port format")
    host, port_text = candidate.rsplit(":", 1)
    if not host:
      raise ValueError("upstream_target host must not be empty")
    try:
      host = str(ipaddress.ip_address(host))
    except ValueError:
      if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError("upstream_target host contains invalid characters")
      for label in host.split("."):
        if not label:
          raise ValueError("upstream_target host contains an empty label")
        if label.startswith("-") or label.endswith("-"):
          raise ValueError("upstream_target host contains an invalid label")
      host = host.lower()

  if not port_text.isdigit():
    raise ValueError("upstream_target port must be numeric")
  port = int(port_text)
  if port < 1 or port > 65535:
    raise ValueError("upstream_target port must be between 1 and 65535")
  return f"{host}:{port}"


def canonicalize_upstream_target_for_container(upstream_target: str) -> str:
  normalized = validate_upstream_target(upstream_target)
  if normalized.startswith("[::1]:"):
    return f"{DOCKER_HOST_GATEWAY_NAME}:{normalized.rsplit(':', 1)[1]}"

  host, port_text = normalized.rsplit(":", 1)
  if host in {"127.0.0.1", "localhost"}:
    return f"{DOCKER_HOST_GATEWAY_NAME}:{port_text}"
  return normalized


def render_caddyfile(
  output_path: Path,
  routes: list[RouteRecord],
  certificates: dict[str, CertificateRecord],
  admin_address: str,
  log_path: Path,
  log_roll_size_mb: int,
  log_roll_keep: int,
) -> RenderResult:
  active_route_domains = [
    route.domain
    for route in routes
    if (certificate := certificates.get(route.domain)) is not None
    and bool(certificate.fullchain_pem)
    and bool(certificate.private_key_pem)
  ]
  lines: list[str] = [
    "{",
    f"\tadmin {admin_address}",
    "\tlog {",
    f"\t\toutput file {log_path} {{",
    f"\t\t\troll_size {log_roll_size_mb}MiB",
    f"\t\t\troll_keep {log_roll_keep}",
    "\t\t}",
    "\t\tformat console",
    "\t}",
    "}",
    "",
  ]

  if active_route_domains:
    domains = " ".join(f"http://{domain}" for domain in active_route_domains)
    lines.extend(
      [
        f"{domains} {{",
        "\tredir https://{host}{uri} 308",
        "}",
        "",
      ]
    )

  for route in routes:
    certificate = certificates.get(route.domain)
    if certificate is None or not certificate.fullchain_pem or not certificate.private_key_pem:
      continue
    domain_dir = output_path.parent.parent / "certs" / route.domain
    block = [
      f"https://{route.domain} {{",
      f"\ttls {domain_dir / 'fullchain.pem'} {domain_dir / 'privkey.pem'}",
    ]
    if route.upstream_target is None:
      block.extend(
        [
          '\trespond "certificate-only route" 200',
        ]
      )
    else:
      block.extend(
        [
          f"\treverse_proxy {canonicalize_upstream_target_for_container(route.upstream_target)}",
        ]
      )
    block.extend(
      [
        "}",
        "",
      ]
    )
    lines.extend(block)

  content = "\n".join(lines)
  output_path.parent.mkdir(parents=True, exist_ok=True)
  output_path.write_text(content)
  return RenderResult(path=output_path, sha256=hashlib.sha256(content.encode("utf-8")).hexdigest())


def reload_caddy(reload_command: list[str]) -> None:
  if not reload_command:
    raise ValueError("caddy reload_command must not be empty")
  subprocess.run(reload_command, check=True)


def state_payload(caddy_sha256: str, route_versions: list[dict[str, str]], cert_versions: list[dict[str, str]]) -> str:
  return json.dumps(
    {
      "caddy_sha256": caddy_sha256,
      "routes": route_versions,
      "certificates": cert_versions,
    },
    indent=2,
    sort_keys=True,
  )
