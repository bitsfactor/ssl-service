from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .db import CertificateRecord, RouteRecord

LOGGER = logging.getLogger("ssl_proxy_controller.caddy")

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


def canonicalize_upstream_for_container(host: str, port: int) -> tuple[str, int]:
  """Loopback rewrite, structured form. Caddy runs in a container; when an
  operator points an upstream at the host's loopback (127.0.0.1, localhost,
  [::1]) we silently rewrite to ``host.docker.internal`` so the connection
  actually reaches the host instead of the container's own loopback.

  Returns a (host, port) pair so the caller can render IPv6 brackets the
  way it prefers.
  """
  if host in {"127.0.0.1", "localhost", "::1", "[::1]"}:
    return DOCKER_HOST_GATEWAY_NAME, port
  return host, port


def canonicalize_upstream_target_for_container(upstream_target: str) -> str:
  """Legacy string-based wrapper around :func:`canonicalize_upstream_for_container`.
  Kept for callers that still hand us a "host:port" string."""
  normalized = validate_upstream_target(upstream_target)
  if normalized.startswith("["):
    # IPv6 bracketed form. partition("]:") strips the close bracket; we
    # add it back so the host string we hand to canonicalize_* still
    # has both brackets — the rewrite rule looks for the literal "[::1]".
    bracketed_host, _, port_text = normalized.partition("]:")
    host = bracketed_host + "]"
    port = int(port_text)
  else:
    host, _, port_text = normalized.rpartition(":")
    port = int(port_text)
  new_host, new_port = canonicalize_upstream_for_container(host, port)
  return f"{new_host}:{new_port}"


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
    # A route has upstreams if the route_upstreams table has rows for
    # it; we fall back to the legacy single upstream_target for old
    # callers (tests, seed data) that still construct RouteRecord with
    # only that field.
    targets: list[str] = []
    if route.upstreams:
      # Structured path: read target_host / target_port directly off
      # each UpstreamRecord and apply the loopback rewrite without
      # round-tripping through a string.
      for up in route.upstreams:
        new_host, new_port = canonicalize_upstream_for_container(
          up.target_host, up.target_port,
        )
        targets.append(f"{new_host}:{new_port}")
    elif route.upstream_target is not None:
      # Legacy fallback for routes that pre-date route_upstreams.
      targets = [canonicalize_upstream_target_for_container(route.upstream_target)]

    if not targets:
      block.append('\trespond "certificate-only route" 200')
    else:
      policy = (route.lb_policy or "random").strip()
      joined = " ".join(targets)
      if len(targets) == 1 and policy == "random":
        # Keep the simple single-line form for the common case, so
        # diffs against older-generated Caddyfiles stay minimal.
        block.append(f"\treverse_proxy {joined}")
      else:
        block.append(f"\treverse_proxy {joined} {{")
        # "random" is Caddy's default; we still emit it explicitly
        # when there are multiple upstreams so the policy is
        # self-documenting in the generated config.
        block.append(f"\t\tlb_policy {policy}")
        block.append("\t}")
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


def reload_caddy(reload_command: list[str], *, timeout: float = 30.0) -> None:
  if not reload_command:
    raise ValueError("caddy reload_command must not be empty")
  # Capture output so a failed reload produces a useful log line — the
  # default subprocess.run inherits stdout/stderr, which means under a
  # systemd unit the operator only sees the exit code, not the parse
  # error. We also set a hard timeout so a hung Caddy admin endpoint
  # doesn't block the controller's main loop.
  try:
    result = subprocess.run(
      reload_command,
      check=False,
      capture_output=True,
      text=True,
      timeout=timeout,
    )
  except subprocess.TimeoutExpired as exc:
    raise RuntimeError(
      f"caddy reload timed out after {timeout}s: {' '.join(reload_command)}"
    ) from exc
  if result.returncode != 0:
    details = (result.stderr or result.stdout or "").strip()
    LOGGER.error("caddy reload failed (exit %d): %s",
                 result.returncode, details or "<no output>")
    raise subprocess.CalledProcessError(
      result.returncode, reload_command,
      output=result.stdout, stderr=result.stderr,
    )


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
