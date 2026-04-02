from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .db import CertificateRecord, RouteRecord


@dataclass(slots=True)
class RenderResult:
  path: Path
  sha256: str


def render_caddyfile(
  output_path: Path,
  routes: list[RouteRecord],
  certificates: dict[str, CertificateRecord],
  acme_webroot: Path,
  admin_address: str,
) -> RenderResult:
  lines: list[str] = [
    "{",
    f"  admin {admin_address}",
    "}",
    "",
  ]

  challenge_domains = [route.domain for route in routes]
  if challenge_domains:
    domains = " ".join(f"http://{domain}" for domain in challenge_domains)
    lines.extend(
      [
        f"{domains} {{",
        "  handle /.well-known/acme-challenge/* {",
        f"    root * {acme_webroot}",
        "    file_server",
        "  }",
        "  redir https://{host}{uri} 308",
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
      f"  tls {domain_dir / 'fullchain.pem'} {domain_dir / 'privkey.pem'}",
    ]
    if route.upstream_port is None:
      block.extend(
        [
          "  respond \"certificate-only route\" 200",
        ]
      )
    else:
      block.extend(
        [
          f"  reverse_proxy 127.0.0.1:{route.upstream_port}",
        ]
      )
    block.extend(
      [
        "}",
        "",
      ]
    )
    lines.extend(block)

  content = "\n".join(lines).strip() + "\n"
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
