from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ssl_proxy_controller.caddy import reload_caddy, render_caddyfile, state_payload, validate_upstream_target
from ssl_proxy_controller.db import CertificateRecord, RouteRecord


def make_certificate(domain: str) -> CertificateRecord:
  now = datetime.now(tz=UTC)
  return CertificateRecord(
    domain=domain,
    fullchain_pem="fullchain",
    private_key_pem="privkey",
    not_before=now,
    not_after=now,
    version=1,
    status="active",
    source="certbot",
    retry_after=None,
    updated_at=now,
    last_error=None,
  )


def test_render_caddyfile_renders_certificate_only_route_without_reverse_proxy(tmp_path: Path) -> None:
  output = tmp_path / "generated" / "Caddyfile"
  routes = [RouteRecord(domain="example.com", upstream_target=None, enabled=True, updated_at=datetime.now(tz=UTC))]
  certificates = {"example.com": make_certificate("example.com")}

  result = render_caddyfile(
    output_path=output,
    routes=routes,
    certificates=certificates,
    admin_address="127.0.0.1:2019",
  )

  content = output.read_text()
  assert "http://example.com" in content
  assert "redir https://{host}{uri} 308" in content
  assert 'respond "certificate-only route" 200' in content
  assert "reverse_proxy" not in content
  assert result.sha256


def test_render_caddyfile_redirects_http_to_https(tmp_path: Path) -> None:
  output = tmp_path / "generated" / "Caddyfile"
  routes = [RouteRecord(domain="example.com", upstream_target=None, enabled=True, updated_at=datetime.now(tz=UTC))]
  certificates = {"example.com": make_certificate("example.com")}

  render_caddyfile(
    output_path=output,
    routes=routes,
    certificates=certificates,
    admin_address="127.0.0.1:2019",
  )

  content = output.read_text()
  assert "redir https://{host}{uri} 308" in content


def test_render_caddyfile_skips_https_block_for_missing_certificate_material(tmp_path: Path) -> None:
  output = tmp_path / "generated" / "Caddyfile"
  routes = [RouteRecord(domain="example.com", upstream_target="127.0.0.1:8080", enabled=True, updated_at=datetime.now(tz=UTC))]
  now = datetime.now(tz=UTC)
  certificates = {
    "example.com": CertificateRecord(
      domain="example.com",
      fullchain_pem="",
      private_key_pem="",
      not_before=now,
      not_after=now,
      version=1,
      status="error",
      source="certbot",
      retry_after=now,
      updated_at=now,
      last_error="failed",
    )
  }

  render_caddyfile(
    output_path=output,
    routes=routes,
    certificates=certificates,
    admin_address="127.0.0.1:2019",
  )

  content = output.read_text()
  assert "http://example.com" not in content
  assert "https://example.com" not in content
  assert "reverse_proxy" not in content


def test_render_caddyfile_only_redirects_domains_with_certificate_material(tmp_path: Path) -> None:
  output = tmp_path / "generated" / "Caddyfile"
  now = datetime.now(tz=UTC)
  routes = [
    RouteRecord(domain="active.example.com", upstream_target="127.0.0.1:8080", enabled=True, updated_at=now),
    RouteRecord(domain="pending.example.com", upstream_target="127.0.0.1:9090", enabled=True, updated_at=now),
  ]
  certificates = {
    "active.example.com": make_certificate("active.example.com"),
    "pending.example.com": CertificateRecord(
      domain="pending.example.com",
      fullchain_pem="",
      private_key_pem="",
      not_before=now,
      not_after=now,
      version=1,
      status="error",
      source="certbot",
      retry_after=now,
      updated_at=now,
      last_error="failed",
    ),
  }

  render_caddyfile(
    output_path=output,
    routes=routes,
    certificates=certificates,
    admin_address="127.0.0.1:2019",
  )

  content = output.read_text()
  assert "http://active.example.com" in content
  assert "http://pending.example.com" not in content
  assert "https://active.example.com" in content
  assert "https://pending.example.com" not in content


def test_render_caddyfile_renders_reverse_proxy_for_service_route(tmp_path: Path) -> None:
  output = tmp_path / "generated" / "Caddyfile"
  routes = [RouteRecord(domain="example.com", upstream_target="10.0.0.25:6111", enabled=True, updated_at=datetime.now(tz=UTC))]
  certificates = {"example.com": make_certificate("example.com")}

  render_caddyfile(
    output_path=output,
    routes=routes,
    certificates=certificates,
    admin_address="127.0.0.1:2019",
  )

  content = output.read_text()
  assert "https://example.com" in content
  assert "reverse_proxy 10.0.0.25:6111" in content


def test_render_caddyfile_renders_ipv6_upstream_target(tmp_path: Path) -> None:
  output = tmp_path / "generated" / "Caddyfile"
  routes = [RouteRecord(domain="example.com", upstream_target="[2001:db8::10]:6111", enabled=True, updated_at=datetime.now(tz=UTC))]
  certificates = {"example.com": make_certificate("example.com")}

  render_caddyfile(
    output_path=output,
    routes=routes,
    certificates=certificates,
    admin_address="127.0.0.1:2019",
  )

  content = output.read_text()
  assert "reverse_proxy [2001:db8::10]:6111" in content


def test_reload_caddy_requires_reload_command() -> None:
  with pytest.raises(ValueError, match="must not be empty"):
    reload_caddy([])


def test_validate_upstream_target_rejects_invalid_value() -> None:
  with pytest.raises(ValueError, match="must not contain spaces or slashes"):
    validate_upstream_target("bad host:8080")


def test_reload_caddy_runs_subprocess(monkeypatch) -> None:
  calls: list[list[str]] = []

  def fake_run(command: list[str], check: bool) -> None:
    calls.append(command)
    assert check is True

  monkeypatch.setattr(subprocess, "run", fake_run)

  reload_caddy(["/usr/bin/caddy", "reload"])

  assert calls == [["/usr/bin/caddy", "reload"]]


def test_state_payload_is_sorted_json() -> None:
  payload = state_payload(
    caddy_sha256="abc",
    route_versions=[{"domain": "example.com", "updated_at": "2026-04-02T00:00:00+00:00"}],
    cert_versions=[{"domain": "example.com", "version": "2", "updated_at": "2026-04-02T00:00:00+00:00"}],
  )

  data = json.loads(payload)
  assert data["caddy_sha256"] == "abc"
  assert data["routes"][0]["domain"] == "example.com"
  assert data["certificates"][0]["version"] == "2"
