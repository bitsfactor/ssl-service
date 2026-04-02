from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ssl_proxy_controller.acme import ensure_dns_cloudflare_plugin, issue_certificate
from ssl_proxy_controller.db import DnsZoneTokenRecord
from ssl_proxy_controller.config import AcmeConfig, AppConfig, CaddyConfig, LoggingConfig, PathsConfig, PostgresConfig, SyncConfig


def make_config(tmp_path: Path) -> AppConfig:
  return AppConfig(
    mode="readwrite",
    postgres=PostgresConfig(dsn="postgresql://example"),
    sync=SyncConfig(),
    paths=PathsConfig(state_dir=tmp_path / "state", log_dir=tmp_path / "log"),
    caddy=CaddyConfig(reload_command=["/usr/bin/caddy", "reload"]),
    acme=AcmeConfig(email="ops@example.com"),
    logging=LoggingConfig(),
  )


class FakeDatabase:
  def get_dns_zone_token_for_domain(self, domain: str) -> DnsZoneTokenRecord | None:
    return DnsZoneTokenRecord(
      zone_name="example.com",
      provider="cloudflare",
      zone_id="zone-id",
      api_token="token",
      updated_at=datetime.now(tz=UTC),
    )


def test_issue_certificate_requires_email(tmp_path: Path) -> None:
  config = make_config(tmp_path)
  config.acme.email = ""

  with pytest.raises(ValueError, match="acme.email is required"):
    issue_certificate(config, FakeDatabase(), "example.com")


def test_issue_certificate_requires_zone_token(tmp_path: Path) -> None:
  class EmptyDatabase:
    def get_dns_zone_token_for_domain(self, domain: str):
      return None

  with pytest.raises(ValueError, match="no Cloudflare zone token configured"):
    issue_certificate(make_config(tmp_path), EmptyDatabase(), "example.com")


def test_issue_certificate_reads_certbot_output(monkeypatch, tmp_path: Path) -> None:
  config = make_config(tmp_path)
  command_calls: list[list[str]] = []
  original_path = Path

  def fake_run(command: list[str], check: bool, capture_output: bool = False, text: bool = False):
    command_calls.append(command)
    assert check is True
    if command == [config.paths.certbot_binary, "plugins"]:
      assert capture_output is True
      assert text is True
      return subprocess.CompletedProcess(command, 0, stdout="dns-cloudflare", stderr="")
    assert capture_output is False
    assert text is False
    return None

  def fake_path(value: str) -> Path:
    if value == "/etc/letsencrypt/live":
      return tmp_path / "letsencrypt" / "live"
    return original_path(value)

  key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
  certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(tz=UTC) - timedelta(days=1))
    .not_valid_after(datetime.now(tz=UTC) + timedelta(days=30))
    .sign(key, hashes.SHA256())
  )
  live_dir = tmp_path / "letsencrypt" / "live" / "example.com"
  live_dir.mkdir(parents=True)
  (live_dir / "fullchain.pem").write_text(certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8"))
  (live_dir / "privkey.pem").write_text(
    key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
  )

  monkeypatch.setattr(subprocess, "run", fake_run)
  monkeypatch.setattr("ssl_proxy_controller.acme.Path", fake_path)

  record = issue_certificate(config, FakeDatabase(), "example.com")

  assert len(command_calls) >= 2
  assert command_calls[0] == [config.paths.certbot_binary, "plugins"]
  assert "--dns-cloudflare" in command_calls[1]
  assert "--dns-cloudflare-credentials" in command_calls[1]
  assert record.domain == "example.com"
  assert record.status == "active"
  assert "BEGIN CERTIFICATE" in record.fullchain_pem
  assert "BEGIN RSA PRIVATE KEY" in record.private_key_pem


def test_ensure_dns_cloudflare_plugin_requires_plugin(monkeypatch) -> None:
  def fake_run(command: list[str], check: bool, capture_output: bool, text: bool):
    assert command == ["/usr/bin/certbot", "plugins"]
    assert check is True
    assert capture_output is True
    assert text is True
    return subprocess.CompletedProcess(command, 0, stdout="* nginx\nDescription", stderr="")

  monkeypatch.setattr(subprocess, "run", fake_run)

  with pytest.raises(RuntimeError, match="dns-cloudflare plugin is not available"):
    ensure_dns_cloudflare_plugin("/usr/bin/certbot")


def test_ensure_dns_cloudflare_plugin_wraps_probe_failure(monkeypatch) -> None:
  def fake_run(command: list[str], check: bool, capture_output: bool, text: bool):
    raise subprocess.CalledProcessError(1, command, output="", stderr="boom")

  monkeypatch.setattr(subprocess, "run", fake_run)

  with pytest.raises(RuntimeError, match="failed to inspect certbot plugins: boom"):
    ensure_dns_cloudflare_plugin("/usr/bin/certbot")
