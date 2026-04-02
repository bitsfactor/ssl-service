from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .config import AppConfig
from .db import CertificateRecord


def issue_certificate(config: AppConfig, domain: str) -> CertificateRecord:
  if not config.acme.email:
    raise ValueError("acme.email is required in readwrite mode")
  if domain.startswith("*."):
    raise ValueError("wildcard domains are not supported with the current HTTP-01 flow")

  config.acme.webroot.mkdir(parents=True, exist_ok=True)
  cert_name = domain.replace("*", "wildcard")
  command = [
    config.paths.certbot_binary,
    "certonly",
    "--non-interactive",
    "--agree-tos",
    "--webroot",
    "--webroot-path",
    str(config.acme.webroot),
    "--email",
    config.acme.email,
    "--cert-name",
    cert_name,
    "-d",
    domain,
  ]
  if config.acme.staging:
    command.append("--test-cert")
  command.extend(config.acme.certbot_args)
  subprocess.run(command, check=True)

  live_dir = Path("/etc/letsencrypt/live") / cert_name
  fullchain_pem = live_dir.joinpath("fullchain.pem").read_text()
  private_key_pem = live_dir.joinpath("privkey.pem").read_text()

  certificate = x509.load_pem_x509_certificate(fullchain_pem.encode("utf-8"))
  private_key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
  normalized_key = private_key.private_bytes(
    encoding=Encoding.PEM,
    format=PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=NoEncryption(),
  ).decode("utf-8")

  return CertificateRecord(
    domain=domain,
    fullchain_pem=fullchain_pem,
    private_key_pem=normalized_key,
    not_before=certificate.not_valid_before_utc.astimezone(UTC),
    not_after=certificate.not_valid_after_utc.astimezone(UTC),
    version=1,
    status="active",
    source="certbot",
    retry_after=None,
    updated_at=datetime.now(tz=UTC),
    last_error=None,
  )
