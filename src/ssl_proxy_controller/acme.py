from __future__ import annotations

import json
import logging
import os
import stat
import subprocess
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .config import AppConfig
from .db import CertificateRecord, Database


LOGGER = logging.getLogger("ssl_proxy_controller.acme")


# Cloudflare returns one of these phrases when a TXT record with the same
# (name, content) already exists for a zone. We don't want to depend on the
# exact wording — partial match against any of these is enough to trigger
# the cleanup-and-retry path. The PROACTIVE cleanup that always runs
# before certbot makes hitting this recovery branch unlikely, but we keep
# it as a safety net for races (e.g. a parallel renewal somewhere else).
#
# Markers are deliberately specific. We did NOT include the substring
# ``_acme-challenge`` here because it appears in unrelated errors too
# (e.g. "your account is suspended; the _acme-challenge zone is blocked")
# and would cause us to retry against errors that won't be fixed by
# deleting records.
_CLOUDFLARE_RECORD_EXISTS_MARKERS: tuple[str, ...] = (
  "An identical record already exists",
  "Record already exists",
  "DNS Validation Error",
  "An A, AAAA, or CNAME record",  # rare interaction (CNAME blocks TXT)
)


def _cloudflare_error_is_existing_record(details: str) -> bool:
  return any(marker in details for marker in _CLOUDFLARE_RECORD_EXISTS_MARKERS)


def ensure_dns_cloudflare_plugin(certbot_binary: str) -> None:
  try:
    result = subprocess.run(
      [certbot_binary, "plugins"],
      check=True,
      capture_output=True,
      text=True,
    )
  except FileNotFoundError as exc:
    raise RuntimeError(f"certbot binary not found: {certbot_binary}") from exc
  except subprocess.CalledProcessError as exc:
    stderr = (exc.stderr or "").strip()
    stdout = (exc.stdout or "").strip()
    details = stderr or stdout or str(exc)
    raise RuntimeError(f"failed to inspect certbot plugins: {details}") from exc

  plugin_output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
  if "dns-cloudflare" not in plugin_output:
    raise RuntimeError(
      "certbot dns-cloudflare plugin is not available; rebuild or update the ssl-service container image"
    )


@contextmanager
def cloudflare_credentials_file(api_token: str):
  with NamedTemporaryFile("w", delete=False) as handle:
    handle.write(f"dns_cloudflare_api_token = {api_token}\n")
    temp_path = Path(handle.name)
  os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
  try:
    yield temp_path
  finally:
    temp_path.unlink(missing_ok=True)


def _cloudflare_request(zone_token: str, method: str, url: str) -> dict:
  request = urllib.request.Request(
    url,
    method=method,
    headers={
      "Authorization": f"Bearer {zone_token}",
      "Content-Type": "application/json",
    },
  )
  with urllib.request.urlopen(request, timeout=20) as response:
    return json.load(response)


def _cleanup_cloudflare_acme_txt_records(zone_id: str, zone_token: str, domain: str) -> None:
  validation_name = f"_acme-challenge.{domain}".rstrip(".")
  params = urllib.parse.urlencode(
    {
      "type": "TXT",
      "name": validation_name,
      "per_page": "100",
    }
  )
  records_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?{params}"
  payload = _cloudflare_request(zone_token, "GET", records_url)
  for record in payload.get("result", []):
    record_id = record.get("id")
    if not record_id:
      continue
    delete_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    _cloudflare_request(zone_token, "DELETE", delete_url)


def _run_certbot_with_cloudflare_recovery(command: list[str], zone_id: str, zone_token: str, domain: str) -> None:
  # PROACTIVE cleanup: always purge any pre-existing _acme-challenge TXT
  # records for this domain before invoking certbot. This is the user-
  # facing fix for "if a DNS record already exists, validation fails on
  # the second add". Stale records from a prior interrupted run, a
  # parallel renewer, or a previously-cancelled certbot session no longer
  # block us — we just delete them.
  #
  # Idempotent + safe: if there are no records, the cleanup is a no-op.
  # If there are some, removing them only affects in-flight ACME validation,
  # which we are about to recreate from scratch anyway.
  try:
    _cleanup_cloudflare_acme_txt_records(zone_id, zone_token, domain)
  except Exception as exc:
    # If the cleanup itself fails (e.g. transient network), don't abort
    # the cert issuance — fall through to certbot which will surface the
    # real error if any. The reactive recovery path below still catches
    # the case where the records weren't deletable in time. We log so a
    # human investigating recurring ACME failures has a breadcrumb.
    LOGGER.warning(
      "acme: proactive cleanup for %s failed (%s: %s); continuing with certbot",
      domain, type(exc).__name__, exc,
    )

  try:
    subprocess.run(command, check=True)
    return
  except subprocess.CalledProcessError as exc:
    details = " ".join(part for part in [str(exc), getattr(exc, "stderr", "") or "", getattr(exc, "stdout", "") or ""] if part)
    if not _cloudflare_error_is_existing_record(details):
      raise

  # Reactive recovery: cleanup again (a record may have been re-created
  # between our pre-cleanup and the certbot call by some race) and retry.
  _cleanup_cloudflare_acme_txt_records(zone_id, zone_token, domain)
  subprocess.run(command, check=True)


def issue_certificate(config: AppConfig, database: Database, domain: str) -> CertificateRecord:
  if not config.acme.email:
    raise ValueError("acme.email is required in readwrite mode")

  zone_token = database.get_dns_zone_token_for_domain(domain)
  if zone_token is None:
    raise ValueError(f"no Cloudflare zone token configured for domain: {domain}")

  ensure_dns_cloudflare_plugin(config.paths.certbot_binary)

  cert_name = domain.replace("*", "wildcard")
  with cloudflare_credentials_file(zone_token.api_token) as credentials_path:
    command = [
      config.paths.certbot_binary,
      "certonly",
      "--non-interactive",
      "--agree-tos",
      "--dns-cloudflare",
      "--dns-cloudflare-credentials",
      str(credentials_path),
      "--dns-cloudflare-propagation-seconds",
      str(config.acme.dns_propagation_seconds),
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
    _run_certbot_with_cloudflare_recovery(command, zone_token.zone_id, zone_token.api_token, domain)

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
