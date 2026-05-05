from __future__ import annotations

import argparse
import json
import logging
import shutil
import signal
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit

from .acme import issue_certificate
from .admin import AdminServer
from .caddy import reload_caddy, render_caddyfile, state_payload
from .config import AppConfig, load_config, load_config_from_env
from .db import CertificateRecord, Database, RouteRecord


LOGGER = logging.getLogger("ssl_proxy_controller")


def normalize_admin_address(admin_url: str) -> str:
  value = (admin_url or "").strip()
  if not value:
    raise ValueError("caddy admin_url must not be empty")
  if "://" in value:
    parsed = urlsplit(value)
    if parsed.netloc:
      return parsed.netloc
    if parsed.path:
      return parsed.path
  return value


class Controller:
  def __init__(self, config: AppConfig) -> None:
    self.config = config
    self.database = Database(config.postgres.dsn)
    self.state_dir = config.paths.state_dir
    self.generated_dir = self.state_dir / "generated"
    self.certs_dir = self.state_dir / "certs"
    self.runtime_state_path = self.state_dir / "state" / "state.json"
    self._running = True
    # Event used to break out of time.sleep() promptly on SIGTERM/SIGINT
    # — without it, the controller can sit in sleep() for tens of seconds
    # after a stop signal, which makes container restarts feel slow.
    self._stop_event = threading.Event()
    # Honor the registry's selected entry at startup. The bootstrap DSN
    # gets us into the database so we can read system_config; if the
    # operator previously hit Activate on a different entry, swap
    # over to it. This survives the absence of any local YAML file.
    try:
      from . import db_registry as _reg  # local import to avoid cycle
      active = _reg.get_active_dsn(self.database)
      if active and active != config.postgres.dsn:
        LOGGER.info("Controller: registry-selected DSN differs from "
                    "bootstrap DSN; swapping pool to selected DSN")
        self.database.swap_to(active)
    except Exception:  # noqa: BLE001
      LOGGER.exception("Controller: could not read registry selected entry; "
                       "staying on bootstrap DSN")

  def ensure_directories(self) -> None:
    for path in [
      self.state_dir,
      self.generated_dir,
      self.certs_dir,
      self.state_dir / "state",
      self.config.paths.log_dir,
    ]:
      path.mkdir(parents=True, exist_ok=True)

  def stop(self, *_args: object) -> None:
    self._running = False
    # Wake any thread blocked in self._stop_event.wait(...) so the
    # main loop returns immediately instead of sleeping out the
    # remainder of poll_interval_seconds.
    try:
      self._stop_event.set()
    except Exception:  # noqa: BLE001
      pass

  def run_forever(self) -> None:
    self.ensure_directories()
    signal.signal(signal.SIGTERM, self.stop)
    signal.signal(signal.SIGINT, self.stop)

    admin_server: AdminServer | None = None
    if self.config.admin.enabled:
      admin_server = AdminServer(self.config, self.database)
      try:
        admin_server.start()
      except OSError as exc:
        LOGGER.error("failed to start admin server on %s:%s: %s",
                     self.config.admin.bind, self.config.admin.port, exc)
        admin_server = None

    try:
      while self._running:
        try:
          self.run_once()
        except Exception:
          LOGGER.exception("controller loop failed")
          if not self._running:
            break
          # Interruptible sleep — wakes on stop signal so the loop
          # exits promptly instead of waiting out the full backoff.
          if self._stop_event.wait(self.config.sync.loop_error_backoff_seconds):
            break
          continue
        if not self._running:
          break
        if self._stop_event.wait(self.config.sync.poll_interval_seconds):
          break
    finally:
      if admin_server is not None:
        admin_server.stop()

  def run_once(self) -> None:
    routes = self.database.fetch_routes()
    certificates = self.database.fetch_certificates()

    if self.config.mode == "readwrite":
      self._renew_if_needed(routes, certificates)
      certificates = self.database.fetch_certificates()

    managed_certificates = self._managed_certificates(routes, certificates)
    changed = self._sync_local_certificates(managed_certificates)
    caddy_changed = self._write_caddyfile(routes, managed_certificates)
    if changed or caddy_changed:
      reload_caddy(self.config.caddy.reload_command)
    self._write_state_file(routes, managed_certificates)

  @staticmethod
  def _managed_certificates(
    routes: list[RouteRecord],
    certificates: dict[str, CertificateRecord],
  ) -> dict[str, CertificateRecord]:
    route_domains = {route.domain for route in routes}
    return {
      domain: certificate
      for domain, certificate in certificates.items()
      if domain in route_domains
    }

  def _renew_if_needed(
    self,
    routes: list[RouteRecord],
    certificates: dict[str, CertificateRecord],
  ) -> None:
    threshold = datetime.now(tz=UTC) + timedelta(days=self.config.sync.renew_before_days)
    domains = [route.domain for route in routes]

    with self.database.connect() as connection:
      for domain in domains:
        current = certificates.get(domain)
        if current is not None and current.not_after > threshold:
          continue
        if current is not None and current.retry_after is not None and current.retry_after > datetime.now(tz=UTC):
          LOGGER.debug("renewal skipped because retry_after is in the future: %s", domain)
          continue
        lock_key = f"certificate:{domain}"
        if not self.database.try_advisory_lock(connection, lock_key):
          LOGGER.info("renewal skipped because advisory lock is held: %s", domain)
          continue
        try:
          LOGGER.info("issuing or renewing certificate for %s", domain)
          certificate = issue_certificate(self.config, self.database, domain)
          self.database.upsert_certificate(certificate)
        except Exception as exc:
          LOGGER.exception("certificate issuance failed for %s", domain)
          retry_after = datetime.now(tz=UTC) + timedelta(seconds=self.config.sync.retry_backoff_seconds)
          try:
            self.database.record_certificate_error(domain, str(exc), retry_after)
          except Exception:  # noqa: BLE001
            LOGGER.exception("could not record certificate error for %s", domain)
        finally:
          # Never let an unlock failure mask the original exception
          # path or break the surrounding loop iteration.
          try:
            self.database.unlock(connection, lock_key)
          except Exception:  # noqa: BLE001
            LOGGER.exception("failed to release advisory lock for %s", domain)

  def _sync_local_certificates(self, certificates: dict[str, CertificateRecord]) -> bool:
    changed = False
    active_domains = {
      domain
      for domain, certificate in certificates.items()
      if certificate.fullchain_pem and certificate.private_key_pem
    }

    for domain_dir in self.certs_dir.iterdir() if self.certs_dir.exists() else []:
      if domain_dir.is_dir() and domain_dir.name not in active_domains:
        shutil.rmtree(domain_dir)
        changed = True

    for domain, certificate in certificates.items():
      if not certificate.fullchain_pem or not certificate.private_key_pem:
        continue
      domain_dir = self.certs_dir / domain
      domain_dir.mkdir(parents=True, exist_ok=True)
      if self._atomic_write(domain_dir / "fullchain.pem", certificate.fullchain_pem):
        changed = True
      if self._atomic_write(domain_dir / "privkey.pem", certificate.private_key_pem):
        changed = True

    return changed

  def _write_caddyfile(
    self,
    routes: list[RouteRecord],
    certificates: dict[str, CertificateRecord],
  ) -> bool:
    output_path = self.generated_dir / "Caddyfile"
    render_result = render_caddyfile(
      output_path=output_path,
      routes=routes,
      certificates=certificates,
      admin_address=normalize_admin_address(self.config.caddy.admin_url),
      log_path=Path(self.config.logging.caddy_log_path),
      log_roll_size_mb=self.config.logging.caddy_log_roll_size_mb,
      log_roll_keep=self.config.logging.caddy_log_roll_keep,
    )
    prior_state = self._read_runtime_state()
    return prior_state.get("caddy_sha256") != render_result.sha256

  def _write_state_file(
    self,
    routes: list[RouteRecord],
    certificates: dict[str, CertificateRecord],
  ) -> None:
    caddy_content = (self.generated_dir / "Caddyfile").read_text()
    payload = state_payload(
      caddy_sha256=self._sha256(caddy_content),
      route_versions=[
        {"domain": route.domain, "updated_at": route.updated_at.isoformat()}
        for route in routes
      ],
      cert_versions=[
        {"domain": cert.domain, "version": str(cert.version), "updated_at": cert.updated_at.isoformat()}
        for cert in certificates.values()
      ],
    )
    self.runtime_state_path.parent.mkdir(parents=True, exist_ok=True)
    self.runtime_state_path.write_text(payload)

  def _read_runtime_state(self) -> dict[str, object]:
    if not self.runtime_state_path.exists():
      return {}
    try:
      return json.loads(self.runtime_state_path.read_text())
    except json.JSONDecodeError:
      return {}

  @staticmethod
  def _sha256(content: str) -> str:
    import hashlib

    return hashlib.sha256(content.encode("utf-8")).hexdigest()

  @staticmethod
  def _atomic_write(path: Path, content: str) -> bool:
    if path.exists() and path.read_text() == content:
      return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
      handle.write(content)
      temp_path = Path(handle.name)
    temp_path.replace(path)
    return True


def parse_args(argv: list[str]) -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="ssl proxy controller")
  # --config is optional; when absent (typical for deployed containers)
  # we build an AppConfig directly from SSL_SERVICE_* environment vars.
  # Local dev still uses --config to point at a YAML file.
  parser.add_argument("--config", required=False, default=None,
                      help="path to YAML config (omit for env-only)")
  parser.add_argument("--once", action="store_true", help="run one sync iteration and exit")
  parser.add_argument(
    "--admin-only",
    action="store_true",
    help="run only the admin server (useful for testing or dedicated admin nodes)",
  )
  return parser.parse_args(argv)


def configure_logging(config: AppConfig) -> None:
  level = getattr(logging, config.logging.level.upper(), logging.INFO)
  controller_log_path = Path(config.logging.controller_log_path)
  controller_log_path.parent.mkdir(parents=True, exist_ok=True)
  logging.basicConfig(
    level=level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
      logging.StreamHandler(sys.stdout),
      RotatingFileHandler(
        controller_log_path,
        maxBytes=config.logging.controller_log_max_bytes,
        backupCount=config.logging.controller_log_backup_count,
        encoding="utf-8",
      ),
    ],
    force=True,
  )


def main(argv: list[str] | None = None) -> int:
  args = parse_args(argv or sys.argv[1:])
  if args.config:
    config = load_config(args.config)
  else:
    # Env-only mode for deployed containers — the platform writes
    # SSL_SERVICE_* env vars via the .env file passed to compose.
    config = load_config_from_env()
  configure_logging(config)

  controller = Controller(config)
  if args.once:
    controller.ensure_directories()
    controller.run_once()
    return 0

  if args.admin_only:
    if not config.admin.enabled:
      LOGGER.error("admin-only mode requires admin.enabled to be true in config")
      return 2
    controller.ensure_directories()
    admin_server = AdminServer(config, controller.database)
    admin_server.start()
    signal.signal(signal.SIGTERM, controller.stop)
    signal.signal(signal.SIGINT, controller.stop)
    try:
      while controller._running:
        # Use the controller's stop_event for interruptible sleep.
        # On SIGTERM/SIGINT, controller.stop() sets the event and the
        # wait returns immediately.
        if controller._stop_event.wait(timeout=1):
          break
    finally:
      admin_server.stop()
    return 0

  controller.run_forever()
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
