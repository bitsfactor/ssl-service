from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ssl_proxy_controller.config import AcmeConfig, AppConfig, CaddyConfig, LoggingConfig, PathsConfig, PostgresConfig, SyncConfig
from ssl_proxy_controller.controller import Controller, main, normalize_admin_address, parse_args
from ssl_proxy_controller.db import CertificateRecord, RouteRecord


def make_config(tmp_path: Path) -> AppConfig:
  return AppConfig(
    mode="readwrite",
    postgres=PostgresConfig(dsn="postgresql://example"),
    sync=SyncConfig(poll_interval_seconds=1, renew_before_days=30, retry_backoff_seconds=3600, loop_error_backoff_seconds=1),
    paths=PathsConfig(state_dir=tmp_path / "state", log_dir=tmp_path / "log"),
    caddy=CaddyConfig(admin_url="http://127.0.0.1:2019", reload_command=["/usr/bin/true"]),
    acme=AcmeConfig(email="ops@example.com", staging=False),
    logging=LoggingConfig(level="INFO"),
  )


def make_certificate(domain: str, *, not_after: datetime, retry_after: datetime | None = None, status: str = "active") -> CertificateRecord:
  now = datetime.now(tz=UTC)
  return CertificateRecord(
    domain=domain,
    fullchain_pem="fullchain" if status == "active" else "",
    private_key_pem="privkey" if status == "active" else "",
    not_before=now,
    not_after=not_after,
    version=1,
    status=status,
    source="certbot",
    retry_after=retry_after,
    updated_at=now,
    last_error=None,
  )


class FakeDatabase:
  def __init__(self) -> None:
    self.upserted: list[CertificateRecord] = []
    self.errors: list[tuple[str, str, datetime]] = []
    self.lock_attempts: list[str] = []
    self.unlocks: list[str] = []
    self.lock_result = True

  class _Connection:
    pass

  class _Ctx:
    def __enter__(self) -> "FakeDatabase._Connection":
      return FakeDatabase._Connection()

    def __exit__(self, exc_type, exc, tb) -> None:
      return None

  def connect(self) -> "FakeDatabase._Ctx":
    return FakeDatabase._Ctx()

  def try_advisory_lock(self, connection, key: str) -> bool:
    self.lock_attempts.append(key)
    return self.lock_result

  def unlock(self, connection, key: str) -> None:
    self.unlocks.append(key)

  def upsert_certificate(self, certificate: CertificateRecord) -> None:
    self.upserted.append(certificate)

  def record_certificate_error(self, domain: str, last_error: str, retry_after: datetime) -> None:
    self.errors.append((domain, last_error, retry_after))


def test_renew_skips_when_retry_after_is_in_future(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  fake_db = FakeDatabase()
  controller.database = fake_db
  route = RouteRecord(domain="example.com", upstream_target=None, enabled=True, updated_at=datetime.now(tz=UTC))
  cert = make_certificate(
    "example.com",
    not_after=datetime.now(tz=UTC) - timedelta(days=1),
    retry_after=datetime.now(tz=UTC) + timedelta(hours=1),
    status="error",
  )

  controller._renew_if_needed([route], {"example.com": cert})

  assert fake_db.lock_attempts == []
  assert fake_db.upserted == []
  assert fake_db.errors == []


def test_renew_records_error_with_backoff_on_failure(tmp_path: Path, monkeypatch) -> None:
  controller = Controller(make_config(tmp_path))
  fake_db = FakeDatabase()
  controller.database = fake_db
  route = RouteRecord(domain="example.com", upstream_target=None, enabled=True, updated_at=datetime.now(tz=UTC))

  def fail_issue(*args, **kwargs):
    raise RuntimeError("boom")

  monkeypatch.setattr("ssl_proxy_controller.controller.issue_certificate", fail_issue)

  before = datetime.now(tz=UTC)
  controller._renew_if_needed([route], {})
  after = datetime.now(tz=UTC)

  assert fake_db.lock_attempts == ["certificate:example.com"]
  assert fake_db.upserted == []
  assert len(fake_db.errors) == 1
  domain, last_error, retry_after = fake_db.errors[0]
  assert domain == "example.com"
  assert "boom" in last_error
  assert before + timedelta(seconds=3599) <= retry_after <= after + timedelta(seconds=3601)
  assert fake_db.unlocks == ["certificate:example.com"]


def test_renew_upserts_certificate_on_success(tmp_path: Path, monkeypatch) -> None:
  controller = Controller(make_config(tmp_path))
  fake_db = FakeDatabase()
  controller.database = fake_db
  route = RouteRecord(domain="example.com", upstream_target="127.0.0.1:6111", enabled=True, updated_at=datetime.now(tz=UTC))
  certificate = make_certificate("example.com", not_after=datetime.now(tz=UTC) + timedelta(days=90))

  monkeypatch.setattr("ssl_proxy_controller.controller.issue_certificate", lambda *_args, **_kwargs: certificate)

  controller._renew_if_needed([route], {})

  assert fake_db.upserted == [certificate]
  assert fake_db.errors == []
  assert fake_db.unlocks == ["certificate:example.com"]


def test_renew_skips_when_certificate_is_still_valid(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  fake_db = FakeDatabase()
  controller.database = fake_db
  route = RouteRecord(domain="example.com", upstream_target=None, enabled=True, updated_at=datetime.now(tz=UTC))
  cert = make_certificate("example.com", not_after=datetime.now(tz=UTC) + timedelta(days=90))

  controller._renew_if_needed([route], {"example.com": cert})

  assert fake_db.lock_attempts == []
  assert fake_db.upserted == []


def test_renew_skips_when_advisory_lock_not_acquired(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  fake_db = FakeDatabase()
  fake_db.lock_result = False
  controller.database = fake_db
  route = RouteRecord(domain="example.com", upstream_target=None, enabled=True, updated_at=datetime.now(tz=UTC))

  controller._renew_if_needed([route], {})

  assert fake_db.lock_attempts == ["certificate:example.com"]
  assert fake_db.upserted == []
  assert fake_db.unlocks == []


def test_sync_local_certificates_removes_stale_and_writes_active(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  controller.ensure_directories()

  stale_dir = controller.certs_dir / "stale.example.com"
  stale_dir.mkdir(parents=True)
  (stale_dir / "fullchain.pem").write_text("old")

  certificate = make_certificate("active.example.com", not_after=datetime.now(tz=UTC) + timedelta(days=10))

  changed = controller._sync_local_certificates({"active.example.com": certificate})

  assert changed is True
  assert not stale_dir.exists()
  assert (controller.certs_dir / "active.example.com" / "fullchain.pem").read_text() == "fullchain"
  assert (controller.certs_dir / "active.example.com" / "privkey.pem").read_text() == "privkey"


def test_sync_local_certificates_removes_stale_nested_directories(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  controller.ensure_directories()

  stale_dir = controller.certs_dir / "stale.example.com"
  (stale_dir / "archive").mkdir(parents=True)
  (stale_dir / "archive" / "fullchain.pem").write_text("old")

  certificate = make_certificate("active.example.com", not_after=datetime.now(tz=UTC) + timedelta(days=10))

  changed = controller._sync_local_certificates({"active.example.com": certificate})

  assert changed is True
  assert not stale_dir.exists()


def test_atomic_write_returns_false_when_content_is_unchanged(tmp_path: Path) -> None:
  path = tmp_path / "certs" / "example.com" / "fullchain.pem"

  assert Controller._atomic_write(path, "same") is True
  assert Controller._atomic_write(path, "same") is False
  assert path.read_text() == "same"


def test_sync_local_certificates_ignores_empty_material(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  controller.ensure_directories()
  now = datetime.now(tz=UTC)

  changed = controller._sync_local_certificates(
    {
      "error.example.com": CertificateRecord(
        domain="error.example.com",
        fullchain_pem="",
        private_key_pem="",
        not_before=now,
        not_after=now,
        version=1,
        status="error",
        source="certbot",
        retry_after=now,
        updated_at=now,
        last_error="boom",
      )
    }
  )

  assert changed is False
  assert not (controller.certs_dir / "error.example.com").exists()


def test_sync_local_certificates_removes_stale_dir_when_record_has_no_material(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  controller.ensure_directories()
  stale_dir = controller.certs_dir / "error.example.com"
  stale_dir.mkdir(parents=True)
  (stale_dir / "fullchain.pem").write_text("old")
  now = datetime.now(tz=UTC)

  changed = controller._sync_local_certificates(
    {
      "error.example.com": CertificateRecord(
        domain="error.example.com",
        fullchain_pem="",
        private_key_pem="",
        not_before=now,
        not_after=now,
        version=1,
        status="error",
        source="certbot",
        retry_after=now,
        updated_at=now,
        last_error="boom",
      )
    }
  )

  assert changed is True
  assert not stale_dir.exists()


def test_sync_local_certificates_keeps_existing_material_when_status_is_error(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  controller.ensure_directories()
  domain_dir = controller.certs_dir / "error.example.com"
  domain_dir.mkdir(parents=True)
  (domain_dir / "fullchain.pem").write_text("old-fullchain")
  (domain_dir / "privkey.pem").write_text("old-privkey")
  now = datetime.now(tz=UTC)

  changed = controller._sync_local_certificates(
    {
      "error.example.com": CertificateRecord(
        domain="error.example.com",
        fullchain_pem="old-fullchain",
        private_key_pem="old-privkey",
        not_before=now,
        not_after=now,
        version=3,
        status="error",
        source="certbot",
        retry_after=now,
        updated_at=now,
        last_error="boom",
      )
    }
  )

  assert changed is False
  assert (domain_dir / "fullchain.pem").read_text() == "old-fullchain"
  assert (domain_dir / "privkey.pem").read_text() == "old-privkey"


def test_write_caddyfile_detects_unchanged_hash(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  controller.ensure_directories()
  route = RouteRecord(domain="example.com", upstream_target=None, enabled=True, updated_at=datetime.now(tz=UTC))
  certificate = make_certificate("example.com", not_after=datetime.now(tz=UTC) + timedelta(days=10))

  first_changed = controller._write_caddyfile([route], {"example.com": certificate})
  controller._write_state_file([route], {"example.com": certificate})
  second_changed = controller._write_caddyfile([route], {"example.com": certificate})

  assert first_changed is True
  assert second_changed is False


def test_write_state_file_persists_versions(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  controller.ensure_directories()
  route = RouteRecord(domain="example.com", upstream_target="127.0.0.1:6111", enabled=True, updated_at=datetime.now(tz=UTC))
  certificate = make_certificate("example.com", not_after=datetime.now(tz=UTC) + timedelta(days=10))
  (controller.generated_dir / "Caddyfile").write_text("test")

  controller._write_state_file([route], {"example.com": certificate})

  payload = json.loads(controller.runtime_state_path.read_text())
  assert payload["routes"][0]["domain"] == "example.com"
  assert payload["certificates"][0]["version"] == "1"


def test_read_runtime_state_returns_empty_for_invalid_json(tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  controller.runtime_state_path.parent.mkdir(parents=True, exist_ok=True)
  controller.runtime_state_path.write_text("{invalid")

  assert controller._read_runtime_state() == {}


def test_run_once_in_readonly_mode_skips_renewal(monkeypatch, tmp_path: Path) -> None:
  config = make_config(tmp_path)
  config.mode = "readonly"
  controller = Controller(config)
  events: list[str] = []
  route = RouteRecord(domain="example.com", upstream_target=None, enabled=True, updated_at=datetime.now(tz=UTC))
  certificate = make_certificate("example.com", not_after=datetime.now(tz=UTC) + timedelta(days=10))

  class RuntimeDatabase:
    def fetch_routes(self):
      events.append("routes")
      return [route]

    def fetch_certificates(self):
      events.append("certificates")
      return {"example.com": certificate}

  controller.database = RuntimeDatabase()
  monkeypatch.setattr(controller, "_renew_if_needed", lambda *_args: events.append("renew"))
  monkeypatch.setattr(controller, "_sync_local_certificates", lambda _certs: False)
  monkeypatch.setattr(controller, "_write_caddyfile", lambda _routes, _certs: False)
  monkeypatch.setattr(controller, "_write_state_file", lambda _routes, _certs: events.append("state"))
  monkeypatch.setattr("ssl_proxy_controller.controller.reload_caddy", lambda _command: events.append("reload"))

  controller.run_once()

  assert events == ["routes", "certificates", "state"]


def test_run_once_reloads_caddy_when_state_changes(monkeypatch, tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  events: list[str] = []

  class RuntimeDatabase:
    def __init__(self) -> None:
      self.calls = 0

    def fetch_routes(self):
      return []

    def fetch_certificates(self):
      self.calls += 1
      return {}

  controller.database = RuntimeDatabase()
  monkeypatch.setattr(controller, "_renew_if_needed", lambda *_args: events.append("renew"))
  monkeypatch.setattr(controller, "_sync_local_certificates", lambda _certs: True)
  monkeypatch.setattr(controller, "_write_caddyfile", lambda _routes, _certs: False)
  monkeypatch.setattr(controller, "_write_state_file", lambda _routes, _certs: events.append("state"))
  monkeypatch.setattr("ssl_proxy_controller.controller.reload_caddy", lambda _command: events.append("reload"))

  controller.run_once()

  assert events == ["renew", "reload", "state"]


def test_run_once_filters_orphan_certificates_from_local_state(monkeypatch, tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  route = RouteRecord(domain="active.example.com", upstream_target=None, enabled=True, updated_at=datetime.now(tz=UTC))
  active_certificate = make_certificate("active.example.com", not_after=datetime.now(tz=UTC) + timedelta(days=10))
  orphan_certificate = make_certificate("orphan.example.com", not_after=datetime.now(tz=UTC) + timedelta(days=10))
  captured: dict[str, dict[str, CertificateRecord]] = {}

  class RuntimeDatabase:
    def fetch_routes(self):
      return [route]

    def fetch_certificates(self):
      return {
        "active.example.com": active_certificate,
        "orphan.example.com": orphan_certificate,
      }

  controller.database = RuntimeDatabase()
  monkeypatch.setattr(controller, "_renew_if_needed", lambda *_args: None)
  monkeypatch.setattr(controller, "_sync_local_certificates", lambda certs: captured.setdefault("sync", dict(certs)) or False)
  monkeypatch.setattr(controller, "_write_caddyfile", lambda _routes, certs: captured.setdefault("caddy", dict(certs)) or False)
  monkeypatch.setattr(controller, "_write_state_file", lambda _routes, certs: captured.setdefault("state", dict(certs)))
  monkeypatch.setattr("ssl_proxy_controller.controller.reload_caddy", lambda _command: None)

  controller.run_once()

  assert list(captured["sync"]) == ["active.example.com"]
  assert list(captured["caddy"]) == ["active.example.com"]
  assert list(captured["state"]) == ["active.example.com"]


def test_run_forever_sleeps_after_loop_error(monkeypatch, tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  events: list[object] = []

  monkeypatch.setattr(controller, "ensure_directories", lambda: events.append("ensure"))
  monkeypatch.setattr("ssl_proxy_controller.controller.signal.signal", lambda sig, handler: events.append(("signal", sig)))

  def fake_run_once() -> None:
    if "run_once" not in events:
      events.append("run_once")
      raise RuntimeError("boom")
    events.append("run_once")
    controller.stop()

  monkeypatch.setattr(controller, "run_once", fake_run_once)
  monkeypatch.setattr("ssl_proxy_controller.controller.time.sleep", lambda seconds: events.append(("sleep", seconds)))

  controller.run_forever()

  assert events[0] == "ensure"
  assert ("sleep", controller.config.sync.loop_error_backoff_seconds) in events
  assert ("sleep", controller.config.sync.poll_interval_seconds) in events


def test_run_forever_does_not_sleep_after_stop(monkeypatch, tmp_path: Path) -> None:
  controller = Controller(make_config(tmp_path))
  sleeps: list[int] = []

  monkeypatch.setattr(controller, "ensure_directories", lambda: None)
  monkeypatch.setattr("ssl_proxy_controller.controller.signal.signal", lambda *_args: None)
  monkeypatch.setattr(controller, "run_once", controller.stop)
  monkeypatch.setattr("ssl_proxy_controller.controller.time.sleep", lambda seconds: sleeps.append(seconds))

  controller.run_forever()

  assert sleeps == []


def test_parse_args_supports_once_flag() -> None:
  args = parse_args(["--config", "/tmp/config.yaml", "--once"])

  assert args.config == "/tmp/config.yaml"
  assert args.once is True


def test_normalize_admin_address_supports_url_and_bare_host() -> None:
  assert normalize_admin_address("http://127.0.0.1:2019") == "127.0.0.1:2019"
  assert normalize_admin_address("https://admin.example.com:2020") == "admin.example.com:2020"
  assert normalize_admin_address("127.0.0.1:2019") == "127.0.0.1:2019"


def test_main_runs_once_mode(monkeypatch, tmp_path: Path) -> None:
  events: list[str] = []
  config = make_config(tmp_path)

  monkeypatch.setattr("ssl_proxy_controller.controller.load_config", lambda _path: config)
  monkeypatch.setattr("ssl_proxy_controller.controller.configure_logging", lambda _config: events.append("logging"))

  class FakeController:
    def __init__(self, loaded_config) -> None:
      assert loaded_config is config
      events.append("init")

    def ensure_directories(self) -> None:
      events.append("ensure")

    def run_once(self) -> None:
      events.append("once")

  monkeypatch.setattr("ssl_proxy_controller.controller.Controller", FakeController)

  assert main(["--config", str(tmp_path / "config.yaml"), "--once"]) == 0
  assert events == ["logging", "init", "ensure", "once"]


def test_main_runs_forever_mode(monkeypatch, tmp_path: Path) -> None:
  events: list[str] = []
  config = make_config(tmp_path)

  monkeypatch.setattr("ssl_proxy_controller.controller.load_config", lambda _path: config)
  monkeypatch.setattr("ssl_proxy_controller.controller.configure_logging", lambda _config: events.append("logging"))

  class FakeController:
    def __init__(self, loaded_config) -> None:
      assert loaded_config is config
      events.append("init")

    def run_forever(self) -> None:
      events.append("forever")

  monkeypatch.setattr("ssl_proxy_controller.controller.Controller", FakeController)

  assert main(["--config", str(tmp_path / "config.yaml")]) == 0
  assert events == ["logging", "init", "forever"]
