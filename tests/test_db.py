from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ssl_proxy_controller.db import CertificateRecord, Database, RouteRecord


class FakeCursor:
  def __init__(self, rows: list[dict] | None = None, row: dict | None = None) -> None:
    self.rows = rows or []
    self.row = row
    self.executed: list[tuple[str, object]] = []

  def __enter__(self) -> "FakeCursor":
    return self

  def __exit__(self, exc_type, exc, tb) -> None:
    return None

  def execute(self, query: str, params: object = None) -> None:
    self.executed.append((query, params))

  def fetchall(self) -> list[dict]:
    return self.rows

  def fetchone(self) -> dict | None:
    return self.row


class FakeConnection:
  def __init__(self, cursor: FakeCursor) -> None:
    self._cursor = cursor
    self.commits = 0

  def __enter__(self) -> "FakeConnection":
    return self

  def __exit__(self, exc_type, exc, tb) -> None:
    return None

  def cursor(self) -> FakeCursor:
    return self._cursor

  def commit(self) -> None:
    self.commits += 1


def make_certificate(domain: str) -> CertificateRecord:
  now = datetime.now(tz=UTC)
  return CertificateRecord(
    domain=domain,
    fullchain_pem="fullchain",
    private_key_pem="privkey",
    not_before=now,
    not_after=now + timedelta(days=90),
    version=0,
    status="active",
    source="certbot",
    retry_after=None,
    updated_at=now,
    last_error=None,
  )


def test_fetch_routes_returns_route_records(monkeypatch) -> None:
  now = datetime.now(tz=UTC)
  cursor = FakeCursor(
    rows=[
      {"domain": "a.example.com", "upstream_port": 6111, "enabled": True, "updated_at": now},
      {"domain": "b.example.com", "upstream_port": None, "enabled": True, "updated_at": now},
    ]
  )
  connection = FakeConnection(cursor)
  monkeypatch.setattr("ssl_proxy_controller.db.psycopg.connect", lambda dsn, row_factory=None: connection)

  records = Database("postgresql://example").fetch_routes()

  assert records == [
    RouteRecord(domain="a.example.com", upstream_port=6111, enabled=True, updated_at=now),
    RouteRecord(domain="b.example.com", upstream_port=None, enabled=True, updated_at=now),
  ]
  assert "FROM routes" in cursor.executed[0][0]


def test_fetch_certificates_returns_domain_map(monkeypatch) -> None:
  now = datetime.now(tz=UTC)
  cursor = FakeCursor(
    rows=[
      {
        "domain": "a.example.com",
        "fullchain_pem": "fullchain",
        "private_key_pem": "privkey",
        "not_before": now,
        "not_after": now,
        "version": 2,
        "status": "active",
        "source": "certbot",
        "retry_after": None,
        "updated_at": now,
        "last_error": None,
      }
    ]
  )
  connection = FakeConnection(cursor)
  monkeypatch.setattr("ssl_proxy_controller.db.psycopg.connect", lambda dsn, row_factory=None: connection)

  records = Database("postgresql://example").fetch_certificates()

  assert list(records) == ["a.example.com"]
  assert records["a.example.com"].version == 2
  assert "FROM certificates" in cursor.executed[0][0]


def test_upsert_certificate_commits_and_normalizes_minimum_version(monkeypatch) -> None:
  cursor = FakeCursor()
  connection = FakeConnection(cursor)
  monkeypatch.setattr("ssl_proxy_controller.db.psycopg.connect", lambda dsn, row_factory=None: connection)
  certificate = make_certificate("a.example.com")

  Database("postgresql://example").upsert_certificate(certificate)

  assert connection.commits == 1
  query, params = cursor.executed[0]
  assert "INSERT INTO certificates" in query
  assert params["domain"] == "a.example.com"
  assert params["version"] == 1


def test_record_certificate_error_commits(monkeypatch) -> None:
  cursor = FakeCursor()
  connection = FakeConnection(cursor)
  monkeypatch.setattr("ssl_proxy_controller.db.psycopg.connect", lambda dsn, row_factory=None: connection)
  retry_after = datetime.now(tz=UTC) + timedelta(hours=1)

  Database("postgresql://example").record_certificate_error("a.example.com", "boom", retry_after)

  assert connection.commits == 1
  query, params = cursor.executed[0]
  assert "status = 'error'" in query
  assert params == ("a.example.com", retry_after, "boom")


def test_clear_certificate_retry_after_returns_true_when_row_exists(monkeypatch) -> None:
  cursor = FakeCursor(row={"domain": "a.example.com"})
  connection = FakeConnection(cursor)
  monkeypatch.setattr("ssl_proxy_controller.db.psycopg.connect", lambda dsn, row_factory=None: connection)

  cleared = Database("postgresql://example").clear_certificate_retry_after("a.example.com")

  assert cleared is True
  assert connection.commits == 1


def test_clear_certificate_retry_after_returns_false_when_missing(monkeypatch) -> None:
  cursor = FakeCursor(row=None)
  connection = FakeConnection(cursor)
  monkeypatch.setattr("ssl_proxy_controller.db.psycopg.connect", lambda dsn, row_factory=None: connection)

  cleared = Database("postgresql://example").clear_certificate_retry_after("missing.example.com")

  assert cleared is False
  assert connection.commits == 1


def test_try_advisory_lock_returns_boolean() -> None:
  connection = FakeConnection(FakeCursor(row={"locked": 1}))

  locked = Database("postgresql://example").try_advisory_lock(connection, "certificate:a.example.com")

  assert locked is True
  assert "pg_try_advisory_lock" in connection.cursor().executed[0][0]


def test_unlock_executes_unlock_query() -> None:
  connection = FakeConnection(FakeCursor())

  Database("postgresql://example").unlock(connection, "certificate:a.example.com")

  assert "pg_advisory_unlock" in connection.cursor().executed[0][0]
