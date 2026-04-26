from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ssl_proxy_controller.db import (
  CertificateRecord,
  Database,
  RouteRecord,
  UpstreamRecord,
)


class FakeCursor:
  """Minimal psycopg-like cursor.

  `rows` is either a single result set (legacy shape, reused for every
  fetchall call) or a list-of-result-sets that are returned in order
  on each fetchall. Similarly `row` can be a single dict or a list of
  dicts returned in order from fetchone.
  """

  def __init__(self, rows: list[dict] | list[list[dict]] | None = None, row: dict | list[dict | None] | None = None) -> None:
    self.rows = rows if rows is not None else []
    self.row = row
    self.executed: list[tuple[str, object]] = []
    self._fetchall_idx = 0
    self._fetchone_idx = 0

  def __enter__(self) -> "FakeCursor":
    return self

  def __exit__(self, exc_type, exc, tb) -> None:
    return None

  def execute(self, query: str, params: object = None) -> None:
    self.executed.append((query, params))

  def fetchall(self) -> list[dict]:
    # If rows is a list of batches, return them in sequence; else it's
    # a single batch and we keep returning it.
    if self.rows and isinstance(self.rows[0], list):
      idx = min(self._fetchall_idx, len(self.rows) - 1)
      self._fetchall_idx += 1
      return self.rows[idx]  # type: ignore[return-value]
    return self.rows  # type: ignore[return-value]

  def fetchone(self) -> dict | None:
    if isinstance(self.row, list):
      if self._fetchone_idx >= len(self.row):
        return None
      result = self.row[self._fetchone_idx]
      self._fetchone_idx += 1
      return result
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
    # Two result sets, in order: first the routes SELECT, then the
    # route_upstreams hydration SELECT.
    rows=[
      [
        {"domain": "a.example.com", "upstream_target": "127.0.0.1:6111", "enabled": True, "updated_at": now, "lb_policy": "random"},
        {"domain": "b.example.com", "upstream_target": None, "enabled": True, "updated_at": now, "lb_policy": "random"},
        {"domain": "c.example.com", "upstream_target": "10.0.0.1:6111", "enabled": True, "updated_at": now, "lb_policy": "ip_hash"},
      ],
      [
        # route_upstreams rows. c.example.com has two upstreams; a.example.com has one; b.example.com has none.
        {"domain": "a.example.com", "target": "127.0.0.1:6111", "weight": 1},
        {"domain": "c.example.com", "target": "10.0.0.1:6111", "weight": 1},
        {"domain": "c.example.com", "target": "10.0.0.2:6111", "weight": 2},
      ],
    ]
  )
  connection = FakeConnection(cursor)
  monkeypatch.setattr("ssl_proxy_controller.db.psycopg.connect", lambda dsn, row_factory=None: connection)

  records = Database("postgresql://example").fetch_routes()

  assert [r.domain for r in records] == ["a.example.com", "b.example.com", "c.example.com"]
  assert records[0].upstream_target == "127.0.0.1:6111"
  assert records[0].upstreams == [UpstreamRecord(target="127.0.0.1:6111", weight=1)]
  assert records[0].lb_policy == "random"

  assert records[1].upstream_target is None
  assert records[1].upstreams == []
  assert records[1].lb_policy == "random"

  assert records[2].upstreams == [
    UpstreamRecord(target="10.0.0.1:6111", weight=1),
    UpstreamRecord(target="10.0.0.2:6111", weight=2),
  ]
  assert records[2].lb_policy == "ip_hash"
  assert "FROM routes" in cursor.executed[0][0]
  assert "FROM route_upstreams" in cursor.executed[1][0]


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


def test_record_certificate_error_does_not_overwrite_existing_certificate_material(monkeypatch) -> None:
  cursor = FakeCursor()
  connection = FakeConnection(cursor)
  monkeypatch.setattr("ssl_proxy_controller.db.psycopg.connect", lambda dsn, row_factory=None: connection)

  Database("postgresql://example").record_certificate_error(
    "a.example.com",
    "boom",
    datetime.now(tz=UTC) + timedelta(hours=1),
  )

  query, _ = cursor.executed[0]
  assert "fullchain_pem = EXCLUDED.fullchain_pem" not in query
  assert "private_key_pem = EXCLUDED.private_key_pem" not in query


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
