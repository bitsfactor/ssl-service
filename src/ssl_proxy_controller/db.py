from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator

import psycopg
from psycopg.rows import dict_row


@dataclass(slots=True)
class RouteRecord:
  domain: str
  upstream_port: int | None
  enabled: bool
  updated_at: datetime


@dataclass(slots=True)
class CertificateRecord:
  domain: str
  fullchain_pem: str
  private_key_pem: str
  not_before: datetime
  not_after: datetime
  version: int
  status: str
  source: str
  retry_after: datetime | None
  updated_at: datetime
  last_error: str | None


class Database:
  def __init__(self, dsn: str) -> None:
    self._dsn = dsn

  @contextmanager
  def connect(self) -> Iterator[psycopg.Connection]:
    with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
      yield connection

  def fetch_routes(self) -> list[RouteRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT domain, upstream_port, enabled, updated_at
          FROM routes
          WHERE enabled = TRUE
          ORDER BY domain ASC
          """
        )
        return [RouteRecord(**row) for row in cursor.fetchall()]

  def fetch_certificates(self) -> dict[str, CertificateRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT domain, fullchain_pem, private_key_pem, not_before, not_after,
                 version, status, source, retry_after, updated_at, last_error
          FROM certificates
          WHERE status IN ('active', 'error')
          ORDER BY domain ASC
          """
        )
        return {row["domain"]: CertificateRecord(**row) for row in cursor.fetchall()}

  def upsert_certificate(self, certificate: CertificateRecord) -> None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO certificates (
            domain, fullchain_pem, private_key_pem, not_before, not_after,
            version, status, source, retry_after, updated_at, last_error
          ) VALUES (
            %(domain)s, %(fullchain_pem)s, %(private_key_pem)s, %(not_before)s, %(not_after)s,
            %(version)s, %(status)s, %(source)s, %(retry_after)s, NOW(), %(last_error)s
          )
          ON CONFLICT (domain) DO UPDATE
          SET
            fullchain_pem = EXCLUDED.fullchain_pem,
            private_key_pem = EXCLUDED.private_key_pem,
            not_before = EXCLUDED.not_before,
            not_after = EXCLUDED.not_after,
            version = certificates.version + 1,
            status = EXCLUDED.status,
            source = EXCLUDED.source,
            retry_after = EXCLUDED.retry_after,
            updated_at = NOW(),
            last_error = EXCLUDED.last_error
          """,
          {
            "domain": certificate.domain,
            "fullchain_pem": certificate.fullchain_pem,
            "private_key_pem": certificate.private_key_pem,
            "not_before": certificate.not_before,
            "not_after": certificate.not_after,
            "version": max(certificate.version, 1),
            "status": certificate.status,
            "source": certificate.source,
            "retry_after": certificate.retry_after,
            "last_error": certificate.last_error,
          },
        )
      connection.commit()

  def record_certificate_error(self, domain: str, last_error: str, retry_after: datetime) -> None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO certificates (
            domain, fullchain_pem, private_key_pem, not_before, not_after,
            version, status, source, retry_after, updated_at, last_error
          ) VALUES (
            %s, '', '', NOW(), NOW(),
            1, 'error', 'certbot', %s, NOW(), %s
          )
          ON CONFLICT (domain) DO UPDATE
          SET
            status = 'error',
            retry_after = EXCLUDED.retry_after,
            updated_at = NOW(),
            last_error = EXCLUDED.last_error
          """,
          (domain, retry_after, last_error),
        )
      connection.commit()

  def clear_certificate_retry_after(self, domain: str) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          UPDATE certificates
          SET retry_after = NULL, updated_at = NOW()
          WHERE domain = %s
          RETURNING domain
          """,
          (domain,),
        )
        row = cursor.fetchone()
      connection.commit()
      return row is not None

  def try_advisory_lock(self, connection: psycopg.Connection, key: str) -> bool:
    with connection.cursor() as cursor:
      cursor.execute("SELECT pg_try_advisory_lock(hashtext(%s)) AS locked", (key,))
      row = cursor.fetchone()
      return bool(row["locked"])

  def unlock(self, connection: psycopg.Connection, key: str) -> None:
    with connection.cursor() as cursor:
      cursor.execute("SELECT pg_advisory_unlock(hashtext(%s))", (key,))
