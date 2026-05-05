"""Postgres connection pool — single source of truth for the user service."""
from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


_POOL: ConnectionPool | None = None


def init_pool() -> ConnectionPool:
  global _POOL
  if _POOL is not None:
    return _POOL
  dsn = os.environ.get("USER_SERVICE_PG_DSN") or os.environ.get("DATABASE_URL")
  if not dsn:
    raise RuntimeError("USER_SERVICE_PG_DSN env var is required")
  _POOL = ConnectionPool(
    dsn,
    min_size=2,
    max_size=10,
    timeout=10,
    kwargs={"row_factory": dict_row},
  )
  _POOL.wait(timeout=10)
  return _POOL


def get_pool() -> ConnectionPool:
  if _POOL is None:
    return init_pool()
  return _POOL


@contextmanager
def connect() -> Iterator[psycopg.Connection]:
  pool = get_pool()
  with pool.connection() as conn:
    yield conn
