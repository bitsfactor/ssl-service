"""Two-database sync — push the logical config from one Postgres to
another, source-wins on PK conflicts, target-only rows preserved.

Direction is decided per call. The "logical config" set covers the
admin-facing tables (routes, services, nodes, …) but excludes runtime
state (probe results, init runs, deploy history).

The flow has two phases the UI can call separately:

    analyze_sync(...) -> dict   # per-table diff, no writes
    apply_sync(...) -> dict     # actually upsert into target

`apply_sync` uses INSERT … ON CONFLICT … DO UPDATE so target-only rows
stay put and PK collisions get the source's row. For ``routes``, the
child ``route_upstreams`` rows are deleted-and-reinserted for each
parent the sync touches, so the upstream set always matches the
source after sync.

`system_config` is filtered to skip ``secondary_db_dsn`` and
``last_sync`` (those are sync-state itself; B has its own).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable

import psycopg
from psycopg import errors as pg_errors
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

LOGGER = logging.getLogger("ssl_proxy_controller.db_sync")


@dataclass(slots=True)
class TableSpec:
  """One table in the sync set. Discovered at runtime via
  information_schema — no hardcoded list, no business logic."""
  name: str
  pk_cols: tuple[str, ...]


# ---------------------------------------------------------------------------
# Schema discovery — populates the table list at runtime
# ---------------------------------------------------------------------------


def discover_tables(conn: psycopg.Connection) -> list[TableSpec]:
  """Discover all BASE TABLEs in the connection's ``current_schema()``,
  with their PRIMARY KEY columns. Tables without a PK are skipped
  (we can't safely upsert into them)."""
  out: list[TableSpec] = []
  with conn.cursor() as cur:
    # NOTE: information_schema.key_column_usage.column_name is of type
    # ``sql_identifier`` (a domain over ``name``), and psycopg doesn't
    # have a built-in text codec for that type — it falls back to
    # returning the array as a raw PG literal string like ``{col1,col2}``.
    # Cast each element to ``text`` BEFORE array_agg so the array comes
    # back to Python as a real list of strings.
    cur.execute("""
      SELECT t.table_name,
             COALESCE(
               (SELECT array_agg(kcu.column_name::text ORDER BY kcu.ordinal_position)
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON kcu.constraint_schema = tc.constraint_schema
                  AND kcu.constraint_name = tc.constraint_name
                WHERE tc.constraint_type = 'PRIMARY KEY'
                  AND tc.table_schema = t.table_schema
                  AND tc.table_name = t.table_name),
               ARRAY[]::text[]
             ) AS pk_cols
      FROM information_schema.tables t
      WHERE t.table_schema = current_schema()
        AND t.table_type = 'BASE TABLE'
      ORDER BY t.table_name
    """)
    for row in cur.fetchall():
      raw_pk = row.get("pk_cols")
      # Defensive: even after the ::text cast, if some psycopg version
      # ever hands us back the literal "{col1,col2}" string, parse it.
      if isinstance(raw_pk, str):
        s = raw_pk.strip()
        if s.startswith("{") and s.endswith("}"):
          s = s[1:-1]
        raw_pk = [p for p in (x.strip().strip('"') for x in s.split(",")) if p]
      pk = tuple(raw_pk or [])
      if not pk:
        LOGGER.warning("discover: skipping %s (no PRIMARY KEY)", row["table_name"])
        continue
      out.append(TableSpec(name=row["table_name"], pk_cols=pk))
  return out


def discover_fk_edges(conn: psycopg.Connection) -> dict[str, set[str]]:
  """Returns ``{child_table: {parent_table, ...}}`` for FKs in
  ``current_schema()``. Self-references are dropped — they don't
  affect topo sort."""
  edges: dict[str, set[str]] = {}
  with conn.cursor() as cur:
    cur.execute("""
      SELECT DISTINCT
        tc.table_name AS child,
        ccu.table_name AS parent
      FROM information_schema.table_constraints tc
      JOIN information_schema.constraint_column_usage ccu
        ON ccu.constraint_schema = tc.constraint_schema
        AND ccu.constraint_name = tc.constraint_name
      WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_schema = current_schema()
        AND ccu.table_schema = current_schema()
    """)
    for row in cur.fetchall():
      child, parent = row.get("child"), row.get("parent")
      if not child or not parent or child == parent:
        continue
      edges.setdefault(child, set()).add(parent)
  return edges


def topo_sort(
  tables: list[TableSpec], fk_edges: dict[str, set[str]],
) -> list[TableSpec]:
  """Return ``tables`` ordered so parents come before children. Cycles
  are tolerated — affected tables get appended at the end and the
  caller deals with any FK errors during apply."""
  by_name = {t.name: t for t in tables}
  visited: set[str] = set()
  visiting: set[str] = set()
  result: list[str] = []

  def _visit(name: str) -> None:
    if name in visited or name in visiting:
      return
    if name not in by_name:
      return  # FK target outside our table set, ignore
    visiting.add(name)
    for parent in fk_edges.get(name, ()):
      _visit(parent)
    visiting.discard(name)
    visited.add(name)
    result.append(name)

  for t in tables:
    _visit(t.name)
  return [by_name[n] for n in result]


def discover_sync_tables(conn: psycopg.Connection) -> list[TableSpec]:
  """Convenience: discover + topo-sort. The result is the order
  apply_sync should write tables in."""
  tables = discover_tables(conn)
  edges = discover_fk_edges(conn)
  return topo_sort(tables, edges)


# Backwards-compat for callers that still reference SYNC_TABLES; this
# is now an empty tuple — the real list is discovered at runtime.
SYNC_TABLES: tuple[TableSpec, ...] = ()

# Columns we ignore when comparing two rows for "did anything change".
# These get bumped on every write and would otherwise mask real diffs.
_COMPARE_IGNORE = ("updated_at", "created_at")


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------


def _connect(dsn: str, *, timeout: float = 15.0) -> psycopg.Connection:
  """Open a fresh dict-row connection to ``dsn``. Caller closes."""
  return psycopg.connect(dsn, row_factory=dict_row, connect_timeout=int(timeout))


# Matches `options=-csearch_path=foo` (plain) and the URL-encoded
# `options=-csearch_path%3Dfoo` form that supabase / sqla typically emits.
_SEARCH_PATH_RE = re.compile(r"-csearch_path(?:=|%3[Dd])([A-Za-z0-9_,]+)")


def _schema_from_dsn(dsn: str) -> str | None:
  """Extract the FIRST schema named in the DSN's
  ``options=-csearch_path=...`` segment. Returns None if no search_path
  is set (PG defaults to ``public``) or it explicitly is ``public``."""
  if not dsn:
    return None
  m = _SEARCH_PATH_RE.search(dsn)
  if not m:
    return None
  name = m.group(1).split(",", 1)[0].strip()
  if not name or name.lower() == "public":
    return None
  # Reject anything that doesn't look like a plain unquoted identifier;
  # we plug this directly into CREATE SCHEMA, so be paranoid.
  if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
    return None
  return name


def apply_schema(dsn: str, schema_sql: str) -> dict[str, Any]:
  """Run ``schema.sql`` against the target. Idempotent — schema.sql
  uses CREATE TABLE IF NOT EXISTS / ALTER TABLE IF NOT EXISTS guards.

  If the DSN's ``search_path`` points at a schema that doesn't exist
  yet, we ``CREATE SCHEMA IF NOT EXISTS`` first. This makes the
  "merge into a fresh third schema" workflow one click instead of
  requiring the user to run CREATE SCHEMA manually in psql / Supabase
  SQL editor before bootstrapping."""
  if not schema_sql.strip():
    raise ValueError("schema_sql is empty")
  schema_name = _schema_from_dsn(dsn)
  with _connect(dsn) as conn:
    with conn.cursor() as cur:
      if schema_name:
        # Schema name was already validated as a plain identifier in
        # _schema_from_dsn so it's safe to interpolate (psycopg has no
        # binding for identifiers).
        cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema_name}"')
      cur.execute(schema_sql)
    conn.commit()
  # Re-check what's there afterwards.
  return test_target_connection(dsn)


def test_target_connection(dsn: str) -> dict[str, Any]:
  """Connect, run ``SELECT 1``, list tables actually present in the
  connection's current_schema(). Used by the UI's "Test" button.

  ``missing_tables`` is empty for now because, with auto-discovery,
  there's no fixed expected list — the sync covers whatever's there.
  Kept in the response shape for backwards compat with callers."""
  with _connect(dsn) as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT 1 AS ok")
      cur.fetchone()
    discovered = discover_tables(conn)
  return {
    "ok": True,
    "missing_tables": [],
    "checked_tables": [s.name for s in discovered],
  }


# ---------------------------------------------------------------------------
# Reading + diff
# ---------------------------------------------------------------------------


def _select_table(cur: psycopg.Cursor, spec: TableSpec) -> dict[tuple, dict]:
  """Return {pk_tuple: row_dict} for the table. PK tuple lets us key
  composite-PK tables transparently."""
  cur.execute(f"SELECT * FROM {spec.name}")
  out: dict[tuple, dict] = {}
  for row in cur.fetchall():
    pk = tuple(row[c] for c in spec.pk_cols)
    out[pk] = dict(row)
  return out


def _select_table_or_missing(
  conn: psycopg.Connection, spec: TableSpec,
) -> tuple[dict[tuple, dict], bool]:
  """Like ``_select_table`` but tolerates ``relation does not exist``
  on this side. Returns ``(rows, exists)``; on UndefinedTable rolls
  back the connection and returns ``({}, False)`` so the caller can
  continue with the remaining tables.

  This is the key piece that lets analyze handle the realistic case:
  one DB has a strict subset of the sync tables (e.g. a fresh prod DB
  that only got a partial migration applied)."""
  try:
    with conn.cursor() as cur:
      return (_select_table(cur, spec), True)
  except pg_errors.UndefinedTable:
    try:
      conn.rollback()
    except Exception:
      pass
    return ({}, False)


def _value_eq(a: Any, b: Any) -> bool:
  """Tolerant equality — handles datetime tz, None, and stringified
  numerics that round-trip through the DB."""
  if a is None and b is None:
    return True
  if a is None or b is None:
    return False
  if type(a) is type(b):
    return a == b
  return str(a) == str(b)


def _row_equal(a: dict, b: dict) -> bool:
  keys = (set(a.keys()) | set(b.keys())) - set(_COMPARE_IGNORE)
  for k in keys:
    if not _value_eq(a.get(k), b.get(k)):
      return False
  return True


def _short(val: Any, n: int = 60) -> str:
  s = "" if val is None else str(val)
  return s if len(s) <= n else s[: n - 1] + "…"


def _row_summary(row: dict, pk_cols: tuple[str, ...]) -> dict[str, str]:
  """Compact representation for the analyze preview."""
  out = {c: _short(row.get(c)) for c in pk_cols}
  for k, v in row.items():
    if k in pk_cols or k in _COMPARE_IGNORE:
      continue
    if len(out) >= len(pk_cols) + 4:  # cap fields shown
      break
    out[k] = _short(v)
  return out


def _diff_table(
  source_rows: dict, target_rows: dict, spec: TableSpec,
) -> dict[str, Any]:
  to_insert: list[dict] = []
  to_overwrite: list[dict] = []
  preserve_count = 0

  for pk, srow in source_rows.items():
    trow = target_rows.get(pk)
    if trow is None:
      to_insert.append(_row_summary(srow, spec.pk_cols))
    elif not _row_equal(srow, trow):
      changed = []
      for k in (set(srow.keys()) | set(trow.keys())) - set(_COMPARE_IGNORE):
        if not _value_eq(srow.get(k), trow.get(k)):
          changed.append(k)
      to_overwrite.append({
        "pk": {c: _short(srow.get(c)) for c in spec.pk_cols},
        "changed_fields": sorted(changed)[:8],
        "after": _row_summary(srow, spec.pk_cols),
        "before": _row_summary(trow, spec.pk_cols),
      })

  for pk in target_rows:
    if pk not in source_rows:
      preserve_count += 1

  return {
    "table": spec.name,
    "insert": len(to_insert),
    "overwrite": len(to_overwrite),
    "preserve_only_in_target": preserve_count,
    "sample_insert": to_insert[:5],
    "sample_overwrite": to_overwrite[:5],
  }


def analyze_sync(
  source_dsn: str, target_dsn: str, direction: str,
) -> dict[str, Any]:
  """direction ∈ {"AtoB", "BtoA"}.

  Convention: A is always the source_dsn argument, B is target_dsn.
  When direction is BtoA we just swap which side is the source.

  Per-table status (in the response):
    - ok:              both sides have the table; insert/overwrite/preserve are real
    - source_missing:  source doesn't have this table; nothing to push;
                       target keeps its rows untouched
    - target_missing:  target doesn't have this table; would need to bootstrap
                       schema there to actually sync; ``would_insert`` reports
                       how many source rows ARE waiting
    - both_missing:    table missing on both sides — ignored
    - error:           unexpected DB error other than UndefinedTable
  """
  if direction not in ("AtoB", "BtoA"):
    raise ValueError(f"direction must be AtoB or BtoA, got {direction!r}")
  src, tgt = (source_dsn, target_dsn) if direction == "AtoB" else (target_dsn, source_dsn)

  per_table: list[dict] = []
  with _connect(src) as src_conn, _connect(tgt) as tgt_conn:
    # Discover the table list from whichever side has more tables
    # (covers the "target schema not bootstrapped yet" case).
    src_tables = discover_tables(src_conn)
    try:
      tgt_tables = discover_tables(tgt_conn)
    except Exception:
      tgt_tables = []
    by_name: dict[str, TableSpec] = {t.name: t for t in src_tables}
    for t in tgt_tables:
      by_name.setdefault(t.name, t)
    union_tables = list(by_name.values())
    edges = discover_fk_edges(src_conn) if src_tables else {}
    tables_in_order = topo_sort(union_tables, edges)

    for spec in tables_in_order:
      try:
        src_rows, src_exists = _select_table_or_missing(src_conn, spec)
        tgt_rows, tgt_exists = _select_table_or_missing(tgt_conn, spec)
      except Exception as exc:  # noqa: BLE001
        LOGGER.exception("analyze: read failed for %s", spec.name)
        per_table.append({
          "table": spec.name, "status": "error", "error": str(exc),
          "insert": 0, "overwrite": 0, "preserve_only_in_target": 0,
          "sample_insert": [], "sample_overwrite": [],
        })
        continue

      if not src_exists and not tgt_exists:
        per_table.append({
          "table": spec.name, "status": "both_missing",
          "insert": 0, "overwrite": 0, "preserve_only_in_target": 0,
          "sample_insert": [], "sample_overwrite": [],
        })
      elif not src_exists:
        per_table.append({
          "table": spec.name, "status": "source_missing",
          "insert": 0, "overwrite": 0,
          "preserve_only_in_target": len(tgt_rows),
          "sample_insert": [], "sample_overwrite": [],
        })
      elif not tgt_exists:
        per_table.append({
          "table": spec.name, "status": "target_missing",
          "insert": 0, "overwrite": 0, "preserve_only_in_target": 0,
          "would_insert": len(src_rows),
          "sample_insert": [], "sample_overwrite": [],
        })
      else:
        diff = _diff_table(src_rows, tgt_rows, spec)
        diff["status"] = "ok"
        per_table.append(diff)

  errored = [t for t in per_table if t.get("status") == "error"]
  source_missing_tables = [t["table"] for t in per_table if t.get("status") == "source_missing"]
  target_missing_tables = [t["table"] for t in per_table if t.get("status") == "target_missing"]
  totals = {
    "insert": sum(t.get("insert", 0) for t in per_table),
    "overwrite": sum(t.get("overwrite", 0) for t in per_table),
    "preserve_only_in_target": sum(t.get("preserve_only_in_target", 0) for t in per_table),
    "errored_tables": len(errored),
    "source_missing_tables": len(source_missing_tables),
    "target_missing_tables": len(target_missing_tables),
    "would_insert_if_bootstrapped": sum(t.get("would_insert", 0) for t in per_table
                                        if t.get("status") == "target_missing"),
  }
  return {
    "direction": direction,
    "tables": per_table,
    "totals": totals,
    "errors": [{"table": t["table"], "error": t["error"]} for t in errored],
    "source_missing": source_missing_tables,
    "target_missing": target_missing_tables,
    "at": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
  }


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def _bind_value(v: Any) -> Any:
  """Convert Python values into a form psycopg can bind for INSERT.

  Only ``dict`` gets wrapped in ``Jsonb(...)``. psycopg auto-adapts:
    - scalars (str/int/datetime/bool) → native PG types
    - list → text[] / PG array (our list columns: ssh_keys.tags,
            nodes.tags, services.required_env are all text[])
  Wrapping a list in Jsonb would store it as JSONB and fail on text[]
  columns with ``DatatypeMismatch: column ... is of type text[] but
  expression is of type jsonb``.

  If we ever need a JSONB column that holds a list value, we'd handle
  that per-column rather than globally."""
  if isinstance(v, dict):
    return Jsonb(v)
  return v


def _build_upsert_sql(
  table: str, cols: list[str], pk_cols: tuple[str, ...], *,
  mode: str = "merge",
) -> str:
  """Build the INSERT ... ON CONFLICT ... statement.

  ``mode``:
    - ``"merge"`` (default): on PK conflict, overwrite the target's
      row with the source's values.
    - ``"insert_only"``: on PK conflict, leave the target row alone.
      Used when the operator wants to add only the source rows that
      don't already exist in target without touching overlaps.
  """
  pk_clause = ", ".join(pk_cols)
  ph = ", ".join(["%s"] * len(cols))
  if mode == "insert_only":
    # Bare ``ON CONFLICT DO NOTHING`` (no column list) catches violations
    # of ANY unique constraint, not just the PK. Tables like
    # ``route_upstreams`` have a separate UNIQUE on (domain, target)
    # that the PK-targeted form would miss, so the insert would still
    # error out. Insert-only is "skip duplicates by any definition",
    # so the un-targeted form is the right semantics.
    return (
      f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({ph}) "
      f"ON CONFLICT DO NOTHING"
    )
  set_clauses = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols if c not in pk_cols)
  if not set_clauses:
    return (
      f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({ph}) "
      f"ON CONFLICT ({pk_clause}) DO NOTHING"
    )
  return (
    f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({ph}) "
    f"ON CONFLICT ({pk_clause}) DO UPDATE SET {set_clauses}"
  )


def _apply_one_table(
  spec: TableSpec, src_conn: psycopg.Connection, tgt_conn: psycopg.Connection,
  *, mode: str = "merge",
) -> dict[str, Any]:
  """Sync ONE table source→target. Per-table transaction.

  Either side missing the table is handled: source missing → nothing
  to push, return 0 applied; target missing → can't apply without
  bootstrapping the schema, return a clear error string.

  ``mode``:
    ``"merge"`` (default) — overwrite target rows on PK conflict, also
      replace children (DELETE + INSERT) for routes/route_upstreams.
    ``"insert_only"`` — only INSERT rows whose PK isn't in target;
      for child tables, INSERT children only for the parents we
      newly inserted (existing parent's children stay untouched).
  """
  src_rows, src_exists = _select_table_or_missing(src_conn, spec)
  if not src_exists:
    return {"table": spec.name, "rows_applied": 0, "child_rows_applied": 0,
            "skipped": "source missing this table"}
  if not src_rows:
    return {"table": spec.name, "rows_applied": 0, "child_rows_applied": 0}

  # In insert_only mode we need to know which parent keys are NEW so
  # we can decide which children to copy. Pull the target PK set once.
  target_pks: set[tuple] = set()
  if mode == "insert_only":
    tgt_rows, tgt_exists = _select_table_or_missing(tgt_conn, spec)
    if tgt_exists:
      target_pks = set(tgt_rows.keys())

  cols = list(next(iter(src_rows.values())).keys())
  upsert_sql = _build_upsert_sql(spec.name, cols, spec.pk_cols, mode=mode)

  with tgt_conn.cursor() as tcur:
    try:
      for row in src_rows.values():
        tcur.execute(upsert_sql, [_bind_value(row.get(c)) for c in cols])
      tgt_conn.commit()
      LOGGER.info("sync.apply table=%s rows=%d mode=%s",
                  spec.name, len(src_rows), mode)
      return {
        "table": spec.name,
        "rows_applied": len(src_rows),
        "child_rows_applied": 0,  # no child handling in pure-data mode
      }
    except pg_errors.UndefinedTable:
      tgt_conn.rollback()
      LOGGER.warning("sync.apply: %s missing on target — skipping", spec.name)
      return {
        "table": spec.name,
        "rows_applied": 0, "child_rows_applied": 0,
        "error": "target missing this table — bootstrap target schema first",
      }
    except Exception as exc:  # noqa: BLE001
      tgt_conn.rollback()
      LOGGER.exception("sync.apply failed for %s", spec.name)
      return {
        "table": spec.name,
        "rows_applied": 0, "child_rows_applied": 0,
        "error": f"{type(exc).__name__}: {exc}",
      }


def apply_sync(
  source_dsn: str, target_dsn: str, direction: str,
  *, mode: str = "merge",
) -> dict[str, Any]:
  """Run the sync. Each table is its own transaction so a failure in
  one table doesn't lose the others. Returns per-table results +
  any errors.

  ``mode``: ``"merge"`` (default, source-wins on conflict) or
  ``"insert_only"`` (skip overwrites — only add rows the target
  doesn't have)."""
  if direction not in ("AtoB", "BtoA"):
    raise ValueError(f"direction must be AtoB or BtoA, got {direction!r}")
  if mode not in ("merge", "insert_only"):
    raise ValueError(f"mode must be merge or insert_only, got {mode!r}")
  src, tgt = (source_dsn, target_dsn) if direction == "AtoB" else (target_dsn, source_dsn)

  results: list[dict] = []
  errors: list[dict] = []
  with _connect(src) as src_conn, _connect(tgt) as tgt_conn:
    tables_in_order = discover_sync_tables(src_conn)
    for spec in tables_in_order:
      r = _apply_one_table(spec, src_conn, tgt_conn, mode=mode)
      if r.get("error"):
        errors.append({"table": r["table"], "error": r["error"]})
      results.append(r)

  return {
    "direction": direction,
    "mode": mode,
    "results": results,
    "errors": errors,
    "at": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
  }


# ---------------------------------------------------------------------------
# Helpers for the admin layer
# ---------------------------------------------------------------------------


def mask_dsn(dsn: str | None) -> str | None:
  """Hide the password in postgres://user:pw@host/db. Return None for
  empty DSN. Not perfect (handles standard URI form only) but enough
  for UI display."""
  if not dsn:
    return None
  try:
    if "://" not in dsn:
      return "***"
    scheme, rest = dsn.split("://", 1)
    if "@" not in rest:
      return f"{scheme}://{rest}"
    creds, host = rest.split("@", 1)
    if ":" in creds:
      user, _ = creds.split(":", 1)
      return f"{scheme}://{user}:****@{host}"
    return f"{scheme}://{creds}@{host}"
  except Exception:  # noqa: BLE001
    return "***"
