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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable

import psycopg
from psycopg.rows import dict_row

LOGGER = logging.getLogger("ssl_proxy_controller.db_sync")


@dataclass(slots=True)
class TableSpec:
  """One table in the sync set."""
  name: str
  pk_cols: tuple[str, ...]
  # SQL WHERE clause used when SELECTing rows from source/target. Lets
  # ``system_config`` skip its own sync-config keys.
  filter_where: str | None = None
  # Optional child table whose rows are replaced (DELETE + INSERT) for
  # every parent row we touch — currently used by routes/route_upstreams.
  child_table: str | None = None
  child_parent_col: str | None = None  # column in child that refs parent.PK[0]


# Apply order: independent tables first, parents before children. Tables
# excluded on purpose: node_status, node_init_runs, service_deployments,
# service_node_state, ip_test_results — these are runtime state, not
# logical config.
SYNC_TABLES: tuple[TableSpec, ...] = (
  TableSpec(
    "system_config", pk_cols=("key",),
    filter_where="key NOT IN ('secondary_db_dsn', 'last_sync')",
  ),
  TableSpec("dns_zone_tokens", pk_cols=("zone_name",)),
  TableSpec("ssh_keys",        pk_cols=("id",)),
  TableSpec("nodes",           pk_cols=("name",)),
  TableSpec("services",        pk_cols=("name",)),
  TableSpec("static_ips",      pk_cols=("id",)),
  TableSpec("certificates",    pk_cols=("domain",)),
  TableSpec(
    "routes", pk_cols=("domain",),
    child_table="route_upstreams", child_parent_col="route_domain",
  ),
)

# Columns we ignore when comparing two rows for "did anything change".
# These get bumped on every write and would otherwise mask real diffs.
_COMPARE_IGNORE = ("updated_at", "created_at")


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------


def _connect(dsn: str, *, timeout: float = 15.0) -> psycopg.Connection:
  """Open a fresh dict-row connection to ``dsn``. Caller closes."""
  return psycopg.connect(dsn, row_factory=dict_row, connect_timeout=int(timeout))


def test_target_connection(dsn: str) -> dict[str, Any]:
  """Connect, run ``SELECT 1``, list tables we'll sync against. Used
  by the UI's "Test connection" button before saving."""
  with _connect(dsn) as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT 1 AS ok")
      cur.fetchone()
      missing: list[str] = []
      for spec in SYNC_TABLES:
        try:
          cur.execute(f"SELECT 1 FROM {spec.name} LIMIT 1")
          cur.fetchone()
        except Exception:  # noqa: BLE001
          missing.append(spec.name)
  return {
    "ok": True,
    "missing_tables": missing,
    "checked_tables": [s.name for s in SYNC_TABLES],
  }


# ---------------------------------------------------------------------------
# Reading + diff
# ---------------------------------------------------------------------------


def _select_table(cur: psycopg.Cursor, spec: TableSpec) -> dict[tuple, dict]:
  """Return {pk_tuple: row_dict} for the table. PK tuple lets us key
  composite-PK tables transparently."""
  where = f" WHERE {spec.filter_where}" if spec.filter_where else ""
  cur.execute(f"SELECT * FROM {spec.name}{where}")
  out: dict[tuple, dict] = {}
  for row in cur.fetchall():
    pk = tuple(row[c] for c in spec.pk_cols)
    out[pk] = dict(row)
  return out


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
  """
  if direction not in ("AtoB", "BtoA"):
    raise ValueError(f"direction must be AtoB or BtoA, got {direction!r}")
  src, tgt = (source_dsn, target_dsn) if direction == "AtoB" else (target_dsn, source_dsn)

  per_table: list[dict] = []
  with _connect(src) as src_conn, _connect(tgt) as tgt_conn:
    with src_conn.cursor() as src_cur, tgt_conn.cursor() as tgt_cur:
      for spec in SYNC_TABLES:
        try:
          src_rows = _select_table(src_cur, spec)
          tgt_rows = _select_table(tgt_cur, spec)
          per_table.append(_diff_table(src_rows, tgt_rows, spec))
        except Exception as exc:  # noqa: BLE001
          LOGGER.exception("analyze: read failed for %s", spec.name)
          per_table.append({
            "table": spec.name, "error": str(exc),
            "insert": 0, "overwrite": 0, "preserve_only_in_target": 0,
            "sample_insert": [], "sample_overwrite": [],
          })

  totals = {
    "insert": sum(t.get("insert", 0) for t in per_table),
    "overwrite": sum(t.get("overwrite", 0) for t in per_table),
    "preserve_only_in_target": sum(t.get("preserve_only_in_target", 0) for t in per_table),
  }
  return {
    "direction": direction,
    "tables": per_table,
    "totals": totals,
    "at": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
  }


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def _build_upsert_sql(table: str, cols: list[str], pk_cols: tuple[str, ...]) -> str:
  pk_clause = ", ".join(pk_cols)
  set_clauses = ", ".join(f"{c} = EXCLUDED.{c}" for c in cols if c not in pk_cols)
  ph = ", ".join(["%s"] * len(cols))
  if not set_clauses:
    # Pure-PK table — nothing to update on conflict.
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
) -> dict[str, Any]:
  """Sync ONE table source→target. Per-table transaction."""
  with src_conn.cursor() as src_cur:
    src_rows = _select_table(src_cur, spec)
  if not src_rows:
    return {"table": spec.name, "rows_applied": 0, "child_rows_applied": 0}
  cols = list(next(iter(src_rows.values())).keys())
  upsert_sql = _build_upsert_sql(spec.name, cols, spec.pk_cols)

  child_rows_total = 0
  with tgt_conn.cursor() as tcur:
    try:
      for row in src_rows.values():
        tcur.execute(upsert_sql, [row.get(c) for c in cols])

      if spec.child_table and spec.child_parent_col and spec.pk_cols:
        # Replace children for each parent we just touched.
        parent_pks = [pk[0] for pk in src_rows.keys()]
        if parent_pks:
          ph = ",".join(["%s"] * len(parent_pks))
          tcur.execute(
            f"DELETE FROM {spec.child_table} "
            f"WHERE {spec.child_parent_col} IN ({ph})",
            parent_pks,
          )
          # Pull source children now and insert.
          with src_conn.cursor() as src_cur:
            src_cur.execute(
              f"SELECT * FROM {spec.child_table} "
              f"WHERE {spec.child_parent_col} IN ({ph})",
              parent_pks,
            )
            child_rows = src_cur.fetchall()
          if child_rows:
            child_cols = [
              c for c in child_rows[0].keys()
              if c != "id"  # auto-generated; let target re-issue
            ]
            child_ph = "(" + ",".join(["%s"] * len(child_cols)) + ")"
            placeholders = ",".join([child_ph] * len(child_rows))
            flat: list = []
            for cr in child_rows:
              flat.extend(cr[c] for c in child_cols)
            tcur.execute(
              f"INSERT INTO {spec.child_table} "
              f"({','.join(child_cols)}) VALUES {placeholders}",
              flat,
            )
            child_rows_total = len(child_rows)
      tgt_conn.commit()
      LOGGER.info("sync.apply table=%s rows=%d children=%d",
                  spec.name, len(src_rows), child_rows_total)
      return {
        "table": spec.name,
        "rows_applied": len(src_rows),
        "child_rows_applied": child_rows_total,
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
) -> dict[str, Any]:
  """Run the sync. Each table is its own transaction so a failure in
  one table doesn't lose the others. Returns per-table results +
  any errors."""
  if direction not in ("AtoB", "BtoA"):
    raise ValueError(f"direction must be AtoB or BtoA, got {direction!r}")
  src, tgt = (source_dsn, target_dsn) if direction == "AtoB" else (target_dsn, source_dsn)

  results: list[dict] = []
  errors: list[dict] = []
  with _connect(src) as src_conn, _connect(tgt) as tgt_conn:
    for spec in SYNC_TABLES:
      r = _apply_one_table(spec, src_conn, tgt_conn)
      if r.get("error"):
        errors.append({"table": r["table"], "error": r["error"]})
      results.append(r)

  return {
    "direction": direction,
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
