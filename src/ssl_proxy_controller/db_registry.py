"""Multi-database registry — the list of Postgres DSNs the admin
knows about, stored in ``system_config['databases']``.

The currently-connected DSN (whatever ``ctx.config.postgres.dsn`` is)
is *always* included; we auto-add it on first read so the user can
immediately label/edit it from the UI. A separate
``system_config['primary_db_id']`` key tracks which entry the user
wants to use *next time the admin restarts* — flipping primary is a
preference, not a live-swap (admin keeps using whatever it booted
against until restart).
"""
from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime
from typing import Any

LOGGER = logging.getLogger("ssl_proxy_controller.db_registry")

_DATABASES_KEY = "databases"
_PRIMARY_ID_KEY = "primary_db_id"
_LEGACY_SECONDARY_KEY = "secondary_db_dsn"


def _now_iso() -> str:
  return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


def _read_entries(database) -> list[dict]:
  cfg = database.get_system_config(_DATABASES_KEY) or {}
  entries = cfg.get("entries") if isinstance(cfg, dict) else None
  return list(entries) if isinstance(entries, list) else []


def _write_entries(database, entries: list[dict]) -> None:
  database.upsert_system_config(_DATABASES_KEY, {"entries": entries})


def _new_id() -> str:
  return secrets.token_hex(6)


def _find(entries: list[dict], db_id: str) -> dict | None:
  for e in entries:
    if e.get("id") == db_id:
      return e
  return None


def _find_by_dsn(entries: list[dict], dsn: str) -> dict | None:
  for e in entries:
    if (e.get("dsn") or "") == dsn:
      return e
  return None


def get_primary_id(database) -> str | None:
  cfg = database.get_system_config(_PRIMARY_ID_KEY) or {}
  return (cfg.get("id") or None) if isinstance(cfg, dict) else None


def set_primary_id(database, db_id: str | None) -> None:
  database.upsert_system_config(_PRIMARY_ID_KEY, {"id": db_id})


def ensure_bootstrap(database, current_dsn: str) -> list[dict]:
  """Idempotent. Two side effects:

  1. If the registry is empty, seed it with the currently-connected
     DSN (label="Primary (config.yaml)") so the UI always has at least
     one entry to show.
  2. If the legacy ``secondary_db_dsn`` key is present and the same
     DSN isn't already in the list, copy it over as a "Secondary" entry.
  """
  entries = _read_entries(database)
  changed = False

  if current_dsn and not _find_by_dsn(entries, current_dsn):
    entries.append({
      "id": _new_id(),
      "label": "Primary (config.yaml)",
      "dsn": current_dsn,
      "added_at": _now_iso(),
    })
    changed = True

  legacy = database.get_system_config(_LEGACY_SECONDARY_KEY) or {}
  legacy_dsn = (legacy.get("dsn") or "").strip() if isinstance(legacy, dict) else ""
  if legacy_dsn and not _find_by_dsn(entries, legacy_dsn):
    entries.append({
      "id": _new_id(),
      "label": "Secondary",
      "dsn": legacy_dsn,
      "added_at": _now_iso(),
    })
    changed = True

  if changed:
    _write_entries(database, entries)
  return entries


def list_databases(database, current_dsn: str) -> dict[str, Any]:
  """Return the full registry view for the UI."""
  entries = ensure_bootstrap(database, current_dsn)
  primary_id = get_primary_id(database)
  current_entry = _find_by_dsn(entries, current_dsn)
  return {
    "current_id": current_entry["id"] if current_entry else None,
    "primary_id": primary_id,
    "entries": [
      {
        "id": e["id"],
        "label": e.get("label") or "",
        "dsn": e.get("dsn") or "",
        "added_at": e.get("added_at"),
        "is_current": (current_entry is not None and e["id"] == current_entry["id"]),
        "is_primary": (primary_id is not None and e["id"] == primary_id),
      }
      for e in entries
    ],
  }


def add_database(database, *, label: str, dsn: str) -> dict:
  entries = _read_entries(database)
  if _find_by_dsn(entries, dsn):
    raise ValueError("a database with that DSN is already registered")
  entry = {
    "id": _new_id(),
    "label": (label or "").strip() or "Unlabeled",
    "dsn": dsn,
    "added_at": _now_iso(),
  }
  entries.append(entry)
  _write_entries(database, entries)
  return entry


def update_database(
  database, db_id: str, *, label: str | None = None, dsn: str | None = None,
) -> dict | None:
  entries = _read_entries(database)
  e = _find(entries, db_id)
  if e is None:
    return None
  if label is not None:
    e["label"] = label.strip() or e.get("label") or "Unlabeled"
  if dsn is not None:
    # Avoid duplicate DSNs across distinct entries.
    other = _find_by_dsn(entries, dsn)
    if other is not None and other.get("id") != db_id:
      raise ValueError("another database with that DSN is already registered")
    e["dsn"] = dsn
  e["updated_at"] = _now_iso()
  _write_entries(database, entries)
  return e


def delete_database(database, db_id: str, *, current_dsn: str) -> bool:
  entries = _read_entries(database)
  e = _find(entries, db_id)
  if e is None:
    return False
  if e.get("dsn") == current_dsn:
    raise ValueError("cannot delete the database that is currently in use")
  primary_id = get_primary_id(database)
  if primary_id == db_id:
    set_primary_id(database, None)
  _write_entries(database, [x for x in entries if x.get("id") != db_id])
  return True


def get_dsn(database, db_id: str) -> str | None:
  entries = _read_entries(database)
  e = _find(entries, db_id)
  return (e.get("dsn") if e else None)
