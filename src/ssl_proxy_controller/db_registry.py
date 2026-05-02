"""Multi-database registry — the list of Postgres DSNs the admin
knows about. Stored as a single row in the ``system_config`` table
under the key ``databases``, **always** in the admin's home schema
(the schema reachable via the bootstrap DSN from ``.env``).

The principle: runtime state lives in exactly two places —
  1. the ``.env`` file (immutable per-deploy bootstrap DSN)
  2. the database

The home schema is determined entirely by ``.env`` and never
changes for the lifetime of the admin process. Even after the
operator clicks "Set Active" on some other DSN, the registry
continues to live on the home schema; only the working
connection pool flips. That way the registry is a single global
place — not per-schema as the previous design accidentally was.

Storage shape::

    {
      "entries": [
        {"id": "aabbccdd", "label": "Primary",
         "dsn": "postgresql://…", "added_at": "...",
         "selected": false},
        {"id": "ffeeddcc", "label": "one",
         "dsn": "postgresql://…", "added_at": "...",
         "selected": true}      <-- exactly one row should be true
      ]
    }

Semantics:

- An entry's ``selected`` flag marks the working DSN. The admin
  starts on the bootstrap DSN, then immediately checks which entry
  is selected and (if it's a different DSN) live-swaps its working
  pool. The selected DSN is what the resolver token
  ``database:<id>`` expands to when deploying ssl-service to remote
  nodes.
- ``entries`` is the full list. Ids are 12-char hex tokens, stable
  across edits.
- Backwards compat: payloads written by the previous version had a
  top-level ``active_id`` field instead of per-entry ``selected``.
  ``_normalize_registry`` upgrades them transparently on read.
"""
from __future__ import annotations

import logging
import secrets
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("ssl_proxy_controller.db_registry")

_LOCK = threading.Lock()

_SYS_KEY = "databases"


def _now_iso() -> str:
  return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


def _new_id() -> str:
  return secrets.token_hex(6)


def _empty_registry() -> dict:
  return {"entries": []}


def _normalize_registry(data: Any) -> dict:
  """Coerce any prior format into the canonical ``{"entries": [...]}``
  shape. Handles two legacy variants:

  - ``{"active_id": X, "entries": [...]}``  (the previous on-disk
    format) → translate ``active_id`` into per-entry ``selected``.
  - ``{"databases": [...]}`` (the original YAML format) → rename to
    ``entries``.
  """
  if not isinstance(data, dict):
    return _empty_registry()
  raw_entries = data.get("entries") or data.get("databases") or []
  active_id = data.get("active_id")  # legacy field — may be absent
  out = _empty_registry()
  if not isinstance(raw_entries, list):
    return out
  for e in raw_entries:
    if not isinstance(e, dict) or not e.get("id") or not e.get("dsn"):
      continue
    selected = e.get("selected")
    if selected is None and active_id is not None:
      # Legacy upgrade path: convert active_id into selected.
      selected = (e.get("id") == active_id)
    out["entries"].append({
      "id": e.get("id"),
      "label": e.get("label") or "Unlabeled",
      "dsn": e.get("dsn") or "",
      "added_at": e.get("added_at") or _now_iso(),
      "selected": bool(selected),
      **({"updated_at": e["updated_at"]} if e.get("updated_at") else {}),
    })
  # Defensive: if more than one entry has selected=true (shouldn't
  # happen but legacy data could be messy), keep only the first.
  seen_selected = False
  for e in out["entries"]:
    if e["selected"]:
      if seen_selected:
        e["selected"] = False
      else:
        seen_selected = True
  return out


def _load(database) -> dict:
  """Read the registry from system_config['databases'] **on the home
  schema**. Returns ``_empty_registry()`` if not yet seeded."""
  try:
    raw = database.get_system_config_home(_SYS_KEY)
  except Exception:  # noqa: BLE001
    LOGGER.exception("could not read system_config[%s]; treating as empty", _SYS_KEY)
    return _empty_registry()
  return _normalize_registry(raw)


def _save(database, data: dict) -> None:
  """Persist the registry into system_config['databases'] **on the
  home schema**."""
  try:
    database.upsert_system_config_home(_SYS_KEY, data)
  except Exception:  # noqa: BLE001
    LOGGER.exception("failed to persist registry into system_config[%s]", _SYS_KEY)
    raise


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


def _find_selected(entries: list[dict]) -> dict | None:
  for e in entries:
    if e.get("selected"):
      return e
  return None


def ensure_bootstrap(database, current_dsn: str) -> list[dict]:
  """Idempotent. Two side effects in priority order:

  1. If the registry is empty, seed it with ``current_dsn`` so the UI
     always has at least one row to show, marked ``selected=true``.
  2. If no entry is marked ``selected`` but one matches the bootstrap
     DSN, mark that one selected.
  """
  with _LOCK:
    data = _load(database)
    changed = False

    if current_dsn and not _find_by_dsn(data["entries"], current_dsn):
      data["entries"].append({
        "id": _new_id(),
        "label": "Primary",
        "dsn": current_dsn,
        "added_at": _now_iso(),
        "selected": False,
      })
      changed = True

    matching = _find_by_dsn(data["entries"], current_dsn) if current_dsn else None
    selected = _find_selected(data["entries"])
    if selected is None and matching is not None:
      matching["selected"] = True
      changed = True
    elif selected is None and data["entries"]:
      # Nothing selected and bootstrap DSN doesn't match anything —
      # default to the first entry so the working pool isn't ambiguous.
      data["entries"][0]["selected"] = True
      changed = True

    if changed:
      _save(database, data)
    return list(data["entries"])


# ---------------------------------------------------------------------------
# Public read API
# ---------------------------------------------------------------------------


def list_databases(database, current_dsn: str) -> dict[str, Any]:
  entries = ensure_bootstrap(database, current_dsn)
  current_entry = _find_by_dsn(entries, current_dsn) if current_dsn else None
  selected = _find_selected(entries)
  selected_id = selected["id"] if selected else None
  return {
    "current_id": current_entry["id"] if current_entry else None,
    # Kept for any callers still reading these older keys; both now
    # mean "the entry whose ``selected`` flag is true".
    "active_id": selected_id,
    "primary_id": selected_id,
    "entries": [
      {
        "id": e["id"],
        "label": e.get("label") or "",
        "dsn": e.get("dsn") or "",
        "added_at": e.get("added_at"),
        "selected": bool(e.get("selected")),
        "is_current": (current_entry is not None and e["id"] == current_entry["id"]),
        # ``is_active`` / ``is_primary`` are old field names the UI
        # may still consult; they all mean the same thing now.
        "is_active": bool(e.get("selected")),
        "is_primary": bool(e.get("selected")),
      }
      for e in entries
    ],
  }


def get_dsn(database, db_id: str) -> str | None:
  entries = _load(database)["entries"]
  e = _find(entries, db_id)
  return e.get("dsn") if e else None


def get_active_dsn(database) -> str | None:
  """Return the DSN of the entry whose ``selected`` flag is true, or
  ``None`` if no entry is marked selected."""
  data = _load(database)
  selected = _find_selected(data["entries"])
  return selected.get("dsn") if selected else None


def get_primary_id(database) -> str | None:
  data = _load(database)
  selected = _find_selected(data["entries"])
  return selected.get("id") if selected else None


# ---------------------------------------------------------------------------
# Public write API
# ---------------------------------------------------------------------------


def add_database(database, *, label: str, dsn: str) -> dict:
  with _LOCK:
    data = _load(database)
    if _find_by_dsn(data["entries"], dsn):
      raise ValueError("a database with that DSN is already registered")
    entry = {
      "id": _new_id(),
      "label": (label or "").strip() or "Unlabeled",
      "dsn": dsn,
      "added_at": _now_iso(),
      "selected": False,
    }
    data["entries"].append(entry)
    _save(database, data)
    return entry


def update_database(
  database, db_id: str, *, label: str | None = None, dsn: str | None = None,
) -> dict | None:
  with _LOCK:
    data = _load(database)
    e = _find(data["entries"], db_id)
    if e is None:
      return None
    if label is not None:
      e["label"] = label.strip() or e.get("label") or "Unlabeled"
    if dsn is not None:
      other = _find_by_dsn(data["entries"], dsn)
      if other is not None and other.get("id") != db_id:
        raise ValueError("another database with that DSN is already registered")
      e["dsn"] = dsn
    e["updated_at"] = _now_iso()
    _save(database, data)
    return e


def delete_database(database, db_id: str, *, current_dsn: str) -> bool:
  with _LOCK:
    data = _load(database)
    e = _find(data["entries"], db_id)
    if e is None:
      return False
    if e.get("dsn") == current_dsn:
      raise ValueError("cannot delete the database that is currently in use")
    if e.get("selected"):
      # Clear the selected flag instead of leaving a dangling
      # selection. Caller should set a different entry as selected
      # before deleting the active one in normal flows; this is just
      # a defensive guard.
      e["selected"] = False
    data["entries"] = [x for x in data["entries"] if x.get("id") != db_id]
    _save(database, data)
    return True


def set_active(database, db_id: str) -> dict:
  """Mark ``db_id`` as the selected entry (clearing the flag on every
  other entry). Returns the new entry. Raises ``ValueError`` if the
  id is unknown. Caller (the admin endpoint) is responsible for the
  in-process pool swap; this function only updates the persisted
  record."""
  with _LOCK:
    data = _load(database)
    e = _find(data["entries"], db_id)
    if e is None:
      raise ValueError(f"database not registered: {db_id}")
    for other in data["entries"]:
      other["selected"] = (other.get("id") == db_id)
    _save(database, data)
    return e


# Backwards-compat shim — older endpoint name.
def set_primary_id(database, db_id: str | None) -> None:
  with _LOCK:
    data = _load(database)
    if db_id is None:
      for e in data["entries"]:
        e["selected"] = False
    else:
      for e in data["entries"]:
        e["selected"] = (e.get("id") == db_id)
    _save(database, data)


# Legacy stub — no on-disk file involved any more, but importers
# (a few admin handlers) still reference it. Returning a path that
# doesn't exist is safe.
def file_path() -> Path:
  return Path("/dev/null")
