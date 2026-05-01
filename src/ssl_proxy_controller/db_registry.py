"""Multi-database registry — the list of Postgres DSNs the admin
knows about, **persisted in the active database's** ``system_config``
table under the ``databases`` key. Single source of truth = the DB
itself; nothing on the local filesystem.

The principle: runtime state lives in exactly two places —
  1. the ``.env`` file (immutable per-deploy config)
  2. the database
That way a fresh admin checkout on a brand-new machine inherits the
operator's full registry as soon as it connects to the bootstrap DSN.
There is no per-machine YAML to remember to copy.

Storage shape (one ``system_config`` row, key=``databases``)::

    {
      "active_id": "aabbccdd",
      "entries": [
        {"id": "aabbccdd", "label": "Primary",
         "dsn": "postgresql://…", "added_at": "..."},
        {"id": "ffeeddcc", "label": "one",
         "dsn": "postgresql://…", "added_at": "..."}
      ]
    }

Semantics:

- ``active_id`` is the DSN the admin should connect to. The admin
  starts with the bootstrap DSN from its env, then immediately checks
  this field and swaps its pool to the active DSN if different. The
  resolver token ``database:<id>`` is what
  ``service.default_env`` references when deploying ssl-service to
  remote nodes — the admin expands it at deploy time so the actual
  DSN never round-trips through the browser.
- ``entries`` is the full list. ids are 12-char hex tokens, stable
  across edits.

A one-shot migration runs on first read: if the running admin used to
write ``~/.ssl-service/databases.yaml``, we import its contents into
``system_config['databases']`` and then ignore the file forever. If
the legacy file is absent the migration is a no-op.
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

LOGGER = logging.getLogger("ssl_proxy_controller.db_registry")

_LOCK = threading.Lock()

_SYS_KEY = "databases"


def _now_iso() -> str:
  return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


def _new_id() -> str:
  return secrets.token_hex(6)


# Legacy file path — only read once during migration, never written.
def _legacy_yaml_path() -> Path:
  override = os.environ.get("SSL_SERVICE_DATABASES_FILE")
  if override:
    return Path(override).expanduser()
  return Path.home() / ".ssl-service" / "databases.yaml"


def _empty_registry() -> dict:
  return {"active_id": None, "entries": []}


def _normalize_registry(data: Any) -> dict:
  if not isinstance(data, dict):
    return _empty_registry()
  out = _empty_registry()
  out["active_id"] = data.get("active_id")
  raw = data.get("entries") or data.get("databases") or []
  if isinstance(raw, list):
    out["entries"] = [
      {
        "id": e.get("id"),
        "label": e.get("label") or "Unlabeled",
        "dsn": e.get("dsn") or "",
        "added_at": e.get("added_at") or _now_iso(),
        **({"updated_at": e["updated_at"]} if e.get("updated_at") else {}),
      }
      for e in raw if isinstance(e, dict) and e.get("id") and e.get("dsn")
    ]
  return out


def _load(database) -> dict:
  """Read the registry from system_config['databases']. Returns
  ``_empty_registry()`` if not yet seeded."""
  try:
    raw = database.get_system_config(_SYS_KEY)
  except Exception:  # noqa: BLE001
    LOGGER.exception("could not read system_config[%s]; treating as empty", _SYS_KEY)
    return _empty_registry()
  return _normalize_registry(raw)


def _save(database, data: dict) -> None:
  """Persist the registry into system_config['databases']."""
  try:
    database.upsert_system_config(_SYS_KEY, data)
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


def _migrate_legacy_yaml_if_needed(database) -> bool:
  """One-shot import: if a legacy ``~/.ssl-service/databases.yaml``
  exists from before this refactor AND the DB doesn't yet have any
  registry entries, copy the file contents into ``system_config``.
  Doesn't delete the file — operator can clean it up after verifying
  the migration."""
  current = _load(database)
  if current["entries"]:
    return False
  path = _legacy_yaml_path()
  if not path.is_file():
    return False
  try:
    raw = yaml.safe_load(path.read_text()) or {}
  except Exception:  # noqa: BLE001
    LOGGER.exception("could not parse legacy %s; skipping migration", path)
    return False
  imported = _normalize_registry(raw)
  if not imported["entries"]:
    return False
  _save(database, imported)
  LOGGER.info("registry: migrated %d entries from legacy file %s into "
              "system_config[%s] — file may be deleted",
              len(imported["entries"]), path, _SYS_KEY)
  return True


def ensure_bootstrap(database, current_dsn: str) -> list[dict]:
  """Idempotent. Three side effects in priority order:

  1. One-time migrate from legacy YAML file if present and registry empty.
  2. If the registry is still empty, seed it with ``current_dsn`` so
     the UI always has at least one row to show.
  3. If active_id is unset OR points at a stale id, set it to the
     entry whose DSN matches ``current_dsn``.
  """
  with _LOCK:
    _migrate_legacy_yaml_if_needed(database)
    data = _load(database)
    changed = False

    if current_dsn and not _find_by_dsn(data["entries"], current_dsn):
      data["entries"].append({
        "id": _new_id(),
        "label": "Primary",
        "dsn": current_dsn,
        "added_at": _now_iso(),
      })
      changed = True

    matching = _find_by_dsn(data["entries"], current_dsn) if current_dsn else None
    if data.get("active_id") is None and matching:
      data["active_id"] = matching["id"]
      changed = True
    elif data.get("active_id") and not _find(data["entries"], data["active_id"]):
      data["active_id"] = matching["id"] if matching else (
        data["entries"][0]["id"] if data["entries"] else None)
      changed = True

    if changed:
      _save(database, data)
    return list(data["entries"])


# ---------------------------------------------------------------------------
# Public read API
# ---------------------------------------------------------------------------


def list_databases(database, current_dsn: str) -> dict[str, Any]:
  entries = ensure_bootstrap(database, current_dsn)
  data = _load(database)
  current_entry = _find_by_dsn(entries, current_dsn) if current_dsn else None
  active_id = data.get("active_id")
  return {
    "current_id": current_entry["id"] if current_entry else None,
    "active_id": active_id,
    # Kept for backward-compat with the older field name in the UI.
    "primary_id": active_id,
    "entries": [
      {
        "id": e["id"],
        "label": e.get("label") or "",
        "dsn": e.get("dsn") or "",
        "added_at": e.get("added_at"),
        "is_current": (current_entry is not None and e["id"] == current_entry["id"]),
        "is_active": (active_id is not None and e["id"] == active_id),
        # Same field with old name for the existing UI build.
        "is_primary": (active_id is not None and e["id"] == active_id),
      }
      for e in entries
    ],
  }


def get_dsn(database, db_id: str) -> str | None:
  entries = _load(database)["entries"]
  e = _find(entries, db_id)
  return e.get("dsn") if e else None


def get_active_dsn(database) -> str | None:
  data = _load(database)
  active_id = data.get("active_id")
  if not active_id:
    return None
  e = _find(data["entries"], active_id)
  return e.get("dsn") if e else None


def get_primary_id(database) -> str | None:
  return _load(database).get("active_id")


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
    if data.get("active_id") == db_id:
      data["active_id"] = None
    data["entries"] = [x for x in data["entries"] if x.get("id") != db_id]
    _save(database, data)
    return True


def set_active(database, db_id: str) -> dict:
  """Switch the active DSN in the registry. Returns the new entry.
  Raises ValueError if the id is unknown. Caller (the admin endpoint)
  is responsible for the in-process pool swap; this function only
  updates the persisted record."""
  with _LOCK:
    data = _load(database)
    e = _find(data["entries"], db_id)
    if e is None:
      raise ValueError(f"database not registered: {db_id}")
    data["active_id"] = db_id
    _save(database, data)
    return e


# Backwards-compat shim — older endpoint name was ``set_primary_id``.
def set_primary_id(database, db_id: str | None) -> None:
  with _LOCK:
    data = _load(database)
    if db_id is None:
      data["active_id"] = None
    else:
      if not _find(data["entries"], db_id):
        pass
      data["active_id"] = db_id
    _save(database, data)


def file_path() -> Path:
  """Legacy public accessor — only meaningful pre-migration. Kept so
  any caller still importing it doesn't crash, but the file is no
  longer the source of truth."""
  return _legacy_yaml_path()
