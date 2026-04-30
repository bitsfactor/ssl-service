"""Multi-database registry — the list of Postgres DSNs the admin
knows about, **persisted to a YAML file** so it survives admin
restarts and the start-admin launcher script can read it before the
admin process even comes up.

File location: ``~/.ssl-service/databases.yaml`` (overridable via the
``SSL_SERVICE_DATABASES_FILE`` env var so tests / users can pick
their own path).

File shape::

    active_id: aabbccdd
    databases:
      - id: aabbccdd
        label: "Primary (config.yaml)"
        dsn: "postgresql://…"
      - id: ffeeddcc
        label: "one"
        dsn: "postgresql://…"

Semantics:

- ``active_id`` is the DSN the admin should connect to. The launcher
  script reads this and writes the right DSN into the runtime
  config.yaml. The admin process itself can also re-read this file
  and swap its connection pool live (see ``Database.swap_to``).
- ``databases`` is the full list. ids are 12-char hex tokens, stable
  across edits.

A separate one-time migration brings any old registry entries from
``system_config['databases']`` into this file on first read. After
migration the system_config row is left in place but stops being the
source of truth.
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

# Lock guards file read/write so two concurrent activate requests don't
# step on each other.
_FILE_LOCK = threading.Lock()


def _file_path() -> Path:
  override = os.environ.get("SSL_SERVICE_DATABASES_FILE")
  if override:
    return Path(override).expanduser()
  return Path.home() / ".ssl-service" / "databases.yaml"


def _now_iso() -> str:
  return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")


def _new_id() -> str:
  return secrets.token_hex(6)


def _load_raw() -> dict:
  path = _file_path()
  if not path.is_file():
    return {"active_id": None, "databases": []}
  try:
    data = yaml.safe_load(path.read_text()) or {}
  except Exception:  # noqa: BLE001
    LOGGER.exception("could not parse %s; treating as empty", path)
    return {"active_id": None, "databases": []}
  if not isinstance(data, dict):
    return {"active_id": None, "databases": []}
  data.setdefault("active_id", None)
  data.setdefault("databases", [])
  if not isinstance(data["databases"], list):
    data["databases"] = []
  return data


def _save_raw(data: dict) -> None:
  path = _file_path()
  path.parent.mkdir(parents=True, exist_ok=True)
  # Write to a temp file then atomically rename so a crash mid-write
  # doesn't leave a half-truncated registry behind.
  tmp = path.with_suffix(".yaml.tmp")
  tmp.write_text(yaml.safe_dump(data, sort_keys=False))
  tmp.replace(path)
  try:
    os.chmod(path, 0o600)
  except Exception:  # noqa: BLE001
    pass


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


def _migrate_from_system_config_if_empty(database) -> bool:
  """One-shot import: if the YAML file doesn't have any entries yet
  but the running admin's system_config already has the multi-DB
  registry from the old design, copy them over. Returns True if any
  rows were imported."""
  data = _load_raw()
  if data["databases"]:
    return False
  changed = False
  try:
    cfg = database.get_system_config("databases") or {}
    legacy = cfg.get("entries") if isinstance(cfg, dict) else None
    if isinstance(legacy, list):
      for e in legacy:
        if e.get("id") and e.get("dsn"):
          data["databases"].append({
            "id": e["id"],
            "label": e.get("label") or "Unlabeled",
            "dsn": e["dsn"],
            "added_at": e.get("added_at") or _now_iso(),
          })
          changed = True
    primary_cfg = database.get_system_config("primary_db_id") or {}
    primary_id = primary_cfg.get("id") if isinstance(primary_cfg, dict) else None
    if primary_id and _find(data["databases"], primary_id):
      data["active_id"] = primary_id
      changed = True
  except Exception:  # noqa: BLE001
    LOGGER.exception("could not migrate from system_config; starting empty")
  if changed:
    _save_raw(data)
    LOGGER.info("registry: migrated %d entries from system_config to %s",
                len(data["databases"]), _file_path())
  return changed


def ensure_bootstrap(database, current_dsn: str) -> list[dict]:
  """Idempotent. Three side effects in priority order:

  1. Migrate from system_config['databases'] if our YAML file is empty
     (preserves the user's earlier registry across the persistence
     refactor).
  2. If the registry is still empty, seed it with the
     currently-connected DSN so the UI has at least one row to show.
  3. If active_id is unset OR points at a stale id, set it to the
     entry whose DSN matches ``current_dsn``.
  """
  with _FILE_LOCK:
    _migrate_from_system_config_if_empty(database)
    data = _load_raw()
    changed = False

    if current_dsn and not _find_by_dsn(data["databases"], current_dsn):
      data["databases"].append({
        "id": _new_id(),
        "label": "Primary (config.yaml)",
        "dsn": current_dsn,
        "added_at": _now_iso(),
      })
      changed = True

    matching = _find_by_dsn(data["databases"], current_dsn) if current_dsn else None
    if data.get("active_id") is None and matching:
      data["active_id"] = matching["id"]
      changed = True
    elif data.get("active_id") and not _find(data["databases"], data["active_id"]):
      data["active_id"] = matching["id"] if matching else (data["databases"][0]["id"] if data["databases"] else None)
      changed = True

    if changed:
      _save_raw(data)
    return list(data["databases"])


# ---------------------------------------------------------------------------
# Public read API
# ---------------------------------------------------------------------------


def list_databases(database, current_dsn: str) -> dict[str, Any]:
  entries = ensure_bootstrap(database, current_dsn)
  data = _load_raw()
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
  entries = _load_raw()["databases"]
  e = _find(entries, db_id)
  return e.get("dsn") if e else None


def get_active_dsn(database) -> str | None:
  data = _load_raw()
  active_id = data.get("active_id")
  if not active_id:
    return None
  e = _find(data["databases"], active_id)
  return e.get("dsn") if e else None


def get_primary_id(database) -> str | None:
  return _load_raw().get("active_id")


# ---------------------------------------------------------------------------
# Public write API
# ---------------------------------------------------------------------------


def add_database(database, *, label: str, dsn: str) -> dict:
  with _FILE_LOCK:
    data = _load_raw()
    if _find_by_dsn(data["databases"], dsn):
      raise ValueError("a database with that DSN is already registered")
    entry = {
      "id": _new_id(),
      "label": (label or "").strip() or "Unlabeled",
      "dsn": dsn,
      "added_at": _now_iso(),
    }
    data["databases"].append(entry)
    _save_raw(data)
    return entry


def update_database(
  database, db_id: str, *, label: str | None = None, dsn: str | None = None,
) -> dict | None:
  with _FILE_LOCK:
    data = _load_raw()
    e = _find(data["databases"], db_id)
    if e is None:
      return None
    if label is not None:
      e["label"] = label.strip() or e.get("label") or "Unlabeled"
    if dsn is not None:
      other = _find_by_dsn(data["databases"], dsn)
      if other is not None and other.get("id") != db_id:
        raise ValueError("another database with that DSN is already registered")
      e["dsn"] = dsn
    e["updated_at"] = _now_iso()
    _save_raw(data)
    return e


def delete_database(database, db_id: str, *, current_dsn: str) -> bool:
  with _FILE_LOCK:
    data = _load_raw()
    e = _find(data["databases"], db_id)
    if e is None:
      return False
    if e.get("dsn") == current_dsn:
      raise ValueError("cannot delete the database that is currently in use")
    if data.get("active_id") == db_id:
      data["active_id"] = None
    data["databases"] = [x for x in data["databases"] if x.get("id") != db_id]
    _save_raw(data)
    return True


def set_active(database, db_id: str) -> dict:
  """Switch the active DSN. Returns the new entry. Raises ValueError
  if the id is unknown. Caller (the admin endpoint) is responsible
  for the in-process pool swap; this function only updates the
  persisted file."""
  with _FILE_LOCK:
    data = _load_raw()
    e = _find(data["databases"], db_id)
    if e is None:
      raise ValueError(f"database not registered: {db_id}")
    data["active_id"] = db_id
    _save_raw(data)
    return e


# Backwards-compat shim — older endpoint name was ``set_primary_id``.
def set_primary_id(database, db_id: str | None) -> None:
  with _FILE_LOCK:
    data = _load_raw()
    if db_id is None:
      data["active_id"] = None
    else:
      if not _find(data["databases"], db_id):
        # Just persist; older code path didn't validate.
        pass
      data["active_id"] = db_id
    _save_raw(data)


def file_path() -> Path:
  """Public accessor — used by the launcher and the migration log."""
  return _file_path()
