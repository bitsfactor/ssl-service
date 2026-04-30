"""HTTP admin server for ssl-service.

A minimal, dependency-free admin backend that exposes REST APIs for
managing routes, certificates, DNS zone tokens, and runtime state, plus a
static single-page frontend (``index.html``) that consumes the same API.

The server is designed to run in the same process as the main controller
loop, on a dedicated background thread, and to be safe to disable via
config.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import subprocess
import threading
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from .caddy import reload_caddy, validate_upstream_target
from .config import AppConfig
from .db import (
  IP_PROTOCOLS,
  LB_POLICIES,
  NODE_AUTH_METHODS,
  CertificateRecord,
  Database,
  DnsZoneTokenRecord,
  IpTestResultRecord,
  NodeInitRunRecord,
  NodeRecord,
  NodeStatusRecord,
  RouteRecord,
  ServiceDeploymentRecord,
  ServiceNodeStateRecord,
  ServiceRecord,
  SshKeyRecord,
  StaticIpRecord,
  UpstreamRecord,
)
from . import nodes as nodes_mod
from . import nodes_init as nodes_init_mod

LOGGER = logging.getLogger("ssl_proxy_controller.admin")

# Domain syntax: labels of a-z0-9-, no leading/trailing hyphen, dot-separated.
_DOMAIN_RE = re.compile(
  r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _to_jsonable(value: Any) -> Any:
  if value is None:
    return None
  if isinstance(value, (str, int, float, bool)):
    return value
  if isinstance(value, datetime):
    if value.tzinfo is None:
      value = value.replace(tzinfo=UTC)
    else:
      value = value.astimezone(UTC)
    return value.isoformat().replace("+00:00", "Z")
  if isinstance(value, (list, tuple)):
    return [_to_jsonable(item) for item in value]
  if isinstance(value, dict):
    return {str(key): _to_jsonable(val) for key, val in value.items()}
  if is_dataclass(value):
    return _to_jsonable(asdict(value))
  return str(value)


def _route_to_dict(route: RouteRecord) -> dict[str, Any]:
  return {
    "domain": route.domain,
    "upstream_target": route.upstream_target,
    "upstreams": [
      {"target": up.target, "weight": up.weight} for up in (route.upstreams or [])
    ],
    "lb_policy": route.lb_policy,
    "enabled": route.enabled,
    "updated_at": _to_jsonable(route.updated_at),
  }


def _certificate_to_dict(cert: CertificateRecord) -> dict[str, Any]:
  now = datetime.now(tz=UTC)
  expires_in_days: int | None = None
  if cert.not_after is not None:
    expires_in_days = int((cert.not_after - now).total_seconds() // 86400)
  return {
    "domain": cert.domain,
    "not_before": _to_jsonable(cert.not_before),
    "not_after": _to_jsonable(cert.not_after),
    "expires_in_days": expires_in_days,
    "version": cert.version,
    "status": cert.status,
    "source": cert.source,
    "retry_after": _to_jsonable(cert.retry_after),
    "updated_at": _to_jsonable(cert.updated_at),
    "last_error": cert.last_error,
    "has_key_material": bool(cert.fullchain_pem and cert.private_key_pem),
  }


def _zone_to_dict(zone: DnsZoneTokenRecord, *, reveal_token: bool = False) -> dict[str, Any]:
  api_token = zone.api_token if reveal_token else _mask_token(zone.api_token)
  return {
    "zone_name": zone.zone_name,
    "provider": zone.provider,
    "zone_id": zone.zone_id,
    "api_token": api_token,
    "updated_at": _to_jsonable(zone.updated_at),
  }


def _mask_token(token: str) -> str:
  if not token:
    return ""
  if len(token) <= 6:
    return "***"
  return token[:3] + "***" + token[-3:]


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------


class HttpError(Exception):
  def __init__(self, status: int, message: str, *, code: str | None = None) -> None:
    super().__init__(message)
    self.status = status
    self.message = message
    self.code = code or HTTPStatus(status).phrase.lower().replace(" ", "_")


# ---------------------------------------------------------------------------
# Service layer — pure functions over Database + AppConfig
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AdminContext:
  config: AppConfig
  database: Database


def _require_readwrite(ctx: AdminContext) -> None:
  if ctx.config.mode != "readwrite":
    raise HttpError(
      HTTPStatus.FORBIDDEN,
      "this operation is only allowed on a readwrite node",
      code="readwrite_required",
    )


def _normalize_domain(domain: str) -> str:
  candidate = (domain or "").strip().lower().rstrip(".")
  if not candidate:
    raise HttpError(HTTPStatus.BAD_REQUEST, "domain is required", code="domain_required")
  if "*" in candidate:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "wildcard domains are not supported",
      code="wildcard_not_supported",
    )
  if not _DOMAIN_RE.match(candidate):
    raise HttpError(HTTPStatus.BAD_REQUEST, f"invalid domain: {candidate}", code="invalid_domain")
  return candidate


def _normalize_upstream_target(value: Any) -> str | None:
  if value is None:
    return None
  if isinstance(value, int) and not isinstance(value, bool):
    value = f"127.0.0.1:{int(value)}"
  if not isinstance(value, str):
    raise HttpError(HTTPStatus.BAD_REQUEST, "upstream_target must be a string", code="invalid_upstream")
  candidate = value.strip()
  if not candidate:
    return None
  if candidate.isdigit():
    candidate = f"127.0.0.1:{candidate}"
  try:
    return validate_upstream_target(candidate)
  except ValueError as exc:
    raise HttpError(HTTPStatus.BAD_REQUEST, str(exc), code="invalid_upstream") from exc


def _normalize_lb_policy(value: Any, *, default: str = "random") -> str:
  if value is None:
    return default
  if not isinstance(value, str):
    raise HttpError(HTTPStatus.BAD_REQUEST, "lb_policy must be a string", code="invalid_lb_policy")
  candidate = value.strip().lower()
  if not candidate:
    return default
  if candidate not in LB_POLICIES:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      f"lb_policy must be one of: {', '.join(LB_POLICIES)}",
      code="invalid_lb_policy",
    )
  return candidate


def _normalize_upstream_entry(raw: Any) -> UpstreamRecord:
  """Accept either a bare string/int or `{target, weight?}` dict."""
  if isinstance(raw, dict):
    target_raw = raw.get("target")
    weight_raw = raw.get("weight", 1)
    if weight_raw is None:
      weight_raw = 1
    if isinstance(weight_raw, bool) or not isinstance(weight_raw, int):
      try:
        weight = int(weight_raw)
      except (TypeError, ValueError) as exc:
        raise HttpError(
          HTTPStatus.BAD_REQUEST, "upstream weight must be an integer", code="invalid_upstream"
        ) from exc
    else:
      weight = int(weight_raw)
    if weight < 1 or weight > 1000:
      raise HttpError(
        HTTPStatus.BAD_REQUEST,
        "upstream weight must be between 1 and 1000",
        code="invalid_upstream",
      )
  else:
    target_raw = raw
    weight = 1
  target = _normalize_upstream_target(target_raw)
  if target is None:
    raise HttpError(
      HTTPStatus.BAD_REQUEST, "upstream target is required", code="invalid_upstream"
    )
  return UpstreamRecord(target=target, weight=weight)


def _normalize_upstreams_list(value: Any) -> list[UpstreamRecord] | None:
  """Return a deduplicated list of upstreams, or None if the caller
  did not specify the `upstreams` field at all.

  An explicit empty list `[]` is treated as "no upstreams" (certificate-only
  route) and returned as `[]`, distinct from `None` (field absent).
  """
  if value is None:
    return None
  if not isinstance(value, list):
    raise HttpError(
      HTTPStatus.BAD_REQUEST, "upstreams must be a list", code="invalid_upstream"
    )
  if len(value) > 32:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "at most 32 upstreams per route are supported",
      code="too_many_upstreams",
    )
  seen: set[str] = set()
  out: list[UpstreamRecord] = []
  for raw in value:
    entry = _normalize_upstream_entry(raw)
    if entry.target in seen:
      raise HttpError(
        HTTPStatus.BAD_REQUEST,
        f"duplicate upstream target: {entry.target}",
        code="duplicate_upstream",
      )
    seen.add(entry.target)
    out.append(entry)
  return out


# ---------------------------------------------------------------------------
# Log reading helpers
# ---------------------------------------------------------------------------


def tail_file(path: Path, *, max_lines: int = 500) -> list[str]:
  if not path.exists() or not path.is_file():
    return []
  try:
    with path.open("rb") as handle:
      handle.seek(0, os.SEEK_END)
      file_size = handle.tell()
      block_size = 8192
      data = bytearray()
      read_offset = file_size
      while read_offset > 0 and data.count(b"\n") <= max_lines:
        step = min(block_size, read_offset)
        read_offset -= step
        handle.seek(read_offset)
        data[:0] = handle.read(step)
      text = data.decode("utf-8", errors="replace")
  except OSError:
    return []
  lines = text.splitlines()
  return lines[-max_lines:]


# ---------------------------------------------------------------------------
# Domain actions
# ---------------------------------------------------------------------------


def list_routes_summary(ctx: AdminContext) -> list[dict[str, Any]]:
  routes = ctx.database.list_routes()
  return [_route_to_dict(route) for route in routes]


def create_route(ctx: AdminContext, payload: dict[str, Any]) -> dict[str, Any]:
  _require_readwrite(ctx)
  domain = _normalize_domain(payload.get("domain", ""))
  enabled = bool(payload.get("enabled", True))
  lb_policy = _normalize_lb_policy(payload.get("lb_policy"))
  upstreams_field = _normalize_upstreams_list(payload.get("upstreams"))
  # Back-compat: accept `upstream_target` when `upstreams` is absent.
  if upstreams_field is None:
    single = _normalize_upstream_target(payload.get("upstream_target"))
    upstreams_field = [UpstreamRecord(target=single, weight=1)] if single else []
  if lb_policy != "random" and len(upstreams_field) < 2:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "lb_policy only applies when there are two or more upstreams",
      code="lb_policy_requires_multiple_upstreams",
    )
  existing = ctx.database.get_route(domain)
  if existing is not None:
    raise HttpError(
      HTTPStatus.CONFLICT, f"route already exists: {domain}", code="route_exists"
    )
  primary = upstreams_field[0].target if upstreams_field else None
  route = ctx.database.insert_route(
    domain,
    primary,
    enabled=enabled,
    upstreams=upstreams_field,
    lb_policy=lb_policy,
  )
  LOGGER.info(
    "admin.create_route domain=%s upstreams=%d lb_policy=%s",
    domain, len(upstreams_field), lb_policy,
  )
  return _route_to_dict(route)


def get_route_detail(ctx: AdminContext, domain: str) -> dict[str, Any]:
  domain = _normalize_domain(domain)
  route = ctx.database.get_route(domain)
  if route is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"route not found: {domain}", code="route_not_found")
  certificates = ctx.database.fetch_certificates()
  cert = certificates.get(domain)
  return {
    "route": _route_to_dict(route),
    "certificate": _certificate_to_dict(cert) if cert else None,
  }


def update_route(ctx: AdminContext, domain: str, payload: dict[str, Any]) -> dict[str, Any]:
  _require_readwrite(ctx)
  domain = _normalize_domain(domain)
  existing = ctx.database.get_route(domain)
  if existing is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"route not found: {domain}", code="route_not_found")
  changed = False

  # "upstreams" takes priority: when present, it authoritatively
  # replaces the full upstream list. Otherwise fall back to legacy
  # single-target update via "upstream_target".
  upstreams_field = _normalize_upstreams_list(payload.get("upstreams"))
  if upstreams_field is not None:
    existing_pairs = [(up.target, up.weight) for up in (existing.upstreams or [])]
    new_pairs = [(up.target, up.weight) for up in upstreams_field]
    if existing_pairs != new_pairs:
      ctx.database.replace_route_upstreams(domain, upstreams_field)
      changed = True
  elif "upstream_target" in payload:
    upstream = _normalize_upstream_target(payload.get("upstream_target"))
    if upstream != existing.upstream_target:
      ctx.database.update_route_target(domain, upstream)
      changed = True

  # Decide effective upstream count for lb_policy validation.
  effective_upstream_count = (
    len(upstreams_field) if upstreams_field is not None else len(existing.upstreams or [])
  )

  if "lb_policy" in payload:
    desired_policy = _normalize_lb_policy(payload.get("lb_policy"))
    if desired_policy != "random" and effective_upstream_count < 2:
      raise HttpError(
        HTTPStatus.BAD_REQUEST,
        "lb_policy only applies when there are two or more upstreams",
        code="lb_policy_requires_multiple_upstreams",
      )
    if desired_policy != existing.lb_policy:
      ctx.database.set_route_lb_policy(domain, desired_policy)
      changed = True

  if "enabled" in payload:
    desired = bool(payload.get("enabled"))
    if desired != existing.enabled:
      ctx.database.set_route_enabled(domain, desired)
      changed = True

  updated = ctx.database.get_route(domain)
  if updated is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"route disappeared: {domain}", code="route_not_found")
  if changed:
    LOGGER.info("admin.update_route domain=%s", domain)
  return _route_to_dict(updated)


def delete_route(ctx: AdminContext, domain: str, *, purge: bool) -> dict[str, Any]:
  _require_readwrite(ctx)
  domain = _normalize_domain(domain)
  existing = ctx.database.get_route(domain)
  if existing is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"route not found: {domain}", code="route_not_found")
  if purge:
    ctx.database.purge_route(domain)
    LOGGER.info("admin.purge_route domain=%s", domain)
    return {"domain": domain, "purged": True}
  try:
    ctx.database.delete_route(domain)
  except Exception as exc:
    raise HttpError(
      HTTPStatus.CONFLICT,
      f"cannot delete route while certificate exists; use purge=1: {exc}",
      code="route_delete_blocked",
    ) from exc
  LOGGER.info("admin.delete_route domain=%s", domain)
  return {"domain": domain, "purged": False}


def clear_retry_after(ctx: AdminContext, domain: str) -> dict[str, Any]:
  _require_readwrite(ctx)
  domain = _normalize_domain(domain)
  cleared = ctx.database.clear_certificate_retry_after(domain)
  return {"domain": domain, "cleared": cleared}


# ---------------------------------------------------------------------------
# Zones
# ---------------------------------------------------------------------------


def list_zones(ctx: AdminContext, *, reveal_token: bool = False) -> list[dict[str, Any]]:
  zones = ctx.database.list_dns_zone_tokens()
  return [_zone_to_dict(zone, reveal_token=reveal_token) for zone in zones]


def upsert_zone(ctx: AdminContext, payload: dict[str, Any]) -> dict[str, Any]:
  _require_readwrite(ctx)
  zone_name = (payload.get("zone_name") or "").strip().lower().rstrip(".")
  if not zone_name or not _DOMAIN_RE.match(zone_name):
    raise HttpError(HTTPStatus.BAD_REQUEST, "invalid zone_name", code="invalid_zone_name")
  zone_id = (payload.get("zone_id") or "").strip()
  api_token = (payload.get("api_token") or "").strip()
  provider = (payload.get("provider") or "cloudflare").strip().lower()
  if provider != "cloudflare":
    raise HttpError(HTTPStatus.BAD_REQUEST, "provider must be cloudflare", code="invalid_provider")
  if not zone_id:
    raise HttpError(HTTPStatus.BAD_REQUEST, "zone_id is required", code="zone_id_required")
  if not api_token:
    raise HttpError(HTTPStatus.BAD_REQUEST, "api_token is required", code="api_token_required")
  zone = ctx.database.upsert_dns_zone_token(zone_name, zone_id, api_token, provider=provider)
  LOGGER.info("admin.upsert_zone zone=%s provider=%s", zone_name, provider)
  return _zone_to_dict(zone)


def delete_zone(ctx: AdminContext, zone_name: str) -> dict[str, Any]:
  _require_readwrite(ctx)
  zone_name = (zone_name or "").strip().lower().rstrip(".")
  if not zone_name:
    raise HttpError(HTTPStatus.BAD_REQUEST, "zone_name is required", code="zone_name_required")
  deleted = ctx.database.delete_dns_zone_token(zone_name)
  if not deleted:
    raise HttpError(HTTPStatus.NOT_FOUND, f"zone not found: {zone_name}", code="zone_not_found")
  LOGGER.info("admin.delete_zone zone=%s", zone_name)
  return {"zone_name": zone_name, "deleted": True}


# ---------------------------------------------------------------------------
# Overview & actions
# ---------------------------------------------------------------------------


def build_overview(ctx: AdminContext) -> dict[str, Any]:
  # Fan out the three reads in parallel — each uses a separate pooled
  # connection. Over a high-latency Supabase link this turns three
  # ~250 ms serial round trips into one ~250 ms parallel batch.
  from concurrent.futures import ThreadPoolExecutor
  with ThreadPoolExecutor(max_workers=3) as ex:
    routes_f = ex.submit(ctx.database.list_routes)
    certs_f = ex.submit(ctx.database.fetch_certificates)
    zones_f = ex.submit(ctx.database.list_dns_zone_tokens)
    routes = routes_f.result()
    certificates = certs_f.result()
    zones = zones_f.result()
  now = datetime.now(tz=UTC)
  active_routes = sum(1 for route in routes if route.enabled)
  disabled_routes = len(routes) - active_routes
  cert_status_counts: dict[str, int] = {}
  expiring_soon = 0
  expired = 0
  for cert in certificates.values():
    cert_status_counts[cert.status] = cert_status_counts.get(cert.status, 0) + 1
    if cert.not_after is not None:
      remaining = (cert.not_after - now).total_seconds() / 86400
      if remaining < 0:
        expired += 1
      elif remaining < ctx.config.sync.renew_before_days:
        expiring_soon += 1
  return {
    "mode": ctx.config.mode,
    "acme_email": ctx.config.acme.email,
    "acme_staging": ctx.config.acme.staging,
    "poll_interval_seconds": ctx.config.sync.poll_interval_seconds,
    "renew_before_days": ctx.config.sync.renew_before_days,
    "retry_backoff_seconds": ctx.config.sync.retry_backoff_seconds,
    "counts": {
      "routes_total": len(routes),
      "routes_enabled": active_routes,
      "routes_disabled": disabled_routes,
      "certificates_total": len(certificates),
      "certificates_expiring_soon": expiring_soon,
      "certificates_expired": expired,
      "certificate_status": cert_status_counts,
      "zones_total": len(zones),
    },
    "paths": {
      "state_dir": str(ctx.config.paths.state_dir),
      "log_dir": str(ctx.config.paths.log_dir),
      "controller_log_path": ctx.config.logging.controller_log_path,
      "caddy_log_path": ctx.config.logging.caddy_log_path,
    },
    "server_time": _to_jsonable(now),
  }


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


_NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def _normalize_node_name(value: Any) -> str:
  text = (value or "").strip() if isinstance(value, str) else ""
  if not text:
    raise HttpError(HTTPStatus.BAD_REQUEST, "node name is required", code="node_name_required")
  if not _NODE_NAME_RE.match(text):
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "node name must match [A-Za-z0-9._-]{1,63}",
      code="invalid_node_name",
    )
  return text


def _node_to_dict(node: NodeRecord, *, reveal_secrets: bool = True) -> dict[str, Any]:
  """Serialize a node. Per the per-user product decision, secrets ARE returned
  in plaintext over the admin API. The `reveal_secrets` flag stays as an
  override so future callers (logs, analytics) can opt out.
  """
  out: dict[str, Any] = {
    "name": node.name,
    "host": node.host,
    "ssh_port": node.ssh_port,
    "ssh_user": node.ssh_user,
    "auth_method": node.auth_method,
    "description": node.description,
    "tags": list(node.tags or []),
    "deploy_command": node.deploy_command,
    "update_command": node.update_command,
    "created_at": _to_jsonable(node.created_at),
    "updated_at": _to_jsonable(node.updated_at),
    "has_ssh_password": bool(node.ssh_password),
    "has_ssh_private_key": bool(node.ssh_private_key),
    "has_ssh_key_passphrase": bool(node.ssh_key_passphrase),
    # Initialization defaults
    "init_git_user_name": node.init_git_user_name,
    "init_git_user_email": node.init_git_user_email,
    "init_desired_ssh_port": node.init_desired_ssh_port,
    "init_install_codex": bool(node.init_install_codex),
    "init_codex_base_url": node.init_codex_base_url,
    "init_timezone": node.init_timezone,
    "has_init_git_private_key": bool(node.init_git_private_key),
    "has_init_codex_api_key": bool(node.init_codex_api_key),
  }
  if reveal_secrets:
    out["ssh_password"] = node.ssh_password
    out["ssh_private_key"] = node.ssh_private_key
    out["ssh_key_passphrase"] = node.ssh_key_passphrase
    out["init_git_private_key"] = node.init_git_private_key
    out["init_codex_api_key"] = node.init_codex_api_key
  return out


def _node_status_to_dict(
  status: NodeStatusRecord | None, *, include_raw: bool = False,
) -> dict[str, Any] | None:
  if status is None:
    return None
  out: dict[str, Any] = {
    "node_name": status.node_name,
    "reachable": status.reachable,
    "service_installed": status.service_installed,
    "service_running": status.service_running,
    "service_mode": status.service_mode,
    "service_version": status.service_version,
    "uptime_seconds": status.uptime_seconds,
    "load_avg": status.load_avg,
    "memory": status.memory,
    "disk_usage": status.disk_usage,
    "os_release": status.os_release,
    "last_probed_at": _to_jsonable(status.last_probed_at),
    "last_probe_error": status.last_probe_error,
  }
  # raw_probe is heavy (full sectioned shell output); only ship it on the
  # single-node detail endpoint, not the list.
  if include_raw:
    out["raw_probe"] = status.raw_probe
  return out


def _normalize_auth_method(value: Any) -> str:
  text = (value or "").strip().lower() if isinstance(value, str) else ""
  if text not in NODE_AUTH_METHODS:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      f"auth_method must be one of: {', '.join(NODE_AUTH_METHODS)}",
      code="invalid_auth_method",
    )
  return text


def _normalize_port(value: Any, default: int = 22) -> int:
  if value is None or value == "":
    return default
  try:
    port = int(value)
  except (TypeError, ValueError) as exc:
    raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_port must be an integer", code="invalid_port") from exc
  if port < 1 or port > 65535:
    raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_port must be 1..65535", code="invalid_port")
  return port


def _normalize_tags(value: Any) -> list[str]:
  if value is None:
    return []
  if isinstance(value, str):
    return [t.strip() for t in value.split(",") if t.strip()]
  if isinstance(value, list):
    out: list[str] = []
    for item in value:
      if not isinstance(item, str):
        raise HttpError(HTTPStatus.BAD_REQUEST, "tags must be strings", code="invalid_tags")
      stripped = item.strip()
      if stripped:
        out.append(stripped)
    return out
  raise HttpError(HTTPStatus.BAD_REQUEST, "tags must be a list of strings", code="invalid_tags")


def _ssh_credentials_for_node(ctx: AdminContext, node_name: str) -> list[dict]:
  """Fetch the linked-keys list shaped for nodes._open_client.
  Returns list of dicts with private_key/passphrase/name/etc."""
  return ctx.database.list_node_ssh_key_links(node_name)


def _linked_keys_for_node(ctx: AdminContext, node_name: str) -> list[dict[str, Any]]:
  """Serialize the keys linked to ``node_name`` for the API response.
  Excludes private_key/passphrase to keep the payload small — the
  caller can fetch the full record via /api/ssh-keys/{id} if needed."""
  return _serialize_linked_keys(ctx.database.list_node_ssh_key_links(node_name))


def _serialize_linked_keys(links: list[dict[str, Any]]) -> list[dict[str, Any]]:
  """Project the verbose junction-row dicts down to the API shape."""
  out: list[dict[str, Any]] = []
  for link in links:
    out.append({
      "id": link["ssh_key_id"],
      "name": link["name"],
      "key_type": link["key_type"],
      "bits": link["bits"],
      "fingerprint_sha256": link["fingerprint_sha256"],
      "priority": link["priority"],
    })
  return out


def list_nodes(ctx: AdminContext, *, with_status: bool = False) -> list[dict[str, Any]]:
  """List all nodes plus linked SSH keys.

  By default this skips the (potentially-slow) node_status query so the
  list endpoint can render fast. The frontend fetches statuses
  separately via /api/node-statuses; pass ``with_status=True`` only
  when a single combined response is required."""
  import time as _time
  from concurrent.futures import ThreadPoolExecutor
  t0 = _time.perf_counter()
  with ThreadPoolExecutor(max_workers=3) as ex:
    fut_records = ex.submit(ctx.database.list_nodes)
    fut_links = ex.submit(ctx.database.list_all_node_ssh_key_links)
    fut_statuses = ex.submit(ctx.database.list_node_statuses) if with_status else None
    records = fut_records.result()
    links_by_node = fut_links.result()
    statuses = fut_statuses.result() if fut_statuses is not None else {}
  t1 = _time.perf_counter()
  LOGGER.info(
    "list_nodes parallel queries: total=%.0fms n=%d with_status=%s",
    (t1 - t0) * 1000, len(records), with_status,
  )
  out: list[dict[str, Any]] = []
  for node in records:
    item = _node_to_dict(node)
    if with_status:
      item["status"] = _node_status_to_dict(statuses.get(node.name))
    item["linked_keys"] = _serialize_linked_keys(links_by_node.get(node.name, []))
    item["ssh_key_ids"] = [k["id"] for k in item["linked_keys"]]
    out.append(item)
  return out


def get_node_detail(ctx: AdminContext, name: str) -> dict[str, Any]:
  name = _normalize_node_name(name)
  node = ctx.database.get_node(name)
  if node is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  item = _node_to_dict(node)
  item["status"] = _node_status_to_dict(
    ctx.database.get_node_status(name), include_raw=True,
  )
  item["linked_keys"] = _linked_keys_for_node(ctx, node.name)
  item["ssh_key_ids"] = [k["id"] for k in item["linked_keys"]]
  return item


def _normalize_ssh_key_ids(value: Any) -> list[int] | None:
  """Normalize an ``ssh_key_ids`` payload entry. ``None`` means
  "don't change"; ``[]`` means "clear all links"."""
  if value is None:
    return None
  if not isinstance(value, list):
    raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_key_ids must be a list",
                    code="invalid_ssh_key_ids")
  out: list[int] = []
  seen: set[int] = set()
  for v in value:
    try:
      n = int(v)
    except (TypeError, ValueError) as exc:
      raise HttpError(HTTPStatus.BAD_REQUEST,
                      "ssh_key_ids entries must be integers",
                      code="invalid_ssh_key_ids") from exc
    if n in seen:
      continue
    seen.add(n)
    out.append(n)
  return out


def create_node(ctx: AdminContext, payload: dict[str, Any]) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_node_name(payload.get("name"))
  host = (payload.get("host") or "").strip()
  if not host:
    raise HttpError(HTTPStatus.BAD_REQUEST, "host is required", code="host_required")
  ssh_user = (payload.get("ssh_user") or "root").strip() or "root"
  port = _normalize_port(payload.get("ssh_port"), default=22)
  auth_method = _normalize_auth_method(payload.get("auth_method"))
  password = (payload.get("ssh_password") or None) or None
  private_key = (payload.get("ssh_private_key") or None) or None
  passphrase = (payload.get("ssh_key_passphrase") or None) or None
  ssh_key_ids = _normalize_ssh_key_ids(payload.get("ssh_key_ids"))
  has_any_key = bool(private_key) or bool(ssh_key_ids)
  if auth_method == "password" and not password:
    raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_password is required for password auth", code="password_required")
  if auth_method == "key" and not has_any_key:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "key auth requires at least one linked SSH key (or an inline ssh_private_key)",
      code="private_key_required",
    )
  if auth_method == "auto" and not (password or has_any_key):
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "auto auth requires at least one credential (password, linked key, or inline key)",
      code="credentials_required",
    )

  existing = ctx.database.get_node(name)
  if existing is not None:
    raise HttpError(HTTPStatus.CONFLICT, f"node already exists: {name}", code="node_exists")

  record = NodeRecord(
    name=name,
    host=host,
    ssh_port=port,
    ssh_user=ssh_user,
    auth_method=auth_method,
    ssh_password=password,
    ssh_private_key=private_key,
    ssh_key_passphrase=passphrase,
    description=(payload.get("description") or None) or None,
    tags=_normalize_tags(payload.get("tags")),
    deploy_command=(payload.get("deploy_command") or None) or None,
    update_command=(payload.get("update_command") or None) or None,
    created_at=datetime.now(tz=UTC),
    updated_at=datetime.now(tz=UTC),
    init_git_private_key=(payload.get("init_git_private_key") or None) or None,
    init_git_user_name=(payload.get("init_git_user_name") or None) or None,
    init_git_user_email=(payload.get("init_git_user_email") or None) or None,
    init_desired_ssh_port=_normalize_port(payload.get("init_desired_ssh_port"), default=60101),
    init_install_codex=bool(payload.get("init_install_codex", True)),
    init_codex_base_url=(payload.get("init_codex_base_url") or None) or None,
    init_codex_api_key=(payload.get("init_codex_api_key") or None) or None,
    init_timezone=(payload.get("init_timezone") or "Asia/Shanghai"),
  )
  inserted = ctx.database.insert_node(record)
  if ssh_key_ids is not None:
    ctx.database.set_node_ssh_keys(inserted.name, ssh_key_ids)
  LOGGER.info("admin.create_node name=%s host=%s auth=%s linked_keys=%s",
              name, host, auth_method,
              len(ssh_key_ids) if ssh_key_ids else 0)
  out = _node_to_dict(inserted)
  out["linked_keys"] = _linked_keys_for_node(ctx, inserted.name)
  out["ssh_key_ids"] = [k["id"] for k in out["linked_keys"]]
  return out


def update_node(ctx: AdminContext, name: str, payload: dict[str, Any]) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_node_name(name)
  existing = ctx.database.get_node(name)
  if existing is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  patch: dict[str, Any] = {}
  # Rename support — `new_name` (or just `name` to align with create payload)
  # routes through the dedicated rename method which atomically updates both
  # the parent row and any FK-referencing children.
  rename_to = payload.get("new_name")
  if not rename_to and "name" in payload and isinstance(payload["name"], str):
    candidate = payload["name"].strip()
    if candidate and candidate != name:
      rename_to = candidate
  if rename_to:
    new_name = _normalize_node_name(rename_to)
    if new_name != name:
      if ctx.database.get_node(new_name) is not None:
        raise HttpError(HTTPStatus.CONFLICT, f"node already exists: {new_name}", code="node_exists")
      renamed = ctx.database.rename_node(name, new_name)
      if renamed is None:
        raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
      LOGGER.info("admin.rename_node from=%s to=%s", name, new_name)
      name = new_name
      existing = ctx.database.get_node(name)
      if existing is None:
        raise HttpError(HTTPStatus.NOT_FOUND, "node disappeared post-rename", code="node_not_found")
  if "host" in payload:
    host = (payload["host"] or "").strip()
    if not host:
      raise HttpError(HTTPStatus.BAD_REQUEST, "host must not be empty", code="host_required")
    patch["host"] = host
  if "ssh_port" in payload:
    patch["ssh_port"] = _normalize_port(payload["ssh_port"], default=existing.ssh_port)
  if "ssh_user" in payload:
    user = (payload["ssh_user"] or "").strip()
    if not user:
      raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_user must not be empty", code="ssh_user_required")
    patch["ssh_user"] = user
  if "auth_method" in payload:
    patch["auth_method"] = _normalize_auth_method(payload["auth_method"])
  # Optional secret fields — only patch if explicitly present and non-empty.
  # An explicit `null` clears them.
  for secret_key in ("ssh_password", "ssh_private_key", "ssh_key_passphrase"):
    if secret_key in payload:
      val = payload[secret_key]
      if val == "" or val is None:
        patch[secret_key] = None
      else:
        patch[secret_key] = val
  if "description" in payload:
    patch["description"] = payload["description"] or None
  if "tags" in payload:
    patch["tags"] = _normalize_tags(payload["tags"])
  if "deploy_command" in payload:
    patch["deploy_command"] = payload["deploy_command"] or None
  if "update_command" in payload:
    patch["update_command"] = payload["update_command"] or None
  # Init defaults — accept whatever the wizard's "save" step sends.
  for k in (
    "init_git_private_key", "init_git_user_name", "init_git_user_email",
    "init_codex_base_url", "init_codex_api_key", "init_timezone",
  ):
    if k in payload:
      v = payload[k]
      patch[k] = v if v not in ("", None) else None
  if "init_desired_ssh_port" in payload:
    patch["init_desired_ssh_port"] = _normalize_port(payload["init_desired_ssh_port"], default=60101)
  if "init_install_codex" in payload:
    patch["init_install_codex"] = bool(payload["init_install_codex"])

  effective_auth = patch.get("auth_method", existing.auth_method)
  effective_pwd = patch.get("ssh_password", existing.ssh_password)
  effective_key = patch.get("ssh_private_key", existing.ssh_private_key)
  # The user can satisfy "key auth" via either an inline ssh_private_key
  # OR via the linked-keys junction table. If the request explicitly
  # includes ``ssh_key_ids``, use that as the authoritative count;
  # otherwise look at what's already linked.
  requested_key_ids = _normalize_ssh_key_ids(payload.get("ssh_key_ids"))
  if requested_key_ids is not None:
    effective_linked_count = len(requested_key_ids)
  else:
    effective_linked_count = len(ctx.database.list_node_ssh_key_links(name))
  effective_has_any_key = bool(effective_key) or effective_linked_count > 0
  if effective_auth == "password" and not effective_pwd:
    raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_password is required for password auth", code="password_required")
  if effective_auth == "key" and not effective_has_any_key:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "key auth requires at least one linked SSH key (or an inline ssh_private_key)",
      code="private_key_required",
    )
  if effective_auth == "auto" and not (effective_pwd or effective_has_any_key):
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "auto auth requires at least one credential (password, linked key, or inline key)",
      code="credentials_required",
    )

  updated = ctx.database.update_node(name, patch)
  if updated is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  # Apply ssh_key_ids replacement (None = leave as-is, [] = clear).
  if "ssh_key_ids" in payload:
    new_ids = _normalize_ssh_key_ids(payload.get("ssh_key_ids"))
    if new_ids is not None:
      ctx.database.set_node_ssh_keys(updated.name, new_ids)
  LOGGER.info("admin.update_node name=%s fields=%s", name, sorted(patch.keys()))
  out = _node_to_dict(updated)
  out["linked_keys"] = _linked_keys_for_node(ctx, updated.name)
  out["ssh_key_ids"] = [k["id"] for k in out["linked_keys"]]
  return out


def delete_node(ctx: AdminContext, name: str) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_node_name(name)
  deleted = ctx.database.delete_node(name)
  if not deleted:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  LOGGER.info("admin.delete_node name=%s", name)
  return {"name": name, "deleted": True}


def probe_node_action(ctx: AdminContext, name: str) -> dict[str, Any]:
  name = _normalize_node_name(name)
  node = ctx.database.get_node(name)
  if node is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  status = nodes_mod.probe_node(node, linked_keys=_ssh_credentials_for_node(ctx, node.name))
  ctx.database.upsert_node_status(status)
  reconcile_node_services(ctx, node.name, status)
  LOGGER.info("admin.probe_node name=%s reachable=%s err=%s", name, status.reachable, status.last_probe_error or "")
  return _node_status_to_dict(status) or {}


def reconcile_node_services(
  ctx: AdminContext, node_name: str, status: NodeStatusRecord,
  *, services: list | None = None,
) -> None:
  """Match every container we just observed on ``node_name`` against the
  registered services list and update the (service, node) liveness row.

  Rules (intentionally conservative — see review R6.1):

  - container present  → upsert with the observed state/image/health.
    A new row is materialized on first sight.
  - container missing AND a row already exists for this (svc, node)
    pair → update it to ``absent``.
  - container missing AND no prior row → do nothing. We don't generate
    rows out of thin air, otherwise every newly-registered service
    would instantly show up as "absent" on every probed node.

  Untracked containers (no matching registered service) are *not*
  persisted — the Node detail view surfaces them from raw_probe.

  ``services`` lets callers (e.g. the parallel refresh path) hand in a
  pre-fetched catalog so we don't issue one ``list_services()`` per
  probed node.
  """
  if not status.reachable:
    return
  containers = []
  if status.raw_probe and isinstance(status.raw_probe, dict):
    containers = status.raw_probe.get("containers") or []
  by_name: dict[str, dict] = {c["name"]: c for c in containers if c.get("name")}
  observed_at = datetime.now(tz=UTC)
  if services is None:
    try:
      services = ctx.database.list_services()
    except Exception:
      LOGGER.exception("reconcile_node_services: list_services failed")
      return

  # Existing rows for this node tell us which absent rows are
  # legitimate to update vs. which new rows we must NOT create.
  try:
    existing_for_node = ctx.database.list_service_node_states_for_node(node_name)
  except Exception:
    LOGGER.exception("reconcile_node_services: list_for_node failed")
    return
  existing_svc_names: set[str] = {r.service_name for r in existing_for_node}

  to_upsert: list[dict] = []
  for svc in services:
    c = by_name.get(svc.name)
    if c is None:
      if svc.name not in existing_svc_names:
        continue                     # don't manufacture an absent row
      to_upsert.append({
        "service_name": svc.name, "node_name": node_name,
        "container_state": "absent", "container_image": None,
        "container_started_at": None, "healthcheck_ok": None,
        "observed_at": observed_at,
      })
      continue
    state = (c.get("state") or "").lower() or None
    healthy = None
    sstr = (c.get("status_str") or "").lower()
    if "unhealthy" in sstr:
      healthy = False
    elif "healthy" in sstr:
      healthy = True
    to_upsert.append({
      "service_name": svc.name, "node_name": node_name,
      "container_state": state, "container_image": c.get("image"),
      "container_started_at": None, "healthcheck_ok": healthy,
      "observed_at": observed_at,
    })

  if not to_upsert:
    return
  try:
    n = ctx.database.bulk_upsert_service_node_liveness(to_upsert)
    LOGGER.info(
      "reconcile node=%s observed=%d rows=%d (running=%d absent=%d)",
      node_name, len(containers), n,
      sum(1 for r in to_upsert if r["container_state"] == "running"),
      sum(1 for r in to_upsert if r["container_state"] == "absent"),
    )
  except Exception:
    LOGGER.exception("reconcile_node_services: bulk upsert failed node=%s rows=%d",
                     node_name, len(to_upsert))


def deploy_node_service(ctx: AdminContext, node_name: str, payload: dict[str, Any]) -> dict[str, Any]:
  """Deploy a registered service to a node via docker compose.

  Payload:
    service: name of the service in the catalog (required)
    branch: override default_branch (optional)
    env_overrides: dict of {KEY: value} merged into service.default_env
    rebuild: whether to pass --build (default true)
  """
  _require_readwrite(ctx)
  node_name = _normalize_node_name(node_name)
  node = ctx.database.get_node(node_name)
  if node is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {node_name}", code="node_not_found")
  service_name = (payload or {}).get("service")
  if not service_name:
    raise HttpError(HTTPStatus.BAD_REQUEST, "service is required", code="service_required")
  service_name = _normalize_service_name(service_name)
  service = ctx.database.get_service(service_name)
  if service is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"service not found: {service_name}", code="service_not_found")

  branch = (payload.get("branch") or service.default_branch).strip() or "main"
  env_overrides = _normalize_env_dict(payload.get("env_overrides"))
  effective_env = dict(service.default_env or {})
  effective_env.update(env_overrides)
  rebuild = bool(payload.get("rebuild", True))

  command = nodes_mod.build_compose_deploy_command(
    service_name=service.name,
    github_repo_url=service.github_repo_url,
    branch=branch,
    install_dir=service.install_dir_template or "/opt/{name}",
    compose_file=service.compose_file or "docker-compose.yml",
    env=effective_env,
    pre_deploy_command=service.pre_deploy_command,
    post_deploy_command=service.post_deploy_command,
    compose_template=service.compose_template,
    config_files=service.config_files,
    rebuild=rebuild,
  )
  if payload.get("dry_run"):
    return {"node": node.name, "service": service.name, "command": command, "dry_run": True}

  try:
    result = nodes_mod.run_command(node, command, timeout=900.0,
                                    linked_keys=_ssh_credentials_for_node(ctx, node.name))
  except Exception as exc:
    raise HttpError(HTTPStatus.BAD_GATEWAY, f"deploy failed: {exc}", code="deploy_failed") from exc
  LOGGER.info("admin.deploy_service node=%s service=%s exit=%s", node.name, service.name, result.exit_code)
  return {
    "node": node.name,
    "service": service.name,
    "branch": branch,
    "command": command,
    "exit_code": result.exit_code,
    "stdout": result.stdout,
    "stderr": result.stderr,
    "duration_seconds": result.duration_seconds,
  }


def deploy_node_action(ctx: AdminContext, name: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_node_name(name)
  node = ctx.database.get_node(name)
  if node is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  override = None
  if payload and isinstance(payload.get("command"), str) and payload["command"].strip():
    override = payload["command"]
  try:
    result = nodes_mod.deploy_service(node, override_command=override,
                                       linked_keys=_ssh_credentials_for_node(ctx, node.name))
  except Exception as exc:
    raise HttpError(HTTPStatus.BAD_GATEWAY, f"deploy failed: {exc}", code="deploy_failed") from exc
  LOGGER.info("admin.deploy_node name=%s exit=%s", name, result.exit_code)
  return {
    "name": name,
    "command": result.command,
    "exit_code": result.exit_code,
    "stdout": result.stdout,
    "stderr": result.stderr,
    "duration_seconds": result.duration_seconds,
  }


def update_node_action(ctx: AdminContext, name: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_node_name(name)
  node = ctx.database.get_node(name)
  if node is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  override = None
  if payload and isinstance(payload.get("command"), str) and payload["command"].strip():
    override = payload["command"]
  try:
    result = nodes_mod.update_service(node, override_command=override,
                                       linked_keys=_ssh_credentials_for_node(ctx, node.name))
  except Exception as exc:
    raise HttpError(HTTPStatus.BAD_GATEWAY, f"update failed: {exc}", code="update_failed") from exc
  LOGGER.info("admin.update_node_action name=%s exit=%s", name, result.exit_code)
  return {
    "name": name,
    "command": result.command,
    "exit_code": result.exit_code,
    "stdout": result.stdout,
    "stderr": result.stderr,
    "duration_seconds": result.duration_seconds,
  }


def run_node_command_action(ctx: AdminContext, name: str, payload: dict[str, Any]) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_node_name(name)
  node = ctx.database.get_node(name)
  if node is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  command = (payload.get("command") or "").strip() if isinstance(payload, dict) else ""
  if not command:
    raise HttpError(HTTPStatus.BAD_REQUEST, "command is required", code="command_required")
  try:
    result = nodes_mod.run_command(node, command, timeout=float(payload.get("timeout") or 60),
                                    linked_keys=_ssh_credentials_for_node(ctx, node.name))
  except Exception as exc:
    raise HttpError(HTTPStatus.BAD_GATEWAY, f"command failed: {exc}", code="command_failed") from exc
  return {
    "name": name,
    "command": result.command,
    "exit_code": result.exit_code,
    "stdout": result.stdout,
    "stderr": result.stderr,
    "duration_seconds": result.duration_seconds,
  }


# ---------------------------------------------------------------------------
# Service catalog
# ---------------------------------------------------------------------------


_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def _normalize_service_name(value: Any) -> str:
  text = (value or "").strip() if isinstance(value, str) else ""
  if not text:
    raise HttpError(HTTPStatus.BAD_REQUEST, "service name is required", code="service_name_required")
  if not _SERVICE_NAME_RE.match(text):
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "service name must match [A-Za-z0-9._-]{1,63}",
      code="invalid_service_name",
    )
  return text


def _service_to_dict(service: ServiceRecord) -> dict[str, Any]:
  return {
    "name": service.name,
    "display_name": service.display_name,
    "description": service.description,
    "github_repo_url": service.github_repo_url,
    "default_branch": service.default_branch,
    "compose_file": service.compose_file,
    "install_dir_template": service.install_dir_template,
    "default_env": dict(service.default_env or {}),
    "pre_deploy_command": service.pre_deploy_command,
    "post_deploy_command": service.post_deploy_command,
    "compose_template": service.compose_template,
    "config_files": dict(service.config_files or {}),
    "created_at": _to_jsonable(service.created_at),
    "updated_at": _to_jsonable(service.updated_at),
    "required_env": list(service.required_env or []),
    "healthcheck": dict(service.healthcheck or {}),
    "depends_on": list(service.depends_on or []),
    "exposed_ports": list(service.exposed_ports or []),
    "deploy_yaml": service.deploy_yaml,
    "deploy_yaml_fetched_at": _to_jsonable(service.deploy_yaml_fetched_at),
    "has_manifest": bool(service.deploy_yaml),
  }


def _service_deployment_to_dict(rec: ServiceDeploymentRecord) -> dict[str, Any]:
  return {
    "id": rec.id,
    "service_name": rec.service_name,
    "node_name": rec.node_name,
    "revision": rec.revision,
    "status": rec.status,
    "healthcheck_passed": rec.healthcheck_passed,
    "healthcheck_detail": rec.healthcheck_detail,
    "env_snapshot": dict(rec.env_snapshot or {}),
    "log_text": rec.log_text or "",
    "exit_code": rec.exit_code,
    "started_at": _to_jsonable(rec.started_at),
    "finished_at": _to_jsonable(rec.finished_at),
    "triggered_by": rec.triggered_by,
  }


def _normalize_config_files(value: Any) -> dict[str, str]:
  if value is None or value == "":
    return {}
  if not isinstance(value, dict):
    raise HttpError(HTTPStatus.BAD_REQUEST, "config_files must be an object", code="invalid_config_files")
  out: dict[str, str] = {}
  for k, v in value.items():
    if not isinstance(k, str) or not k:
      raise HttpError(HTTPStatus.BAD_REQUEST, "config_files keys must be non-empty strings", code="invalid_config_files")
    # Reject path traversal (relative paths only)
    if k.startswith("/") or ".." in k.split("/"):
      raise HttpError(HTTPStatus.BAD_REQUEST, f"config_files path must be relative: {k}", code="invalid_config_files")
    out[k] = "" if v is None else str(v)
  return out


def _normalize_env_dict(value: Any) -> dict[str, str]:
  if value is None or value == "":
    return {}
  if not isinstance(value, dict):
    raise HttpError(HTTPStatus.BAD_REQUEST, "default_env must be an object", code="invalid_env")
  out: dict[str, str] = {}
  for k, v in value.items():
    if not isinstance(k, str):
      raise HttpError(HTTPStatus.BAD_REQUEST, "env keys must be strings", code="invalid_env")
    out[k.strip()] = "" if v is None else str(v)
  return out


def list_services(ctx: AdminContext) -> list[dict[str, Any]]:
  return [_service_to_dict(s) for s in ctx.database.list_services()]


def get_service_detail(ctx: AdminContext, name: str) -> dict[str, Any]:
  name = _normalize_service_name(name)
  s = ctx.database.get_service(name)
  if s is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"service not found: {name}", code="service_not_found")
  return _service_to_dict(s)


def create_service(ctx: AdminContext, payload: dict[str, Any]) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_service_name(payload.get("name"))
  if ctx.database.get_service(name) is not None:
    raise HttpError(HTTPStatus.CONFLICT, f"service already exists: {name}", code="service_exists")
  github = (payload.get("github_repo_url") or "").strip()
  if not github:
    raise HttpError(HTTPStatus.BAD_REQUEST, "github_repo_url is required", code="github_repo_required")
  record = ServiceRecord(
    name=name,
    display_name=(payload.get("display_name") or name).strip(),
    description=(payload.get("description") or None) or None,
    github_repo_url=github,
    default_branch=(payload.get("default_branch") or "main").strip() or "main",
    compose_file=(payload.get("compose_file") or "docker-compose.yml").strip() or "docker-compose.yml",
    install_dir_template=(payload.get("install_dir_template") or "/opt/{name}").strip() or "/opt/{name}",
    default_env=_normalize_env_dict(payload.get("default_env")),
    pre_deploy_command=(payload.get("pre_deploy_command") or None) or None,
    post_deploy_command=(payload.get("post_deploy_command") or None) or None,
    compose_template=(payload.get("compose_template") or None) or None,
    config_files=_normalize_config_files(payload.get("config_files")),
    created_at=datetime.now(tz=UTC),
    updated_at=datetime.now(tz=UTC),
  )
  inserted = ctx.database.insert_service(record)
  LOGGER.info("admin.create_service name=%s repo=%s", name, github)
  return _service_to_dict(inserted)


def update_service(ctx: AdminContext, name: str, payload: dict[str, Any]) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_service_name(name)
  patch: dict[str, Any] = {}
  for k in ("display_name", "description", "github_repo_url", "default_branch",
            "compose_file", "install_dir_template",
            "pre_deploy_command", "post_deploy_command",
            "compose_template"):
    if k in payload:
      v = payload[k]
      patch[k] = (v.strip() if isinstance(v, str) else v) or None
  if "default_env" in payload:
    patch["default_env"] = _normalize_env_dict(payload["default_env"])
  if "config_files" in payload:
    patch["config_files"] = _normalize_config_files(payload["config_files"])
  updated = ctx.database.update_service(name, patch)
  if updated is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"service not found: {name}", code="service_not_found")
  return _service_to_dict(updated)


def delete_service(ctx: AdminContext, name: str) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_service_name(name)
  if not ctx.database.delete_service(name):
    raise HttpError(HTTPStatus.NOT_FOUND, f"service not found: {name}", code="service_not_found")
  return {"name": name, "deleted": True}


# ---------------------------------------------------------------------------
# Manifest-driven service deployment
# ---------------------------------------------------------------------------

from . import services_deploy as services_deploy_mod  # noqa: E402


def fetch_service_manifest(
  ctx: AdminContext, name: str, *, save: bool = True
) -> dict[str, Any]:
  """Pull `.deploy.yaml` from the service's git repo, parse, persist."""
  name = _normalize_service_name(name)
  s = ctx.database.get_service(name)
  if s is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"service not found: {name}", code="service_not_found")
  try:
    text, branch_used = services_deploy_mod.fetch_deploy_yaml_from_github(
      s.github_repo_url, s.default_branch or "main",
    )
  except ValueError as exc:
    raise HttpError(HTTPStatus.BAD_REQUEST, str(exc), code="manifest_fetch_failed") from exc
  try:
    manifest = services_deploy_mod.parse_deploy_yaml(text)
  except ValueError as exc:
    raise HttpError(HTTPStatus.BAD_REQUEST, str(exc), code="manifest_invalid") from exc

  if save:
    ctx.database.update_service(name, {
      "deploy_yaml": text,
      "deploy_yaml_fetched_at": datetime.now(tz=UTC),
      "required_env": manifest.required_env,
      "healthcheck": manifest.healthcheck,
      "depends_on": manifest.depends_on,
      "exposed_ports": manifest.exposed_ports,
      "compose_file": manifest.compose_file,
      "install_dir_template": manifest.install_dir_template,
    })
    s = ctx.database.get_service(name)

  return {
    "service": _service_to_dict(s) if s else None,
    "branch_used": branch_used,
    "manifest": {
      "service": manifest.service,
      "runtime": manifest.runtime,
      "compose_file": manifest.compose_file,
      "install_dir_template": manifest.install_dir_template,
      "required_env": manifest.required_env,
      "defaults": manifest.defaults,
      "secrets": manifest.secrets,
      "exposed_ports": manifest.exposed_ports,
      "healthcheck": manifest.healthcheck,
      "depends_on": manifest.depends_on,
      "hooks": manifest.hooks,
      "volumes": manifest.volumes,
    },
  }


def deploy_service_to_nodes(
  ctx: AdminContext, name: str, payload: dict[str, Any]
) -> dict[str, Any]:
  """Render + push the deploy script to one or more nodes; verify
  healthcheck per node; record per-attempt history."""
  _require_readwrite(ctx)
  name = _normalize_service_name(name)
  s = ctx.database.get_service(name)
  if s is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"service not found: {name}", code="service_not_found")
  if not s.deploy_yaml:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "manifest not yet fetched — call /api/services/{name}/manifest first",
      code="manifest_missing",
    )
  try:
    manifest = services_deploy_mod.parse_deploy_yaml(s.deploy_yaml)
  except ValueError as exc:
    raise HttpError(HTTPStatus.BAD_REQUEST, str(exc), code="manifest_invalid") from exc

  # Targets
  all_nodes = bool(payload.get("all"))
  if all_nodes:
    target_names = [n.name for n in ctx.database.list_nodes()]
  else:
    raw = payload.get("nodes")
    if not isinstance(raw, list) or not raw:
      raise HttpError(
        HTTPStatus.BAD_REQUEST,
        "nodes must be a non-empty list (or set all=true)",
        code="nodes_required",
      )
    target_names = [str(n).strip() for n in raw if str(n).strip()]
  node_recs: list[NodeRecord] = []
  missing: list[str] = []
  for nm in target_names:
    n = ctx.database.get_node(nm)
    if n is None:
      missing.append(nm)
    else:
      node_recs.append(n)
  if missing:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node(s) not found: {', '.join(missing)}",
                    code="node_not_found")

  # Effective env
  per_deploy_env = payload.get("env") or {}
  if not isinstance(per_deploy_env, dict):
    raise HttpError(HTTPStatus.BAD_REQUEST, "env must be an object", code="invalid_env")
  per_deploy_env_clean = {str(k): str(v) for k, v in per_deploy_env.items() if k}

  # System config secrets resolver — `system_config:KEY.PATH`.
  def _resolver(src: str) -> str | None:
    if not src.startswith("system_config:"):
      return None
    rest = src[len("system_config:"):]
    parts = rest.split(".", 1)
    key = parts[0].strip()
    cfg = ctx.database.get_system_config(key) or {}
    if len(parts) == 1:
      return None
    return str(cfg.get(parts[1].strip()) or "") or None

  env, missing_env = services_deploy_mod.build_effective_env(
    manifest,
    per_deploy_env=per_deploy_env_clean,
    service_default_env=s.default_env,
    secrets_resolver=_resolver,
  )
  if missing_env:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      f"required env missing: {', '.join(missing_env)}",
      code="missing_required_env",
    )

  revision = (payload.get("revision") or s.default_branch or "main").strip()
  triggered_by = (payload.get("triggered_by") or "admin").strip()
  env_file = services_deploy_mod.render_env_file(env)
  deploy_script = services_deploy_mod.render_deploy_script(
    manifest=manifest,
    service_repo_url=s.github_repo_url,
    service_branch=s.default_branch or "main",
    revision=revision,
    env_file_content=env_file,
  )
  hc_script = services_deploy_mod.render_healthcheck_script(manifest, env)

  from concurrent.futures import ThreadPoolExecutor

  def _deploy_one(n: NodeRecord) -> dict[str, Any]:
    dep = ctx.database.insert_service_deployment(
      service_name=s.name, node_name=n.name,
      revision=revision, env_snapshot=env, triggered_by=triggered_by,
    )
    try:
      r = nodes_mod.deploy_service_with_manifest(
        n,
        service_name=s.name,
        deploy_script=deploy_script,
        healthcheck_script=hc_script,
        linked_keys=_ssh_credentials_for_node(ctx, n.name),
      )
    except Exception as exc:  # noqa: BLE001
      LOGGER.exception("deploy_service crashed for node=%s", n.name)
      ctx.database.finalize_service_deployment(
        dep.id, status="failed", healthcheck_passed=False,
        healthcheck_detail=str(exc)[:500], log_text=str(exc),
        exit_code=None,
      )
      ctx.database.upsert_service_node_state(
        service_name=s.name, node_name=n.name, revision=revision,
        status="failed", last_deployment_id=dep.id,
      )
      return {
        "node": n.name, "host": f"{n.ssh_user}@{n.host}:{n.ssh_port}",
        "ok": False, "error": f"{type(exc).__name__}: {exc}"[:500],
      }
    final_status = "success" if r.ok else "failed"
    final = ctx.database.finalize_service_deployment(
      dep.id,
      status=final_status,
      healthcheck_passed=r.healthcheck_passed,
      healthcheck_detail=r.healthcheck_detail,
      log_text=r.log_text,
      exit_code=r.exit_code,
      revision=r.deployed_sha or revision,
    )
    ctx.database.upsert_service_node_state(
      service_name=s.name, node_name=n.name,
      revision=r.deployed_sha or revision,
      status=final_status, last_deployment_id=dep.id,
    )
    return {
      "node": n.name,
      "host": f"{n.ssh_user}@{n.host}:{n.ssh_port}",
      "ok": r.ok,
      "exit_code": r.exit_code,
      "deployed_sha": r.deployed_sha,
      "healthcheck_passed": r.healthcheck_passed,
      "healthcheck_detail": (r.healthcheck_detail or "")[:300],
      "duration_seconds": r.duration_seconds,
      "deployment_id": dep.id,
      "error": r.error,
    }

  workers = min(6, max(1, len(node_recs)))
  with ThreadPoolExecutor(max_workers=workers) as ex:
    results = list(ex.map(_deploy_one, node_recs))

  ok_count = sum(1 for r in results if r["ok"])
  return {
    "service": s.name,
    "revision_requested": revision,
    "total": len(results),
    "success": ok_count,
    "fail": len(results) - ok_count,
    "results": results,
    "at": _to_jsonable(datetime.now(tz=UTC)),
  }


def list_service_deployments(
  ctx: AdminContext, *, service_name: str | None = None,
  node_name: str | None = None, limit: int = 50,
) -> list[dict[str, Any]]:
  rows = ctx.database.list_service_deployments(
    service_name=service_name, node_name=node_name, limit=int(limit),
  )
  return [_service_deployment_to_dict(r) for r in rows]


def list_service_node_states(
  ctx: AdminContext, *, service_name: str | None = None,
) -> list[dict[str, Any]]:
  rows = ctx.database.list_service_node_states(service_name=service_name)
  return [_service_node_state_to_dict(r) for r in rows]


def _service_node_state_to_dict(r) -> dict[str, Any]:
  return {
    "service_name": r.service_name,
    "node_name": r.node_name,
    "revision": r.revision,
    "status": r.status,
    "last_deployment_id": r.last_deployment_id,
    "updated_at": _to_jsonable(r.updated_at),
    "container_state": r.container_state,
    "container_image": r.container_image,
    "container_started_at": _to_jsonable(r.container_started_at),
    "healthcheck_ok": r.healthcheck_ok,
    "last_observed_at": _to_jsonable(r.last_observed_at),
  }


def services_summary(ctx: AdminContext) -> list[dict[str, Any]]:
  """One row per registered service: counts of nodes by container_state.
  Used by the Dashboard stat card and the Services list page."""
  by_service: dict[str, dict[str, int]] = {}
  states = ctx.database.list_service_node_states()
  for r in states:
    bucket = by_service.setdefault(r.service_name, {
      "running": 0, "absent": 0, "unhealthy": 0, "other": 0, "total": 0,
    })
    bucket["total"] += 1
    state = (r.container_state or "absent").lower()
    if state == "running":
      if r.healthcheck_ok is False:
        bucket["unhealthy"] += 1
      else:
        bucket["running"] += 1
    elif state == "absent":
      bucket["absent"] += 1
    elif state in ("exited", "dead", "restarting", "created", "paused", "removing"):
      bucket["unhealthy"] += 1
    else:
      bucket["other"] += 1

  out: list[dict[str, Any]] = []
  for svc in ctx.database.list_services():
    counts = by_service.get(svc.name, {
      "running": 0, "absent": 0, "unhealthy": 0, "other": 0, "total": 0,
    })
    out.append({
      "name": svc.name,
      "github_repo_url": svc.github_repo_url,
      "has_manifest": bool(svc.deploy_yaml),
      "running": counts["running"],
      "unhealthy": counts["unhealthy"],
      "absent": counts["absent"],
      "other": counts["other"],
      "total": counts["total"],
    })
  return out


def list_service_node_status(
  ctx: AdminContext, name: str,
) -> list[dict[str, Any]]:
  """All node rows for a single service. Used by the per-service detail
  view's "Per-node status" table. 404 on unknown service so typos in
  the URL surface."""
  name = _normalize_service_name(name)
  if ctx.database.get_service(name) is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"service not found: {name}", code="service_not_found")
  return list_service_node_states(ctx, service_name=name)


def refresh_service_nodes(
  ctx: AdminContext, name: str,
) -> dict[str, Any]:
  """Probe every node that already has a service_node_state row for this
  service (in parallel) and reconcile. Used by the per-service detail
  page's "Refresh" button.

  - 404 if the service is not registered (so typos surface).
  - Empty payload if no node has a state row yet (instead of a silent
    "0 refreshed").
  - Pre-fetches the services catalog once and hands it to each
    reconcile call so we don't fan out N catalog queries.
  """
  name = _normalize_service_name(name)
  if ctx.database.get_service(name) is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"service not found: {name}", code="service_not_found")
  states = ctx.database.list_service_node_states(service_name=name)
  node_names = sorted({s.node_name for s in states})
  if not node_names:
    return {
      "service": name, "refreshed": 0, "total": 0,
      "errors": [],
      "message": "No nodes have a state row yet — deploy this service first.",
      "at": _to_jsonable(datetime.now(tz=UTC)),
    }
  services = ctx.database.list_services()
  results: list[dict[str, Any]] = []

  def _one(node_name: str) -> dict[str, Any]:
    n = ctx.database.get_node(node_name)
    if n is None:
      return {"node": node_name, "ok": False, "error": "node not found"}
    try:
      st = nodes_mod.probe_node(n, linked_keys=_ssh_credentials_for_node(ctx, n.name))
      ctx.database.upsert_node_status(st)
      reconcile_node_services(ctx, n.name, st, services=services)
      return {"node": node_name, "ok": True, "reachable": st.reachable}
    except Exception as exc:  # noqa: BLE001
      LOGGER.exception("refresh_service_nodes: probe failed for %s", node_name)
      return {"node": node_name, "ok": False, "error": str(exc)}

  # Cap at 6 workers (pool size 10 minus headroom for the foreground
  # request handler + a possible /api/nodes call from another tab —
  # see review pass-2 R2.1 on connection-pool exhaustion).
  workers = min(6, max(1, len(node_names)))
  from concurrent.futures import ThreadPoolExecutor as _TPE
  with _TPE(max_workers=workers) as ex:
    results = list(ex.map(_one, node_names))
  ok = sum(1 for r in results if r["ok"])
  return {
    "service": name,
    "refreshed": ok,
    "total": len(results),
    "errors": [r for r in results if not r["ok"]],
    "at": _to_jsonable(datetime.now(tz=UTC)),
  }


# ---------------------------------------------------------------------------
# Init runs (orchestrated full-server bootstrap)
# ---------------------------------------------------------------------------


def _init_run_to_dict(run: NodeInitRunRecord) -> dict[str, Any]:
  return {
    "id": run.id,
    "node_name": run.node_name,
    "status": run.status,
    "current_step": run.current_step,
    "log_text": run.log_text,
    "exit_code": run.exit_code,
    "started_at": _to_jsonable(run.started_at),
    "finished_at": _to_jsonable(run.finished_at),
    "config_snapshot": run.config_snapshot,
  }


def start_init_run(ctx: AdminContext, name: str, payload: dict[str, Any] | None) -> dict[str, Any]:
  _require_readwrite(ctx)
  name = _normalize_node_name(name)
  node = ctx.database.get_node(name)
  if node is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")

  payload = payload or {}
  # If any field is in payload, persist to nodes row first so reuse is sticky.
  patch_fields = {}
  for k in (
    "init_git_private_key", "init_git_user_name", "init_git_user_email",
    "init_codex_base_url", "init_codex_api_key", "init_timezone",
    "init_install_codex", "init_desired_ssh_port",
  ):
    if k in payload:
      patch_fields[k] = payload[k]
  if patch_fields:
    update_node(ctx, name, patch_fields)
    node = ctx.database.get_node(name)
    if node is None:
      raise HttpError(HTTPStatus.NOT_FOUND, "node disappeared mid-update", code="node_not_found")

  cfg = nodes_init_mod.InitConfig(
    git_private_key=node.init_git_private_key,
    git_user_name=node.init_git_user_name,
    git_user_email=node.init_git_user_email,
    desired_ssh_port=int(node.init_desired_ssh_port or 60101),
    install_codex=bool(node.init_install_codex),
    codex_base_url=node.init_codex_base_url,
    codex_api_key=node.init_codex_api_key,
    timezone=node.init_timezone or "Asia/Shanghai",
  )
  run = nodes_init_mod.schedule_init_run(ctx.database, node, cfg)
  return _init_run_to_dict(run)


def get_init_run(ctx: AdminContext, name: str, run_id: int) -> dict[str, Any]:
  name = _normalize_node_name(name)
  run = ctx.database.get_init_run(int(run_id))
  if run is None or run.node_name != name:
    raise HttpError(HTTPStatus.NOT_FOUND, f"init run not found: {run_id}", code="init_run_not_found")
  return _init_run_to_dict(run)


def init_status_bulk(ctx: AdminContext, names: list[str]) -> dict[str, dict[str, Any]]:
  """For each node in ``names``, return the latest init run summary so
  the bulk-deploy frontend can decide which nodes need init first.

  A node is considered "initialized" iff its latest init run is
  ``status == 'success'`` (the value nodes_init writes). ``never`` means
  no init run on record (i.e. the node has never been bootstrapped
  through this admin).
  """
  cleaned = [_normalize_node_name(n) for n in names if n]
  latest = ctx.database.latest_init_run_per_node(cleaned)
  _SUCCESS_STATUSES = {"success", "completed"}
  out: dict[str, dict[str, Any]] = {}
  for name in cleaned:
    run = latest.get(name)
    if run is None:
      out[name] = {
        "initialized": False,
        "last_run_status": "never",
        "last_run_id": None,
        "last_run_step": None,
        "last_run_finished_at": None,
      }
    else:
      out[name] = {
        "initialized": run.status in _SUCCESS_STATUSES,
        "last_run_status": run.status,
        "last_run_id": run.id,
        "last_run_step": run.current_step,
        "last_run_finished_at": _to_jsonable(run.finished_at),
      }
  return out


def list_init_runs(ctx: AdminContext, name: str) -> list[dict[str, Any]]:
  name = _normalize_node_name(name)
  runs = ctx.database.list_init_runs(name, limit=20)
  # Trim log_text in list view to avoid sending megabytes of logs every poll.
  out = []
  for run in runs:
    item = _init_run_to_dict(run)
    item["log_text"] = (run.log_text[-2000:] if run.log_text else "")
    out.append(item)
  return out


# ---------------------------------------------------------------------------
# Host SSH keys (local Mac the admin runs on)
# ---------------------------------------------------------------------------

def _ssh_dir() -> Path:
  return Path(os.path.expanduser("~/.ssh"))


def _is_private_key_file(path: Path) -> bool:
  try:
    if not path.is_file():
      return False
    if path.suffix == ".pub":
      return False
    if path.name in {"known_hosts", "known_hosts.old", "config", "authorized_keys"}:
      return False
    head = path.open("r", errors="ignore").read(200)
    return "BEGIN" in head and "PRIVATE KEY" in head
  except OSError:
    return False


def list_host_ssh_keys(ctx: AdminContext) -> list[dict[str, Any]]:
  """Scan ~/.ssh for SSH private key files (no contents returned)."""
  ssh_dir = _ssh_dir()
  if not ssh_dir.exists():
    return []
  out: list[dict[str, Any]] = []
  candidates = sorted(ssh_dir.iterdir(), key=lambda p: p.name)
  for entry in candidates:
    if not _is_private_key_file(entry):
      continue
    info: dict[str, Any] = {
      "path": str(entry),
      "name": entry.name,
      "size": entry.stat().st_size,
      "fingerprint": None,
      "type": None,
    }
    pub = entry.with_suffix(entry.suffix + ".pub") if entry.suffix else entry.parent / (entry.name + ".pub")
    if pub.exists():
      try:
        text = pub.read_text(errors="ignore").strip()
        # `ssh-keygen` style line: "<type> <base64> [comment]"
        parts = text.split()
        if len(parts) >= 2:
          info["type"] = parts[0]
          info["fingerprint"] = parts[1][:30] + "…"
      except OSError:
        pass
    out.append(info)
  return out


def read_host_ssh_key(ctx: AdminContext, payload: dict[str, Any]) -> dict[str, Any]:
  """Return the contents of a private key under ~/.ssh."""
  if not isinstance(payload, dict):
    raise HttpError(HTTPStatus.BAD_REQUEST, "expected JSON object", code="invalid_payload")
  raw_path = payload.get("path") or ""
  if not isinstance(raw_path, str) or not raw_path:
    raise HttpError(HTTPStatus.BAD_REQUEST, "path is required", code="path_required")
  candidate = Path(os.path.expanduser(raw_path)).resolve()
  ssh_dir = _ssh_dir().resolve()
  try:
    candidate.relative_to(ssh_dir)
  except ValueError as exc:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "path must be inside ~/.ssh",
      code="path_outside_ssh_dir",
    ) from exc
  if not _is_private_key_file(candidate):
    raise HttpError(HTTPStatus.BAD_REQUEST, "not a private key file", code="not_a_private_key")
  try:
    content = candidate.read_text()
  except OSError as exc:
    raise HttpError(HTTPStatus.INTERNAL_SERVER_ERROR, f"could not read: {exc}", code="read_failed") from exc
  return {"path": str(candidate), "content": content}


def trigger_sync_now(ctx: AdminContext) -> dict[str, Any]:
  try:
    reload_caddy(ctx.config.caddy.reload_command)
  except subprocess.CalledProcessError as exc:
    raise HttpError(
      HTTPStatus.INTERNAL_SERVER_ERROR,
      f"reload_command failed with exit code {exc.returncode}",
      code="reload_failed",
    ) from exc
  except FileNotFoundError as exc:
    raise HttpError(
      HTTPStatus.INTERNAL_SERVER_ERROR,
      f"reload binary not found: {exc.filename}",
      code="reload_binary_missing",
    ) from exc
  LOGGER.info("admin.sync_now reloaded caddy")
  return {"reloaded": True, "at": _to_jsonable(datetime.now(tz=UTC))}


# ---------------------------------------------------------------------------
# Static IP actions
# ---------------------------------------------------------------------------

from . import static_ips as static_ips_mod  # noqa: E402

# Port range — single source of truth, mirrors the schema CHECK constraint
# `port > 0 AND port < 65536`.
_MIN_PORT = 1
_MAX_PORT = 65535

# Allowed values for ip_test_results.test_kind. Mirrors the schema CHECK
# constraint; if this and the schema disagree, inserts will fail at the
# database layer with a confusing error — keep them in sync.
_TEST_KINDS = ("connectivity", "probe", "manual", "loop", "test_all")


def _static_ip_to_dict(rec: StaticIpRecord) -> dict[str, Any]:
  return {
    "id": rec.id,
    "ip": rec.ip,
    "port": rec.port,
    "protocol": rec.protocol,
    "country": rec.country,
    "provider": rec.provider,
    "label": rec.label,
    "notes": rec.notes,
    "static_info": rec.static_info or {},
    "loop_test_seconds": rec.loop_test_seconds,
    "last_test_at": _to_jsonable(rec.last_test_at),
    "last_test_success": rec.last_test_success,
    "last_test_latency_ms": rec.last_test_latency_ms,
    "last_test_error": rec.last_test_error,
    "last_probe_at": _to_jsonable(rec.last_probe_at),
    "created_at": _to_jsonable(rec.created_at),
    "updated_at": _to_jsonable(rec.updated_at),
  }


def _ip_test_result_to_dict(rec: IpTestResultRecord) -> dict[str, Any]:
  return {
    "id": rec.id,
    "ip_id": rec.ip_id,
    "test_kind": rec.test_kind,
    "success": rec.success,
    "latency_ms": rec.latency_ms,
    "error": rec.error,
    "raw": rec.raw or {},
    "created_at": _to_jsonable(rec.created_at),
  }


def _normalize_protocol(value: Any) -> str:
  if value is None:
    return "tcp"
  if not isinstance(value, str):
    raise HttpError(HTTPStatus.BAD_REQUEST, "protocol must be a string", code="invalid_protocol")
  proto = value.strip().lower() or "tcp"
  if proto not in IP_PROTOCOLS:
    # Don't reject — operators sometimes track exotic protocols (e.g.
    # "naive", "ssh-tunnel"). Just log so the operator can spot typos
    # in their bulk paste.
    LOGGER.info("static-ip protocol %r is not in the canonical list", proto)
  return proto


def _normalize_ip(value: Any) -> str:
  if not isinstance(value, str):
    raise HttpError(HTTPStatus.BAD_REQUEST, "ip is required", code="invalid_ip")
  candidate = value.strip()
  if not candidate:
    raise HttpError(HTTPStatus.BAD_REQUEST, "ip is required", code="invalid_ip")
  return candidate


def _normalize_static_ip_port(value: Any) -> int | None:
  """Stricter port normalizer for the static-ips API: rejects bool,
  rejects 0, returns None for empty/missing. (The node API has its
  own ``_normalize_port`` higher up in the file with `default=22`
  semantics — these used to share a name and shadow each other.)"""
  if value is None or value == "":
    return None
  # Reject bool early — int(True) is 1, which would silently accept
  # `{"port": true}` payloads as port=1.
  if isinstance(value, bool):
    raise HttpError(HTTPStatus.BAD_REQUEST, "port must be an integer", code="invalid_port")
  try:
    port = int(value)
  except (TypeError, ValueError) as exc:
    raise HttpError(HTTPStatus.BAD_REQUEST, "port must be an integer", code="invalid_port") from exc
  if port < _MIN_PORT or port > _MAX_PORT:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      f"port must be {_MIN_PORT}..{_MAX_PORT}",
      code="invalid_port",
    )
  return port


_STATIC_IP_SORTS = ("country", "provider", "ip", "created")


def list_static_ips(ctx: AdminContext, *, sort: str = "country") -> list[dict[str, Any]]:
  if sort not in _STATIC_IP_SORTS:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      f"sort must be one of: {', '.join(_STATIC_IP_SORTS)}",
      code="invalid_sort",
    )
  return [_static_ip_to_dict(r) for r in ctx.database.list_static_ips(sort=sort)]


def get_static_ip_detail(ctx: AdminContext, ip_id: int) -> dict[str, Any]:
  # Parallel fetch — the row and its history are independent reads;
  # over a remote DB this halves the wall time.
  from concurrent.futures import ThreadPoolExecutor
  iid = int(ip_id)
  with ThreadPoolExecutor(max_workers=2) as ex:
    rec_f = ex.submit(ctx.database.get_static_ip, iid)
    hist_f = ex.submit(ctx.database.list_ip_test_results, iid, limit=50)
    rec = rec_f.result()
    history = hist_f.result()
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"static ip not found: {ip_id}", code="ip_not_found")
  payload = _static_ip_to_dict(rec)
  payload["recent_results"] = [_ip_test_result_to_dict(r) for r in history]
  return payload


def create_static_ip(ctx: AdminContext, payload: dict[str, Any]) -> dict[str, Any]:
  ip = _normalize_ip(payload.get("ip"))
  port = _normalize_static_ip_port(payload.get("port"))
  protocol = _normalize_protocol(payload.get("protocol"))
  country = (payload.get("country") or None)
  provider = (payload.get("provider") or None)
  label = (payload.get("label") or None)
  notes = (payload.get("notes") or None)
  loop = payload.get("loop_test_seconds")
  loop_seconds: int | None = None
  if loop not in (None, "", 0):
    try:
      loop_seconds = max(1, int(loop))
    except (TypeError, ValueError) as exc:
      raise HttpError(HTTPStatus.BAD_REQUEST, "loop_test_seconds must be an integer", code="invalid_loop") from exc
  rec = ctx.database.insert_static_ip(
    ip=ip, port=port, protocol=protocol,
    country=country, provider=provider,
    label=label, notes=notes,
    loop_test_seconds=loop_seconds,
  )
  return _static_ip_to_dict(rec)


def update_static_ip_record(
  ctx: AdminContext, ip_id: int, payload: dict[str, Any]
) -> dict[str, Any]:
  fields: dict[str, Any] = {}
  if "ip" in payload:
    fields["ip"] = _normalize_ip(payload["ip"])
  if "port" in payload:
    fields["port"] = _normalize_static_ip_port(payload["port"])
  if "protocol" in payload:
    fields["protocol"] = _normalize_protocol(payload["protocol"])
  for key in ("country", "provider", "label", "notes"):
    if key in payload:
      fields[key] = (payload[key] or None)
  if "loop_test_seconds" in payload:
    val = payload["loop_test_seconds"]
    if val in (None, "", 0):
      fields["loop_test_seconds"] = None
    else:
      try:
        fields["loop_test_seconds"] = max(1, int(val))
      except (TypeError, ValueError) as exc:
        raise HttpError(HTTPStatus.BAD_REQUEST, "loop_test_seconds must be an integer", code="invalid_loop") from exc
  rec = ctx.database.update_static_ip(int(ip_id), fields)
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"static ip not found: {ip_id}", code="ip_not_found")
  return _static_ip_to_dict(rec)


def delete_static_ip_record(ctx: AdminContext, ip_id: int) -> dict[str, Any]:
  ok = ctx.database.delete_static_ip(int(ip_id))
  if not ok:
    raise HttpError(HTTPStatus.NOT_FOUND, f"static ip not found: {ip_id}", code="ip_not_found")
  return {"deleted": True, "id": int(ip_id)}


def _ai_parser_config(ctx: AdminContext) -> dict[str, Any]:
  """Read AI parser credentials from the system_config table.

  Returns a dict shaped for static_ips.parse_bulk_input. Empty when
  nothing is configured — caller falls back to env vars / regex.
  """
  try:
    row = ctx.database.get_system_config("ai_api") or {}
  except Exception:
    return {}
  cfg: dict[str, Any] = {}
  base_url = (row.get("base_url") or "").strip()
  api_key = (row.get("api_key") or "").strip()
  model = (row.get("model") or "").strip()
  provider = (row.get("provider") or "openai").lower()
  if provider == "anthropic":
    if api_key:
      cfg["anthropic"] = {"api_key": api_key, "model": model}
  else:
    if api_key or base_url or model:
      cfg["openai"] = {
        "base_url": base_url or "https://api.openai.com",
        "api_key": api_key,
        "model": model,
      }
  return cfg


def parse_bulk_static_ips(ctx: AdminContext, payload: dict[str, Any]) -> dict[str, Any]:
  text = (payload.get("text") or "")
  commit = bool(payload.get("commit"))
  ai_cfg = _ai_parser_config(ctx)
  ai_was_configured = bool(ai_cfg.get("openai") or ai_cfg.get("anthropic"))
  parsed, mode = static_ips_mod.parse_bulk_input(text, config=ai_cfg)
  created: list[dict[str, Any]] = []
  errors: list[dict[str, Any]] = []
  if commit and parsed:
    # One round trip for the whole batch — inserting 50 rows used to
    # take ~12 s on a remote Supabase link, now ~250 ms.
    rows, bulk_errors = ctx.database.bulk_insert_static_ips(parsed)
    created = [_static_ip_to_dict(r) for r in rows]
    errors.extend(bulk_errors)
    # If the bulk SQL itself failed (everything is in errors and
    # nothing in rows), fall back to per-row inserts so a single bad
    # value doesn't take down the whole batch.
    if not rows and bulk_errors and any(
      "bulk insert failed" in e.get("error", "") for e in bulk_errors
    ):
      LOGGER.warning("bulk insert failed; falling back to per-row")
      created, errors = [], []
      for rec in parsed:
        ip_val = (rec.get("ip") or "").strip() if isinstance(rec, dict) else ""
        if not ip_val:
          errors.append({"input": rec, "error": "empty ip"})
          continue
        try:
          row = ctx.database.insert_static_ip(
            ip=ip_val,
            port=rec.get("port"),
            protocol=rec.get("protocol") or "tcp",
            country=rec.get("country"),
            provider=rec.get("provider"),
            label=rec.get("label"),
          )
          created.append(_static_ip_to_dict(row))
        except Exception as exc:  # noqa: BLE001
          LOGGER.exception("static ip insert failed for %r", rec)
          errors.append({"input": rec, "error": str(exc)[:200]})
  return {
    "mode": mode,
    # When AI credentials are configured but the parser ended up using
    # regex, the AI request failed silently — surface the hint so the UI
    # can warn the operator. Look in the controller log for the cause.
    "ai_fallback": ai_was_configured and mode == "regex",
    "parsed": parsed,
    "committed": created,
    "errors": errors,
  }


def run_ip_connectivity_test(
  ctx: AdminContext, ip_id: int, *, kind: str = "connectivity"
) -> dict[str, Any]:
  if kind not in _TEST_KINDS:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      f"kind must be one of: {', '.join(_TEST_KINDS)}",
      code="invalid_test_kind",
    )
  rec = ctx.database.get_static_ip(int(ip_id))
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"static ip not found: {ip_id}", code="ip_not_found")
  result = static_ips_mod.test_connectivity(rec.ip, rec.port, rec.protocol)
  ctx.database.insert_ip_test_result(
    ip_id=rec.id,
    test_kind=kind,
    success=bool(result["success"]),
    latency_ms=result.get("latency_ms"),
    error=result.get("error"),
    raw={"kind": result.get("kind")},
  )
  ctx.database.update_static_ip(rec.id, {
    "last_test_at": datetime.now(tz=UTC),
    "last_test_success": bool(result["success"]),
    "last_test_latency_ms": result.get("latency_ms"),
    "last_test_error": result.get("error"),
  })
  return {
    "id": rec.id,
    "ip": rec.ip,
    "port": rec.port,
    "protocol": rec.protocol,
    "kind": kind,
    "result": result,
  }


def run_ip_test_all(ctx: AdminContext) -> dict[str, Any]:
  rows = ctx.database.list_static_ips()
  if not rows:
    return {
      "total": 0, "success": 0, "fail": 0,
      "results": [], "errors": [], "at": _to_jsonable(datetime.now(tz=UTC)),
    }
  # Parallelize the connectivity probes — each TCP/ICMP test is mostly
  # waiting on network IO and they're independent. Capping workers at 8
  # avoids fanning out so wide we exhaust the DB pool when the
  # follow-up writes fire.
  from concurrent.futures import ThreadPoolExecutor

  def _probe_one(rec):
    try:
      res = static_ips_mod.test_connectivity(rec.ip, rec.port, rec.protocol)
      return rec, res, None
    except Exception as exc:  # noqa: BLE001
      LOGGER.exception("test_connectivity raised for ip_id=%s", rec.id)
      return rec, {
        "success": False, "latency_ms": None,
        "error": str(exc)[:300], "kind": "tcp",
      }, exc

  workers = min(8, max(2, len(rows)))
  with ThreadPoolExecutor(max_workers=workers) as ex:
    probed = list(ex.map(_probe_one, rows))

  # Persist results — also parallelized since each row uses its own
  # pooled connection. We tolerate per-row write failures without
  # aborting the whole batch.
  errors: list[dict[str, Any]] = []
  results: list[dict[str, Any]] = []
  ok = 0
  fail = 0
  now = datetime.now(tz=UTC)

  def _persist(item):
    rec, res, probe_exc = item
    if probe_exc is not None:
      errors.append({"id": rec.id, "ip": rec.ip, "stage": "test", "error": str(probe_exc)[:300]})
    try:
      ctx.database.insert_ip_test_result(
        ip_id=rec.id,
        test_kind="test_all",
        success=bool(res["success"]),
        latency_ms=res.get("latency_ms"),
        error=res.get("error"),
        raw={"kind": res.get("kind")},
      )
      ctx.database.update_static_ip(rec.id, {
        "last_test_at": now,
        "last_test_success": bool(res["success"]),
        "last_test_latency_ms": res.get("latency_ms"),
        "last_test_error": res.get("error"),
      })
    except Exception as exc:  # noqa: BLE001
      LOGGER.exception("DB write failed for ip_id=%s during test-all", rec.id)
      errors.append({"id": rec.id, "ip": rec.ip, "stage": "persist", "error": str(exc)[:300]})

  with ThreadPoolExecutor(max_workers=workers) as ex:
    list(ex.map(_persist, probed))

  for rec, res, _ in probed:
    if res["success"]:
      ok += 1
    else:
      fail += 1
    results.append({
      "id": rec.id, "ip": rec.ip, "port": rec.port,
      "protocol": rec.protocol, "country": rec.country, "provider": rec.provider,
      "result": res,
    })
  return {
    "total": len(rows),
    "success": ok,
    "fail": fail,
    "results": results,
    "errors": errors,
    "at": _to_jsonable(now),
  }


def run_ip_static_probe(ctx: AdminContext, ip_id: int) -> dict[str, Any]:
  rec = ctx.database.get_static_ip(int(ip_id))
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"static ip not found: {ip_id}", code="ip_not_found")
  info = static_ips_mod.probe_static_info(rec.ip)
  geo = info.get("geo") or {}
  geo_error = geo.get("error") if isinstance(geo, dict) else None
  ctx.database.update_static_ip(rec.id, {
    "static_info": info,
    "last_probe_at": datetime.now(tz=UTC),
  })
  ctx.database.insert_ip_test_result(
    ip_id=rec.id,
    test_kind="probe",
    success=geo_error is None,
    latency_ms=None,
    error=geo_error,
    raw={"summary": "static info probe", "geo": geo},
  )
  return {
    "id": rec.id,
    "ip": rec.ip,
    "static_info": info,
  }


# ---------------------------------------------------------------------------
# System config (key/value store, plain text)
# ---------------------------------------------------------------------------

# Recognized keys → schema (allowed sub-keys). Unknown sub-keys are
# rejected so a typo like "api_ky" doesn't silently get persisted.
SYSTEM_CONFIG_SCHEMAS: dict[str, set[str]] = {
  "ai_api": {"provider", "base_url", "api_key", "model"},
}
SYSTEM_CONFIG_KEYS = tuple(SYSTEM_CONFIG_SCHEMAS.keys())


def list_system_config(ctx: AdminContext) -> dict[str, dict[str, Any]]:
  rows = ctx.database.list_system_config()
  out: dict[str, dict[str, Any]] = {k: {} for k in SYSTEM_CONFIG_KEYS}
  for k, v in rows.items():
    out[k] = v if isinstance(v, dict) else {}
  return out


def get_system_config(ctx: AdminContext, key: str) -> dict[str, Any]:
  if key not in SYSTEM_CONFIG_SCHEMAS:
    raise HttpError(
      HTTPStatus.NOT_FOUND, f"unknown config key: {key}", code="config_key_not_found"
    )
  return ctx.database.get_system_config(key) or {}


def upsert_system_config(
  ctx: AdminContext, key: str, payload: dict[str, Any]
) -> dict[str, Any]:
  schema = SYSTEM_CONFIG_SCHEMAS.get(key)
  if schema is None:
    raise HttpError(
      HTTPStatus.NOT_FOUND, f"unknown config key: {key}", code="config_key_not_found"
    )
  if not isinstance(payload, dict):
    raise HttpError(
      HTTPStatus.BAD_REQUEST, "config value must be an object", code="invalid_config"
    )
  unknown = sorted(set(payload.keys()) - schema)
  if unknown:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      f"unknown sub-keys for {key}: {', '.join(unknown)}; allowed: {', '.join(sorted(schema))}",
      code="invalid_config",
    )
  cleaned: dict[str, Any] = {}
  for k, v in payload.items():
    if v is None:
      continue
    if not isinstance(v, (str, bool, int, float)):
      raise HttpError(
        HTTPStatus.BAD_REQUEST,
        f"value for {key}.{k} must be a primitive (string/bool/number)",
        code="invalid_config",
      )
    cleaned[k] = v.strip() if isinstance(v, str) else v
  return ctx.database.upsert_system_config(key, cleaned)


# ---------------------------------------------------------------------------
# SSH key actions
# ---------------------------------------------------------------------------

from . import ssh_keys as ssh_keys_mod  # noqa: E402

_SSH_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def _ssh_key_to_dict(rec: SshKeyRecord, *, reveal_private: bool = True) -> dict[str, Any]:
  """Per the operator's stated preference, secrets ARE returned in
  plaintext. The flag is preserved for any future caller that wants
  a redacted view."""
  return {
    "id": rec.id,
    "name": rec.name,
    "description": rec.description,
    "key_type": rec.key_type,
    "bits": rec.bits,
    "private_key": rec.private_key if reveal_private else None,
    "public_key": rec.public_key,
    "fingerprint_sha256": rec.fingerprint_sha256,
    "comment": rec.comment,
    "passphrase": rec.passphrase if reveal_private else None,
    "has_passphrase": bool(rec.passphrase),
    "source": rec.source,
    "tags": list(rec.tags or []),
    "created_at": _to_jsonable(rec.created_at),
    "updated_at": _to_jsonable(rec.updated_at),
  }


def _normalize_ssh_key_name(value: Any) -> str:
  text = (value or "").strip() if isinstance(value, str) else ""
  if not text:
    raise HttpError(HTTPStatus.BAD_REQUEST, "name is required", code="ssh_key_name_required")
  if not _SSH_KEY_NAME_RE.match(text):
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "name must match [A-Za-z0-9._-]{1,63}",
      code="invalid_ssh_key_name",
    )
  return text


def list_ssh_keys(ctx: AdminContext) -> list[dict[str, Any]]:
  rows = ctx.database.list_ssh_keys()
  out: list[dict[str, Any]] = []
  for rec in rows:
    payload = _ssh_key_to_dict(rec)
    payload["used_by_nodes"] = ctx.database.count_nodes_using_key(rec.private_key)
    out.append(payload)
  return out


def get_ssh_key_detail(ctx: AdminContext, key_id: int) -> dict[str, Any]:
  rec = ctx.database.get_ssh_key(int(key_id))
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"ssh key not found: {key_id}", code="ssh_key_not_found")
  payload = _ssh_key_to_dict(rec)
  payload["used_by_nodes"] = ctx.database.count_nodes_using_key(rec.private_key)
  return payload


def create_ssh_key(ctx: AdminContext, payload: dict[str, Any]) -> dict[str, Any]:
  """Create an SSH key — either generate a fresh keypair or import an
  existing one. Mode is selected by which fields are present."""
  name = _normalize_ssh_key_name(payload.get("name"))
  description = (payload.get("description") or None)
  comment = (payload.get("comment") or "")
  passphrase = (payload.get("passphrase") or None)
  tags_in = payload.get("tags") or []
  if not isinstance(tags_in, list):
    raise HttpError(HTTPStatus.BAD_REQUEST, "tags must be a list", code="invalid_tags")
  tags = [str(t).strip() for t in tags_in if str(t).strip()]

  if ctx.database.get_ssh_key_by_name(name) is not None:
    raise HttpError(HTTPStatus.CONFLICT, f"ssh key already exists: {name}", code="ssh_key_exists")

  imported_private = (payload.get("private_key") or "").strip()
  imported_public = (payload.get("public_key") or "").strip()

  source = "generated"
  if imported_private:
    # Import path — derive metadata + canonicalize.
    try:
      meta = ssh_keys_mod.parse_private_key(imported_private, passphrase=passphrase)
    except ValueError as exc:
      raise HttpError(HTTPStatus.BAD_REQUEST, str(exc), code="invalid_private_key") from exc
    if comment and not meta["public_key"].endswith(" " + comment):
      # Append comment to the canonical public key line.
      parts = meta["public_key"].split(None, 2)
      if len(parts) >= 2:
        meta["public_key"] = f"{parts[0]} {parts[1]} {comment}"
        meta["fingerprint_sha256"] = ssh_keys_mod.sha256_fingerprint(meta["public_key"])
    source = "imported"
    rec = ctx.database.insert_ssh_key(
      name=name, description=description, comment=comment or None,
      passphrase=passphrase, source=source, tags=tags,
      key_type=meta["key_type"], bits=meta["bits"],
      private_key=meta["private_key"], public_key=meta["public_key"],
      fingerprint_sha256=meta["fingerprint_sha256"],
    )
  elif imported_public and not imported_private:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      "cannot import a public key alone — paste the private key (we derive the public)",
      code="public_only_import_unsupported",
    )
  else:
    # Generate path — type / bits selected via payload.
    key_type = (payload.get("key_type") or "ed25519").strip().lower()
    bits_raw = payload.get("bits")
    bits = None
    if bits_raw not in (None, ""):
      try:
        bits = int(bits_raw)
      except (TypeError, ValueError) as exc:
        raise HttpError(HTTPStatus.BAD_REQUEST, "bits must be integer", code="invalid_bits") from exc
    try:
      gen = ssh_keys_mod.generate_keypair(
        key_type=key_type, bits=bits,
        comment=comment, passphrase=passphrase,
      )
    except ValueError as exc:
      raise HttpError(HTTPStatus.BAD_REQUEST, str(exc), code="invalid_key_params") from exc
    rec = ctx.database.insert_ssh_key(
      name=name, description=description, comment=comment or None,
      passphrase=passphrase, source="generated", tags=tags,
      key_type=gen.key_type, bits=gen.bits,
      private_key=gen.private_key, public_key=gen.public_key,
      fingerprint_sha256=gen.fingerprint_sha256,
    )
  return _ssh_key_to_dict(rec)


def update_ssh_key_record(
  ctx: AdminContext, key_id: int, payload: dict[str, Any]
) -> dict[str, Any]:
  fields: dict[str, Any] = {}
  if "name" in payload:
    new_name = _normalize_ssh_key_name(payload["name"])
    existing = ctx.database.get_ssh_key_by_name(new_name)
    if existing is not None and existing.id != int(key_id):
      raise HttpError(HTTPStatus.CONFLICT, f"name in use: {new_name}", code="ssh_key_exists")
    fields["name"] = new_name
  for key in ("description", "comment", "passphrase"):
    if key in payload:
      fields[key] = payload[key] or None
  if "tags" in payload:
    raw = payload["tags"]
    if not isinstance(raw, list):
      raise HttpError(HTTPStatus.BAD_REQUEST, "tags must be a list", code="invalid_tags")
    fields["tags"] = [str(t).strip() for t in raw if str(t).strip()]
  # If comment changed, also rebuild the public_key line and fingerprint.
  if "comment" in fields:
    rec = ctx.database.get_ssh_key(int(key_id))
    if rec is not None:
      parts = rec.public_key.split(None, 2)
      base = " ".join(parts[:2]) if len(parts) >= 2 else rec.public_key
      new_pub = f"{base} {fields['comment']}" if fields["comment"] else base
      fields["public_key"] = new_pub
      fields["fingerprint_sha256"] = ssh_keys_mod.sha256_fingerprint(new_pub)
  rec = ctx.database.update_ssh_key(int(key_id), fields)
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"ssh key not found: {key_id}", code="ssh_key_not_found")
  return _ssh_key_to_dict(rec)


def delete_ssh_key_record(ctx: AdminContext, key_id: int) -> dict[str, Any]:
  rec = ctx.database.get_ssh_key(int(key_id))
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"ssh key not found: {key_id}", code="ssh_key_not_found")
  used = ctx.database.count_nodes_using_key(rec.private_key)
  if used > 0:
    raise HttpError(
      HTTPStatus.CONFLICT,
      f"key is in use by {used} node(s) — detach it first or delete the nodes",
      code="ssh_key_in_use",
    )
  ctx.database.delete_ssh_key(int(key_id))
  return {"deleted": True, "id": int(key_id)}


def regenerate_ssh_key(ctx: AdminContext, key_id: int, payload: dict[str, Any]) -> dict[str, Any]:
  """Replace the keypair on an existing row, keeping the name/tags/etc."""
  rec = ctx.database.get_ssh_key(int(key_id))
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"ssh key not found: {key_id}", code="ssh_key_not_found")
  key_type = (payload.get("key_type") or rec.key_type).strip().lower()
  bits_raw = payload.get("bits")
  bits = None
  if bits_raw not in (None, ""):
    try:
      bits = int(bits_raw)
    except (TypeError, ValueError) as exc:
      raise HttpError(HTTPStatus.BAD_REQUEST, "bits must be integer", code="invalid_bits") from exc
  comment = payload.get("comment") if "comment" in payload else (rec.comment or "")
  passphrase = payload.get("passphrase") if "passphrase" in payload else rec.passphrase
  try:
    gen = ssh_keys_mod.generate_keypair(
      key_type=key_type, bits=bits,
      comment=comment or "", passphrase=passphrase,
    )
  except ValueError as exc:
    raise HttpError(HTTPStatus.BAD_REQUEST, str(exc), code="invalid_key_params") from exc
  updated = ctx.database.update_ssh_key(int(key_id), {
    "key_type": gen.key_type, "bits": gen.bits,
    "private_key": gen.private_key, "public_key": gen.public_key,
    "fingerprint_sha256": gen.fingerprint_sha256,
    "comment": comment or None,
    "passphrase": passphrase or None,
    "source": "generated",
  })
  return _ssh_key_to_dict(updated) if updated else _ssh_key_to_dict(rec)


_SSH_KEY_DEPLOY_MODES = ("public", "private", "both")


_LOCAL_APPLY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def apply_ssh_key_to_local(
  ctx: AdminContext, key_id: int, payload: dict[str, Any]
) -> dict[str, Any]:
  """Write the selected SSH key to the LOCAL machine's ``~/.ssh/`` dir.

  This is a destructive convenience: it mimics what an operator would
  manually do with a fresh laptop — overwrite ``~/.ssh/id_<algo>`` and
  ``~/.ssh/id_<algo>.pub`` so OpenSSH picks up the key by default.

  Existing files at the target paths are backed up to
  ``id_<algo>.bak.<YYYYMMDDHHMMSS>`` first; nothing is silently
  destroyed.

  Optional ``payload.filename`` overrides the default ``id_<algo>``
  base name (must match ``[A-Za-z0-9._-]{1,64}``). Useful when you
  don't want to clobber the existing default identity.
  """
  rec = ctx.database.get_ssh_key(int(key_id))
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"ssh key not found: {key_id}", code="ssh_key_not_found")

  ssh_dir = os.path.expanduser("~/.ssh")

  # Determine the base file name. Default = id_<algo> (the standard
  # OpenSSH identity file).
  override = (payload.get("filename") or "").strip()
  if override:
    if not _LOCAL_APPLY_NAME_RE.match(override):
      raise HttpError(
        HTTPStatus.BAD_REQUEST,
        "filename must match [A-Za-z0-9._-]{1,64}",
        code="invalid_filename",
      )
    base_name = override
  else:
    base_name = f"id_{rec.key_type}"  # id_ed25519 / id_rsa / id_ecdsa / id_dsa

  priv_path = os.path.join(ssh_dir, base_name)
  pub_path = priv_path + ".pub"

  # Hard safety: refuse anything outside ~/.ssh.
  resolved = os.path.realpath(priv_path)
  if not resolved.startswith(os.path.realpath(ssh_dir) + os.sep):
    raise HttpError(HTTPStatus.BAD_REQUEST, "refusing to write outside ~/.ssh",
                    code="path_unsafe")

  # Make ~/.ssh if needed (mode 700).
  try:
    os.makedirs(ssh_dir, exist_ok=True)
    os.chmod(ssh_dir, 0o700)
  except OSError as exc:
    raise HttpError(HTTPStatus.INTERNAL_SERVER_ERROR,
                    f"could not prepare {ssh_dir}: {exc}",
                    code="ssh_dir_unavailable") from exc

  # Back up anything already at the target paths.
  ts = datetime.now(tz=UTC).strftime("%Y%m%d%H%M%S")
  backups: list[str] = []
  for path in (priv_path, pub_path):
    if os.path.exists(path):
      bak = f"{path}.bak.{ts}"
      try:
        os.replace(path, bak)
      except OSError as exc:
        raise HttpError(HTTPStatus.INTERNAL_SERVER_ERROR,
                        f"could not back up {path}: {exc}",
                        code="backup_failed") from exc
      backups.append(bak)

  # Write the new files.
  written: list[str] = []
  try:
    # Use os.open + os.fdopen so we control the mode bits at create time —
    # avoids a brief window where the file exists at default mode 644.
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
      with os.fdopen(fd, "w") as fh:
        fh.write(rec.private_key if rec.private_key.endswith("\n")
                 else rec.private_key + "\n")
    finally:
      try: os.chmod(priv_path, 0o600)
      except OSError: pass
    written.append(priv_path)

    pub_text = rec.public_key.strip() + "\n"
    fd = os.open(pub_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
      with os.fdopen(fd, "w") as fh:
        fh.write(pub_text)
    finally:
      try: os.chmod(pub_path, 0o644)
      except OSError: pass
    written.append(pub_path)
  except OSError as exc:
    raise HttpError(HTTPStatus.INTERNAL_SERVER_ERROR,
                    f"failed writing key files: {exc}",
                    code="write_failed") from exc

  LOGGER.warning(
    "admin.apply_ssh_key_to_local key=%s name=%s -> %s (backups=%s)",
    rec.id, rec.name, written, backups,
  )
  return {
    "applied": True,
    "ssh_key_id": rec.id,
    "ssh_key_name": rec.name,
    "key_type": rec.key_type,
    "fingerprint_sha256": rec.fingerprint_sha256,
    "ssh_dir": ssh_dir,
    "written": written,
    "backups": backups,
    "applied_at": _to_jsonable(datetime.now(tz=UTC)),
  }


def attach_ssh_key_to_node(
  ctx: AdminContext, key_id: int, payload: dict[str, Any]
) -> dict[str, Any]:
  """Legacy single-node "use as admin login credential" — only writes
  the private key into ``nodes.ssh_private_key``. Used when the public
  key is already on the remote (or the operator just wants the admin
  service to authenticate to the node with this key).

  For deploying to remote ~/.ssh/* files, see ``deploy_ssh_key_to_nodes``.
  """
  rec = ctx.database.get_ssh_key(int(key_id))
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"ssh key not found: {key_id}", code="ssh_key_not_found")
  node_name = (payload.get("node_name") or "").strip()
  if not node_name:
    raise HttpError(HTTPStatus.BAD_REQUEST, "node_name is required", code="node_name_required")
  ok = ctx.database.attach_ssh_key_to_node(node_name, rec.private_key, rec.passphrase)
  if not ok:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {node_name}", code="node_not_found")
  return {
    "attached": True,
    "ssh_key_id": rec.id,
    "ssh_key_name": rec.name,
    "node_name": node_name,
    "fingerprint_sha256": rec.fingerprint_sha256,
  }


def deploy_ssh_key_to_nodes(
  ctx: AdminContext, key_id: int, payload: dict[str, Any]
) -> dict[str, Any]:
  """Deploy a key's material to one or more nodes.

  Body: ``{"nodes": ["us01", "us02"], "mode": "public"|"private"|"both",
           "all": false}``. When ``all`` is true the ``nodes`` list is
  ignored and every registered node is targeted. Returns a per-node
  result list; partial failures are reported, not raised.
  """
  rec = ctx.database.get_ssh_key(int(key_id))
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"ssh key not found: {key_id}", code="ssh_key_not_found")

  mode = (payload.get("mode") or "both").strip().lower()
  if mode not in _SSH_KEY_DEPLOY_MODES:
    raise HttpError(
      HTTPStatus.BAD_REQUEST,
      f"mode must be one of: {', '.join(_SSH_KEY_DEPLOY_MODES)}",
      code="invalid_deploy_mode",
    )

  all_nodes = bool(payload.get("all"))
  if all_nodes:
    targets = [n.name for n in ctx.database.list_nodes()]
  else:
    raw = payload.get("nodes")
    if not isinstance(raw, list) or not raw:
      raise HttpError(
        HTTPStatus.BAD_REQUEST,
        "nodes must be a non-empty list (or set all=true)",
        code="nodes_required",
      )
    targets = [str(n).strip() for n in raw if str(n).strip()]
    if not targets:
      raise HttpError(HTTPStatus.BAD_REQUEST, "nodes list empty", code="nodes_required")

  # Resolve node records up front so we fail fast on bad names.
  node_recs: list[NodeRecord] = []
  missing: list[str] = []
  for name in targets:
    n = ctx.database.get_node(name)
    if n is None:
      missing.append(name)
    else:
      node_recs.append(n)
  if missing:
    raise HttpError(
      HTTPStatus.NOT_FOUND,
      f"node(s) not found: {', '.join(missing)}",
      code="node_not_found",
    )

  from concurrent.futures import ThreadPoolExecutor

  def _deploy_one(n: NodeRecord):
    try:
      r = nodes_mod.deploy_ssh_key(
        n,
        key_name=rec.name,
        public_key=rec.public_key,
        private_key=rec.private_key if mode in ("private", "both") else None,
        mode=mode,
        linked_keys=_ssh_credentials_for_node(ctx, n.name),
      )
      return {
        "node": n.name,
        "host": f"{n.ssh_user}@{n.host}:{n.ssh_port}",
        "mode": r.mode,
        "ok": r.ok,
        "public_added": r.public_added,
        "public_already_present": r.public_already_present,
        "private_path": r.private_path,
        "error": r.error,
        "duration_seconds": r.duration_seconds,
      }
    except Exception as exc:  # noqa: BLE001
      LOGGER.exception("deploy_ssh_key crashed for node=%s key=%s", n.name, rec.name)
      return {
        "node": n.name,
        "host": f"{n.ssh_user}@{n.host}:{n.ssh_port}",
        "mode": mode,
        "ok": False,
        "error": f"{type(exc).__name__}: {exc}"[:500],
      }

  workers = min(8, max(1, len(node_recs)))
  with ThreadPoolExecutor(max_workers=workers) as ex:
    results = list(ex.map(_deploy_one, node_recs))

  ok_count = sum(1 for r in results if r["ok"])
  return {
    "ssh_key_id": rec.id,
    "ssh_key_name": rec.name,
    "fingerprint_sha256": rec.fingerprint_sha256,
    "mode": mode,
    "total": len(results),
    "success": ok_count,
    "fail": len(results) - ok_count,
    "results": results,
    "at": _to_jsonable(datetime.now(tz=UTC)),
  }


def list_ip_test_results_action(ctx: AdminContext, ip_id: int, *, limit: int = 50) -> list[dict[str, Any]]:
  rec = ctx.database.get_static_ip(int(ip_id))
  if rec is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"static ip not found: {ip_id}", code="ip_not_found")
  rows = ctx.database.list_ip_test_results(int(ip_id), limit=int(limit))
  return [_ip_test_result_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


RouteHandler = Callable[["_Request"], "_Response"]


@dataclass(slots=True)
class _Request:
  method: str
  path: str
  query: dict[str, list[str]]
  headers: dict[str, str]
  body: bytes
  path_params: dict[str, str]

  def json_body(self) -> dict[str, Any]:
    if not self.body:
      return {}
    try:
      data = json.loads(self.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
      raise HttpError(HTTPStatus.BAD_REQUEST, f"invalid JSON body: {exc}", code="invalid_json") from exc
    if not isinstance(data, dict):
      raise HttpError(HTTPStatus.BAD_REQUEST, "JSON body must be an object", code="invalid_json")
    return data

  def query_bool(self, name: str, default: bool = False) -> bool:
    if name not in self.query:
      return default
    value = (self.query[name][0] or "").strip().lower()
    return value in {"1", "true", "yes", "on"}

  def query_int(self, name: str, default: int) -> int:
    if name not in self.query:
      return default
    value = (self.query[name][0] or "").strip()
    try:
      return int(value)
    except ValueError as exc:
      raise HttpError(HTTPStatus.BAD_REQUEST, f"invalid {name}", code="invalid_query") from exc

  def query_str(self, name: str, default: str = "") -> str:
    if name not in self.query:
      return default
    return (self.query[name][0] or "").strip()


@dataclass(slots=True)
class _Response:
  status: int = HTTPStatus.OK
  body: bytes = b""
  headers: dict[str, str] | None = None


def _json_response(status: int, payload: Any) -> _Response:
  body = json.dumps(_to_jsonable(payload), ensure_ascii=False).encode("utf-8")
  return _Response(
    status=status,
    body=body,
    headers={
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  )


def _error_response(error: HttpError) -> _Response:
  return _json_response(error.status, {"error": {"code": error.code, "message": error.message}})


class _Router:
  def __init__(self) -> None:
    self._routes: list[tuple[str, re.Pattern[str], RouteHandler]] = []

  def add(self, method: str, pattern: str, handler: RouteHandler) -> None:
    compiled = re.compile("^" + re.sub(r"\{([^/]+)\}", r"(?P<\1>[^/]+)", pattern) + "$")
    self._routes.append((method.upper(), compiled, handler))

  def resolve(self, method: str, path: str) -> tuple[RouteHandler, dict[str, str]] | None:
    for route_method, compiled, handler in self._routes:
      if route_method != method.upper():
        continue
      match = compiled.match(path)
      if match is not None:
        return handler, match.groupdict()
    return None


def _build_router(ctx: AdminContext) -> _Router:
  router = _Router()

  def with_auth(handler: RouteHandler) -> RouteHandler:
    def wrapped(request: _Request) -> _Response:
      return handler(request)

    wrapped.__name__ = handler.__name__
    return wrapped

  def overview_handler(_request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, build_overview(ctx))

  def list_routes_handler(request: _Request) -> _Response:
    data = list_routes_summary(ctx)
    q = request.query_str("q")
    if q:
      lowered = q.lower()
      data = [item for item in data if lowered in item["domain"].lower()]
    return _json_response(HTTPStatus.OK, {"routes": data})

  def create_route_handler(request: _Request) -> _Response:
    result = create_route(ctx, request.json_body())
    return _json_response(HTTPStatus.CREATED, result)

  def route_detail_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, get_route_detail(ctx, request.path_params["domain"]))

  def route_patch_handler(request: _Request) -> _Response:
    result = update_route(ctx, request.path_params["domain"], request.json_body())
    return _json_response(HTTPStatus.OK, result)

  def route_delete_handler(request: _Request) -> _Response:
    purge = request.query_bool("purge")
    return _json_response(
      HTTPStatus.OK,
      delete_route(ctx, request.path_params["domain"], purge=purge),
    )

  def route_enable_handler(request: _Request) -> _Response:
    result = update_route(ctx, request.path_params["domain"], {"enabled": True})
    return _json_response(HTTPStatus.OK, result)

  def route_disable_handler(request: _Request) -> _Response:
    result = update_route(ctx, request.path_params["domain"], {"enabled": False})
    return _json_response(HTTPStatus.OK, result)

  def clear_retry_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK,
      clear_retry_after(ctx, request.path_params["domain"]),
    )

  def certificates_handler(_request: _Request) -> _Response:
    certificates = ctx.database.fetch_certificates()
    rows = [_certificate_to_dict(cert) for cert in certificates.values()]
    return _json_response(HTTPStatus.OK, {"certificates": rows})

  def certificate_detail_handler(request: _Request) -> _Response:
    domain = _normalize_domain(request.path_params["domain"])
    certificates = ctx.database.fetch_certificates()
    cert = certificates.get(domain)
    if cert is None:
      raise HttpError(
        HTTPStatus.NOT_FOUND,
        f"certificate not found: {domain}",
        code="certificate_not_found",
      )
    return _json_response(HTTPStatus.OK, _certificate_to_dict(cert))

  def zones_handler(request: _Request) -> _Response:
    reveal = request.query_bool("reveal_token")
    return _json_response(HTTPStatus.OK, {"zones": list_zones(ctx, reveal_token=reveal)})

  def upsert_zone_handler(request: _Request) -> _Response:
    result = upsert_zone(ctx, request.json_body())
    return _json_response(HTTPStatus.OK, result)

  def delete_zone_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK,
      delete_zone(ctx, request.path_params["zone_name"]),
    )

  def logs_handler(request: _Request) -> _Response:
    which = request.query_str("which", "controller")
    tail = max(1, min(request.query_int("tail", 500), 5000))
    if which == "controller":
      path = Path(ctx.config.logging.controller_log_path)
    elif which == "caddy":
      path = Path(ctx.config.logging.caddy_log_path)
    else:
      raise HttpError(HTTPStatus.BAD_REQUEST, "which must be controller|caddy", code="invalid_logs")
    lines = tail_file(path, max_lines=tail)
    return _json_response(
      HTTPStatus.OK,
      {"which": which, "path": str(path), "lines": lines},
    )

  def sync_handler(_request: _Request) -> _Response:
    _require_readwrite(ctx)
    return _json_response(HTTPStatus.OK, trigger_sync_now(ctx))

  def nodes_handler(request: _Request) -> _Response:
    # Default: skip the heavy node_status query and let the frontend
    # ask /api/node-statuses separately. ?with_status=1 keeps the legacy
    # combined response for any client that needs it.
    qs = parse_qs(urlsplit(request.path).query) if request.path else {}
    with_status_q = (qs.get("with_status", [""])[0] or "").lower()
    with_status = with_status_q in ("1", "true", "yes")
    return _json_response(HTTPStatus.OK, {"nodes": list_nodes(ctx, with_status=with_status)})

  def node_statuses_handler(_request: _Request) -> _Response:
    """Standalone status feed used by the Nodes view to populate badges
    after the row skeleton has already rendered."""
    statuses = ctx.database.list_node_statuses()
    return _json_response(HTTPStatus.OK, {
      "statuses": {name: _node_status_to_dict(s) for name, s in statuses.items()},
    })

  def init_status_bulk_handler(request: _Request) -> _Response:
    """POST {"nodes": ["a", "b", ...]} → per-node init summary."""
    payload = request.json_body() if request.body else {}
    raw = payload.get("nodes")
    if not isinstance(raw, list):
      raise HttpError(HTTPStatus.BAD_REQUEST, "nodes must be a list", code="nodes_required")
    return _json_response(HTTPStatus.OK, {"status": init_status_bulk(ctx, raw)})

  def create_node_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.CREATED, create_node(ctx, request.json_body()))

  def node_detail_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, get_node_detail(ctx, request.path_params["name"]))

  def node_patch_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK, update_node(ctx, request.path_params["name"], request.json_body())
    )

  def node_delete_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, delete_node(ctx, request.path_params["name"]))

  def node_probe_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, probe_node_action(ctx, request.path_params["name"]))

  def node_deploy_handler(request: _Request) -> _Response:
    payload = request.json_body() if request.body else {}
    return _json_response(
      HTTPStatus.OK, deploy_node_action(ctx, request.path_params["name"], payload)
    )

  def node_deploy_service_handler(request: _Request) -> _Response:
    payload = request.json_body() if request.body else {}
    return _json_response(
      HTTPStatus.OK, deploy_node_service(ctx, request.path_params["name"], payload)
    )

  def node_update_handler(request: _Request) -> _Response:
    payload = request.json_body() if request.body else {}
    return _json_response(
      HTTPStatus.OK, update_node_action(ctx, request.path_params["name"], payload)
    )

  def node_run_handler(request: _Request) -> _Response:
    payload = request.json_body() if request.body else {}
    return _json_response(
      HTTPStatus.OK, run_node_command_action(ctx, request.path_params["name"], payload)
    )

  def host_ssh_keys_handler(_request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, {"keys": list_host_ssh_keys(ctx)})

  def host_ssh_keys_read_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, read_host_ssh_key(ctx, request.json_body()))

  def init_start_handler(request: _Request) -> _Response:
    payload = request.json_body() if request.body else {}
    return _json_response(HTTPStatus.ACCEPTED, start_init_run(ctx, request.path_params["name"], payload))

  def init_get_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK,
      get_init_run(ctx, request.path_params["name"], int(request.path_params["run_id"])),
    )

  def init_list_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK,
      {"runs": list_init_runs(ctx, request.path_params["name"])},
    )

  def services_list_handler(_request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, {"services": list_services(ctx)})

  def service_create_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.CREATED, create_service(ctx, request.json_body()))

  def service_get_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, get_service_detail(ctx, request.path_params["name"]))

  def service_patch_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, update_service(ctx, request.path_params["name"], request.json_body()))

  def service_delete_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, delete_service(ctx, request.path_params["name"]))

  router.add("GET", "/api/status", with_auth(overview_handler))
  router.add("GET", "/api/overview", with_auth(overview_handler))
  router.add("GET", "/api/routes", with_auth(list_routes_handler))
  router.add("POST", "/api/routes", with_auth(create_route_handler))
  router.add("GET", "/api/routes/{domain}", with_auth(route_detail_handler))
  router.add("PATCH", "/api/routes/{domain}", with_auth(route_patch_handler))
  router.add("DELETE", "/api/routes/{domain}", with_auth(route_delete_handler))
  router.add("POST", "/api/routes/{domain}/enable", with_auth(route_enable_handler))
  router.add("POST", "/api/routes/{domain}/disable", with_auth(route_disable_handler))
  router.add("POST", "/api/routes/{domain}/clear-retry", with_auth(clear_retry_handler))
  router.add("GET", "/api/certificates", with_auth(certificates_handler))
  router.add("GET", "/api/certificates/{domain}", with_auth(certificate_detail_handler))
  router.add("GET", "/api/zones", with_auth(zones_handler))
  router.add("POST", "/api/zones", with_auth(upsert_zone_handler))
  router.add("DELETE", "/api/zones/{zone_name}", with_auth(delete_zone_handler))
  router.add("GET", "/api/logs", with_auth(logs_handler))
  router.add("POST", "/api/sync", with_auth(sync_handler))
  router.add("GET", "/api/nodes", with_auth(nodes_handler))
  router.add("GET", "/api/node-statuses", with_auth(node_statuses_handler))
  router.add("POST", "/api/nodes/init-status-bulk", with_auth(init_status_bulk_handler))
  router.add("POST", "/api/nodes", with_auth(create_node_handler))
  router.add("GET", "/api/nodes/{name}", with_auth(node_detail_handler))
  router.add("PATCH", "/api/nodes/{name}", with_auth(node_patch_handler))
  router.add("DELETE", "/api/nodes/{name}", with_auth(node_delete_handler))
  router.add("POST", "/api/nodes/{name}/probe", with_auth(node_probe_handler))
  router.add("POST", "/api/nodes/{name}/deploy", with_auth(node_deploy_handler))
  router.add("POST", "/api/nodes/{name}/deploy-service", with_auth(node_deploy_service_handler))
  router.add("POST", "/api/nodes/{name}/update", with_auth(node_update_handler))
  router.add("POST", "/api/nodes/{name}/run", with_auth(node_run_handler))
  router.add("GET", "/api/host/ssh-keys", with_auth(host_ssh_keys_handler))
  router.add("POST", "/api/host/ssh-keys/read", with_auth(host_ssh_keys_read_handler))
  router.add("POST", "/api/nodes/{name}/init/start", with_auth(init_start_handler))
  router.add("GET", "/api/nodes/{name}/init/runs", with_auth(init_list_handler))
  router.add("GET", "/api/nodes/{name}/init/runs/{run_id}", with_auth(init_get_handler))
  def service_manifest_handler(request: _Request) -> _Response:
    body = request.json_body() if request.body else {}
    save = bool(body.get("save", True))
    return _json_response(HTTPStatus.OK,
                          fetch_service_manifest(ctx, request.path_params["name"], save=save))

  def service_deploy_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK,
      deploy_service_to_nodes(ctx, request.path_params["name"], request.json_body()),
    )

  def service_deployments_handler(request: _Request) -> _Response:
    limit = max(1, min(request.query_int("limit", 50), 500))
    return _json_response(HTTPStatus.OK, {
      "deployments": list_service_deployments(
        ctx, service_name=request.path_params["name"], limit=limit,
      ),
      "states": list_service_node_states(ctx, service_name=request.path_params["name"]),
    })

  def services_summary_handler(_request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, {"services": services_summary(ctx)})

  def service_nodes_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, {
      "service": request.path_params["name"],
      "states": list_service_node_status(ctx, request.path_params["name"]),
    })

  def service_refresh_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK,
                          refresh_service_nodes(ctx, request.path_params["name"]))

  router.add("GET", "/api/services-summary", with_auth(services_summary_handler))
  router.add("GET", "/api/services/{name}/nodes", with_auth(service_nodes_handler))
  router.add("POST", "/api/services/{name}/refresh", with_auth(service_refresh_handler))
  router.add("GET", "/api/services", with_auth(services_list_handler))
  router.add("POST", "/api/services", with_auth(service_create_handler))
  router.add("GET", "/api/services/{name}", with_auth(service_get_handler))
  router.add("PATCH", "/api/services/{name}", with_auth(service_patch_handler))
  router.add("DELETE", "/api/services/{name}", with_auth(service_delete_handler))
  router.add("POST", "/api/services/{name}/manifest", with_auth(service_manifest_handler))
  router.add("POST", "/api/services/{name}/deploy", with_auth(service_deploy_handler))
  router.add("GET", "/api/services/{name}/deployments", with_auth(service_deployments_handler))

  # Static IP endpoints ---------------------------------------------
  def static_ips_list_handler(request: _Request) -> _Response:
    sort = request.query_str("sort", "country") or "country"
    return _json_response(HTTPStatus.OK, {"static_ips": list_static_ips(ctx, sort=sort)})

  def static_ips_create_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.CREATED, create_static_ip(ctx, request.json_body()))

  def static_ips_parse_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, parse_bulk_static_ips(ctx, request.json_body()))

  def static_ips_test_all_handler(_request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, run_ip_test_all(ctx))

  def static_ip_get_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK, get_static_ip_detail(ctx, int(request.path_params["id"]))
    )

  def static_ip_patch_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK,
      update_static_ip_record(ctx, int(request.path_params["id"]), request.json_body()),
    )

  def static_ip_delete_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK, delete_static_ip_record(ctx, int(request.path_params["id"]))
    )

  def static_ip_test_handler(request: _Request) -> _Response:
    payload = request.json_body() if request.body else {}
    kind = (payload.get("kind") or "connectivity")
    return _json_response(
      HTTPStatus.OK, run_ip_connectivity_test(ctx, int(request.path_params["id"]), kind=kind)
    )

  def static_ip_probe_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK, run_ip_static_probe(ctx, int(request.path_params["id"]))
    )

  def static_ip_results_handler(request: _Request) -> _Response:
    limit = max(1, min(request.query_int("limit", 50), 500))
    return _json_response(
      HTTPStatus.OK,
      {"results": list_ip_test_results_action(ctx, int(request.path_params["id"]), limit=limit)},
    )

  def system_config_list_handler(_request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, {"config": list_system_config(ctx)})

  def system_config_get_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK, get_system_config(ctx, request.path_params["key"])
    )

  def system_config_put_handler(request: _Request) -> _Response:
    return _json_response(
      HTTPStatus.OK,
      upsert_system_config(ctx, request.path_params["key"], request.json_body()),
    )

  router.add("GET", "/api/system-config", with_auth(system_config_list_handler))
  router.add("GET", "/api/system-config/{key}", with_auth(system_config_get_handler))
  router.add("PUT", "/api/system-config/{key}", with_auth(system_config_put_handler))

  # SSH key endpoints ------------------------------------------------
  def ssh_keys_list_handler(_request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, {"ssh_keys": list_ssh_keys(ctx)})

  def ssh_keys_create_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.CREATED, create_ssh_key(ctx, request.json_body()))

  def ssh_key_get_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK,
                          get_ssh_key_detail(ctx, int(request.path_params["id"])))

  def ssh_key_patch_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK,
                          update_ssh_key_record(ctx, int(request.path_params["id"]),
                                                request.json_body()))

  def ssh_key_delete_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK,
                          delete_ssh_key_record(ctx, int(request.path_params["id"])))

  def ssh_key_regenerate_handler(request: _Request) -> _Response:
    payload = request.json_body() if request.body else {}
    return _json_response(HTTPStatus.OK,
                          regenerate_ssh_key(ctx, int(request.path_params["id"]), payload))

  def ssh_key_attach_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK,
                          attach_ssh_key_to_node(ctx, int(request.path_params["id"]),
                                                  request.json_body()))

  def ssh_key_deploy_handler(request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK,
                          deploy_ssh_key_to_nodes(ctx, int(request.path_params["id"]),
                                                  request.json_body()))

  def ssh_key_apply_local_handler(request: _Request) -> _Response:
    payload = request.json_body() if request.body else {}
    return _json_response(HTTPStatus.OK,
                          apply_ssh_key_to_local(ctx, int(request.path_params["id"]), payload))

  router.add("GET", "/api/ssh-keys", with_auth(ssh_keys_list_handler))
  router.add("POST", "/api/ssh-keys", with_auth(ssh_keys_create_handler))
  router.add("GET", "/api/ssh-keys/{id}", with_auth(ssh_key_get_handler))
  router.add("PATCH", "/api/ssh-keys/{id}", with_auth(ssh_key_patch_handler))
  router.add("DELETE", "/api/ssh-keys/{id}", with_auth(ssh_key_delete_handler))
  router.add("POST", "/api/ssh-keys/{id}/regenerate", with_auth(ssh_key_regenerate_handler))
  router.add("POST", "/api/ssh-keys/{id}/attach", with_auth(ssh_key_attach_handler))
  router.add("POST", "/api/ssh-keys/{id}/deploy", with_auth(ssh_key_deploy_handler))
  router.add("POST", "/api/ssh-keys/{id}/apply-local", with_auth(ssh_key_apply_local_handler))

  router.add("GET", "/api/static-ips", with_auth(static_ips_list_handler))
  router.add("POST", "/api/static-ips", with_auth(static_ips_create_handler))
  router.add("POST", "/api/static-ips/parse", with_auth(static_ips_parse_handler))
  router.add("POST", "/api/static-ips/test-all", with_auth(static_ips_test_all_handler))
  router.add("GET", "/api/static-ips/{id}", with_auth(static_ip_get_handler))
  router.add("PATCH", "/api/static-ips/{id}", with_auth(static_ip_patch_handler))
  router.add("DELETE", "/api/static-ips/{id}", with_auth(static_ip_delete_handler))
  router.add("POST", "/api/static-ips/{id}/test", with_auth(static_ip_test_handler))
  router.add("POST", "/api/static-ips/{id}/probe", with_auth(static_ip_probe_handler))
  router.add("GET", "/api/static-ips/{id}/results", with_auth(static_ip_results_handler))

  return router


# ---------------------------------------------------------------------------
# HTTP server plumbing
# ---------------------------------------------------------------------------


_STATIC_MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
}


def _static_response(static_dir: Path, relative_path: str) -> _Response | None:
  if not static_dir.exists():
    return None
  if relative_path in ("", "/"):
    relative_path = "index.html"
  relative_path = relative_path.lstrip("/")
  # security: do not allow path traversal
  if ".." in relative_path.split("/"):
    raise HttpError(HTTPStatus.BAD_REQUEST, "invalid path", code="invalid_path")
  candidate = (static_dir / relative_path).resolve()
  try:
    candidate.relative_to(static_dir.resolve())
  except ValueError as exc:
    raise HttpError(HTTPStatus.BAD_REQUEST, "invalid path", code="invalid_path") from exc
  if candidate.is_dir():
    candidate = candidate / "index.html"
  if not candidate.exists() or not candidate.is_file():
    return None
  suffix = candidate.suffix.lower()
  mime = _STATIC_MIME_TYPES.get(suffix, "application/octet-stream")
  data = candidate.read_bytes()
  return _Response(
    status=HTTPStatus.OK,
    body=data,
    headers={"Content-Type": mime, "Cache-Control": "no-cache"},
  )


def _build_auth_checker(token: str) -> Callable[[_Request], bool]:
  expected = token.strip()

  def check(request: _Request) -> bool:
    if not expected:
      return False
    header_token = request.headers.get("authorization", "")
    if header_token.lower().startswith("bearer "):
      provided = header_token[7:].strip()
    else:
      provided = request.headers.get("x-admin-token", "").strip()
      if not provided and "token" in request.query:
        provided = (request.query["token"][0] or "").strip()
    if not provided:
      return False
    return hmac.compare_digest(provided, expected)

  return check


def _make_handler_class(
  router: _Router,
  *,
  token: str,
  static_dir: Path,
) -> type[BaseHTTPRequestHandler]:
  auth_check = _build_auth_checker(token)

  class _Handler(BaseHTTPRequestHandler):
    server_version = "ssl-service-admin/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003 — BaseHTTPRequestHandler signature
      LOGGER.info("admin %s - %s", self.address_string(), format % args)

    def _send_response(self, response: _Response) -> None:
      headers = dict(response.headers or {})
      headers.setdefault("Content-Length", str(len(response.body)))
      headers.setdefault("X-Content-Type-Options", "nosniff")
      self.send_response(response.status)
      for name, value in headers.items():
        self.send_header(name, value)
      self.end_headers()
      if self.command != "HEAD":
        self.wfile.write(response.body)

    def _read_body(self) -> bytes:
      length = int(self.headers.get("Content-Length", "0") or "0")
      if length <= 0:
        return b""
      return self.rfile.read(length)

    def _build_request(self) -> _Request:
      parsed = urlsplit(self.path)
      headers = {k.lower(): v for k, v in self.headers.items()}
      return _Request(
        method=self.command,
        path=parsed.path,
        query=parse_qs(parsed.query, keep_blank_values=True),
        headers=headers,
        body=self._read_body(),
        path_params={},
      )

    def _dispatch(self) -> None:
      try:
        request = self._build_request()
        # Serve static files for non /api paths on GET/HEAD
        if not request.path.startswith("/api/"):
          if self.command in ("GET", "HEAD"):
            static = _static_response(static_dir, request.path)
            if static is not None:
              self._send_response(static)
              return
            # fallback to index for SPA
            index_response = _static_response(static_dir, "/")
            if index_response is not None:
              self._send_response(index_response)
              return
          self._send_response(_error_response(HttpError(HTTPStatus.NOT_FOUND, "not found")))
          return

        # Auth required for /api/*
        if not auth_check(request):
          self._send_response(
            _error_response(HttpError(HTTPStatus.UNAUTHORIZED, "missing or invalid token", code="unauthorized"))
          )
          return

        resolved = router.resolve(request.method, request.path)
        if resolved is None:
          self._send_response(_error_response(HttpError(HTTPStatus.NOT_FOUND, "not found")))
          return
        handler, params = resolved
        request.path_params = params
        response = handler(request)
      except HttpError as exc:
        response = _error_response(exc)
      except Exception as exc:  # noqa: BLE001
        LOGGER.exception("admin handler failed")
        response = _error_response(
          HttpError(HTTPStatus.INTERNAL_SERVER_ERROR, f"internal error: {exc}", code="internal_error")
        )
      self._send_response(response)

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler contract
      self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
      self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
      self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
      self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
      self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
      self._dispatch()

  return _Handler


def build_application(ctx: AdminContext) -> tuple[_Router, Path]:
  """Return the internal router and static directory for a given context.

  Exposed for tests and in-process programmatic access.
  """

  return _build_router(ctx), STATIC_DIR


class AdminServer:
  def __init__(self, config: AppConfig, database: Database) -> None:
    self._ctx = AdminContext(config=config, database=database)
    self._router, self._static_dir = build_application(self._ctx)
    self._server: ThreadingHTTPServer | None = None
    self._thread: threading.Thread | None = None

  @property
  def context(self) -> AdminContext:
    return self._ctx

  def start(self) -> None:
    if self._server is not None:
      return
    handler_class = _make_handler_class(
      self._router,
      token=self._ctx.config.admin.token,
      static_dir=self._static_dir,
    )
    bind = self._ctx.config.admin.bind or "127.0.0.1"
    port = self._ctx.config.admin.port
    self._server = ThreadingHTTPServer((bind, port), handler_class)
    LOGGER.info("admin server listening on %s:%s", bind, port)
    thread = threading.Thread(target=self._server.serve_forever, name="ssl-service-admin", daemon=True)
    self._thread = thread
    thread.start()

  def stop(self) -> None:
    server = self._server
    if server is None:
      return
    server.shutdown()
    server.server_close()
    if self._thread is not None:
      self._thread.join(timeout=5)
    self._server = None
    self._thread = None
    LOGGER.info("admin server stopped")


__all__ = [
  "AdminContext",
  "AdminServer",
  "HttpError",
  "build_application",
  "build_overview",
  "create_route",
  "delete_route",
  "delete_zone",
  "get_route_detail",
  "list_routes_summary",
  "list_zones",
  "tail_file",
  "trigger_sync_now",
  "update_route",
  "upsert_zone",
]
