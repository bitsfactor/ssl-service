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
  LB_POLICIES,
  NODE_AUTH_METHODS,
  CertificateRecord,
  Database,
  DnsZoneTokenRecord,
  NodeInitRunRecord,
  NodeRecord,
  NodeStatusRecord,
  RouteRecord,
  ServiceRecord,
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
  routes = ctx.database.list_routes()
  certificates = ctx.database.fetch_certificates()
  zones = ctx.database.list_dns_zone_tokens()
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


def _node_status_to_dict(status: NodeStatusRecord | None) -> dict[str, Any] | None:
  if status is None:
    return None
  return {
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


def list_nodes(ctx: AdminContext) -> list[dict[str, Any]]:
  records = ctx.database.list_nodes()
  statuses = ctx.database.list_node_statuses()
  out: list[dict[str, Any]] = []
  for node in records:
    item = _node_to_dict(node)
    item["status"] = _node_status_to_dict(statuses.get(node.name))
    out.append(item)
  return out


def get_node_detail(ctx: AdminContext, name: str) -> dict[str, Any]:
  name = _normalize_node_name(name)
  node = ctx.database.get_node(name)
  if node is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  item = _node_to_dict(node)
  item["status"] = _node_status_to_dict(ctx.database.get_node_status(name))
  return item


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
  if auth_method == "password" and not password:
    raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_password is required for password auth", code="password_required")
  if auth_method == "key" and not private_key:
    raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_private_key is required for key auth", code="private_key_required")

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
  LOGGER.info("admin.create_node name=%s host=%s auth=%s", name, host, auth_method)
  return _node_to_dict(inserted)


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
  if effective_auth == "password" and not effective_pwd:
    raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_password is required for password auth", code="password_required")
  if effective_auth == "key" and not effective_key:
    raise HttpError(HTTPStatus.BAD_REQUEST, "ssh_private_key is required for key auth", code="private_key_required")

  updated = ctx.database.update_node(name, patch)
  if updated is None:
    raise HttpError(HTTPStatus.NOT_FOUND, f"node not found: {name}", code="node_not_found")
  LOGGER.info("admin.update_node name=%s fields=%s", name, sorted(patch.keys()))
  return _node_to_dict(updated)


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
  status = nodes_mod.probe_node(node)
  ctx.database.upsert_node_status(status)
  LOGGER.info("admin.probe_node name=%s reachable=%s err=%s", name, status.reachable, status.last_probe_error or "")
  return _node_status_to_dict(status) or {}


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
    result = nodes_mod.run_command(node, command, timeout=900.0)
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
    result = nodes_mod.deploy_service(node, override_command=override)
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
    result = nodes_mod.update_service(node, override_command=override)
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
    result = nodes_mod.run_command(node, command, timeout=float(payload.get("timeout") or 60))
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

  def nodes_handler(_request: _Request) -> _Response:
    return _json_response(HTTPStatus.OK, {"nodes": list_nodes(ctx)})

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
  router.add("GET", "/api/services", with_auth(services_list_handler))
  router.add("POST", "/api/services", with_auth(service_create_handler))
  router.add("GET", "/api/services/{name}", with_auth(service_get_handler))
  router.add("PATCH", "/api/services/{name}", with_auth(service_patch_handler))
  router.add("DELETE", "/api/services/{name}", with_auth(service_delete_handler))

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
