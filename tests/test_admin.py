from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ssl_proxy_controller.admin import (
  AdminContext,
  HttpError,
  _normalize_domain,
  _normalize_upstream_target,
  build_overview,
  create_route,
  delete_route,
  delete_zone,
  get_route_detail,
  list_routes_summary,
  list_zones,
  tail_file,
  update_route,
  upsert_zone,
)
from ssl_proxy_controller.config import (
  AcmeConfig,
  AdminConfig,
  AppConfig,
  CaddyConfig,
  LoggingConfig,
  PathsConfig,
  PostgresConfig,
  SyncConfig,
)
from ssl_proxy_controller.db import (
  LB_POLICIES,
  NODE_AUTH_METHODS,
  CertificateRecord,
  DnsZoneTokenRecord,
  NodeInitRunRecord,
  NodeRecord,
  NodeStatusRecord,
  RouteRecord,
  ServiceRecord,
  UpstreamRecord,
)


class FakeDatabase:
  """In-memory stand-in for the `Database` interface used by admin tests."""

  def __init__(self) -> None:
    self.routes: dict[str, RouteRecord] = {}
    self.certificates: dict[str, CertificateRecord] = {}
    self.zones: dict[str, DnsZoneTokenRecord] = {}
    self.nodes: dict[str, NodeRecord] = {}
    self.node_statuses: dict[str, NodeStatusRecord] = {}
    self.init_runs: dict[int, NodeInitRunRecord] = {}
    self._init_run_seq: int = 0
    self.services: dict[str, ServiceRecord] = {}

  # routes
  def list_routes(self) -> list[RouteRecord]:
    return sorted(self.routes.values(), key=lambda r: r.domain)

  def get_route(self, domain: str) -> RouteRecord | None:
    return self.routes.get(domain)

  def insert_route(
    self,
    domain: str,
    upstream_target: str | None,
    enabled: bool = True,
    *,
    upstreams: list[UpstreamRecord] | None = None,
    lb_policy: str = "random",
  ) -> RouteRecord:
    if upstreams:
      ups = list(upstreams)
      primary = ups[0].target
    elif upstream_target is not None:
      ups = [UpstreamRecord(target=upstream_target, weight=1)]
      primary = upstream_target
    else:
      ups = []
      primary = None
    record = RouteRecord(
      domain=domain,
      upstream_target=primary,
      enabled=enabled,
      updated_at=datetime.now(tz=UTC),
      upstreams=ups,
      lb_policy=lb_policy,
    )
    self.routes[domain] = record
    return record

  def update_route_target(self, domain: str, upstream_target: str | None) -> bool:
    ups = (
      [UpstreamRecord(target=upstream_target, weight=1)] if upstream_target else []
    )
    return self.replace_route_upstreams(domain, ups)

  def replace_route_upstreams(
    self, domain: str, upstreams: list[UpstreamRecord]
  ) -> bool:
    if domain not in self.routes:
      return False
    current = self.routes[domain]
    self.routes[domain] = RouteRecord(
      domain=current.domain,
      upstream_target=(upstreams[0].target if upstreams else None),
      enabled=current.enabled,
      updated_at=datetime.now(tz=UTC),
      upstreams=list(upstreams),
      lb_policy=current.lb_policy,
    )
    return True

  def set_route_lb_policy(self, domain: str, lb_policy: str) -> bool:
    if domain not in self.routes:
      return False
    if lb_policy not in LB_POLICIES:
      raise ValueError(f"invalid lb_policy: {lb_policy}")
    current = self.routes[domain]
    self.routes[domain] = RouteRecord(
      domain=current.domain,
      upstream_target=current.upstream_target,
      enabled=current.enabled,
      updated_at=datetime.now(tz=UTC),
      upstreams=list(current.upstreams or []),
      lb_policy=lb_policy,
    )
    return True

  def set_route_enabled(self, domain: str, enabled: bool) -> bool:
    if domain not in self.routes:
      return False
    current = self.routes[domain]
    self.routes[domain] = RouteRecord(
      domain=current.domain,
      upstream_target=current.upstream_target,
      enabled=enabled,
      updated_at=datetime.now(tz=UTC),
      upstreams=list(current.upstreams or []),
      lb_policy=current.lb_policy,
    )
    return True

  def delete_route(self, domain: str) -> bool:
    if domain in self.certificates:
      raise RuntimeError("foreign key: certificate exists")
    return self.routes.pop(domain, None) is not None

  def purge_route(self, domain: str) -> bool:
    self.certificates.pop(domain, None)
    return self.routes.pop(domain, None) is not None

  # certificates
  def fetch_certificates(self) -> dict[str, CertificateRecord]:
    return dict(self.certificates)

  def clear_certificate_retry_after(self, domain: str) -> bool:
    cert = self.certificates.get(domain)
    if cert is None:
      return False
    self.certificates[domain] = CertificateRecord(
      domain=cert.domain,
      fullchain_pem=cert.fullchain_pem,
      private_key_pem=cert.private_key_pem,
      not_before=cert.not_before,
      not_after=cert.not_after,
      version=cert.version,
      status=cert.status,
      source=cert.source,
      retry_after=None,
      updated_at=datetime.now(tz=UTC),
      last_error=cert.last_error,
    )
    return True

  # zones
  def list_dns_zone_tokens(self) -> list[DnsZoneTokenRecord]:
    return sorted(self.zones.values(), key=lambda z: z.zone_name)

  def upsert_dns_zone_token(
    self,
    zone_name: str,
    zone_id: str,
    api_token: str,
    provider: str = "cloudflare",
  ) -> DnsZoneTokenRecord:
    record = DnsZoneTokenRecord(
      zone_name=zone_name,
      provider=provider,
      zone_id=zone_id,
      api_token=api_token,
      updated_at=datetime.now(tz=UTC),
    )
    self.zones[zone_name] = record
    return record

  def delete_dns_zone_token(self, zone_name: str) -> bool:
    return self.zones.pop(zone_name, None) is not None

  # nodes ----------------------------------------------------------------
  def list_nodes(self) -> list[NodeRecord]:
    return sorted(self.nodes.values(), key=lambda n: n.name)

  def get_node(self, name: str) -> NodeRecord | None:
    return self.nodes.get(name)

  def insert_node(self, node: NodeRecord) -> NodeRecord:
    if node.auth_method not in NODE_AUTH_METHODS:
      raise ValueError(f"invalid auth_method: {node.auth_method}")
    if node.name in self.nodes:
      raise RuntimeError(f"duplicate node: {node.name}")
    self.nodes[node.name] = node
    return node

  def update_node(self, name: str, fields: dict) -> NodeRecord | None:
    existing = self.nodes.get(name)
    if existing is None:
      return None
    data = {f: getattr(existing, f) for f in (
      "name", "host", "ssh_port", "ssh_user", "auth_method",
      "ssh_password", "ssh_private_key", "ssh_key_passphrase",
      "description", "tags", "deploy_command", "update_command",
      "created_at", "updated_at",
      "init_git_private_key", "init_git_user_name", "init_git_user_email",
      "init_desired_ssh_port", "init_install_codex",
      "init_codex_base_url", "init_codex_api_key", "init_timezone",
    )}
    for k, v in fields.items():
      if k in data:
        data[k] = v
    data["updated_at"] = datetime.now(tz=UTC)
    if data["auth_method"] not in NODE_AUTH_METHODS:
      raise ValueError(f"invalid auth_method: {data['auth_method']}")
    self.nodes[name] = NodeRecord(**data)
    return self.nodes[name]

  def delete_node(self, name: str) -> bool:
    self.node_statuses.pop(name, None)
    return self.nodes.pop(name, None) is not None

  def rename_node(self, current_name: str, new_name: str) -> NodeRecord | None:
    existing = self.nodes.pop(current_name, None)
    if existing is None:
      return None
    existing.name = new_name
    existing.updated_at = datetime.now(tz=UTC)
    self.nodes[new_name] = existing
    # Cascade: child tables follow.
    status = self.node_statuses.pop(current_name, None)
    if status is not None:
      status.node_name = new_name
      self.node_statuses[new_name] = status
    for run in self.init_runs.values():
      if run.node_name == current_name:
        run.node_name = new_name
    return existing

  def get_node_status(self, name: str) -> NodeStatusRecord | None:
    return self.node_statuses.get(name)

  def list_node_statuses(self) -> dict[str, NodeStatusRecord]:
    return dict(self.node_statuses)

  def upsert_node_status(self, status: NodeStatusRecord) -> NodeStatusRecord:
    self.node_statuses[status.node_name] = status
    return status

  # init runs ------------------------------------------------------------
  def insert_init_run(self, node_name: str, config_snapshot: dict | None = None) -> NodeInitRunRecord:
    self._init_run_seq += 1
    rec = NodeInitRunRecord(
      id=self._init_run_seq,
      node_name=node_name,
      status="queued",
      current_step=None,
      log_text="",
      exit_code=None,
      started_at=datetime.now(tz=UTC),
      finished_at=None,
      config_snapshot=config_snapshot,
    )
    self.init_runs[rec.id] = rec
    return rec

  def get_init_run(self, run_id: int) -> NodeInitRunRecord | None:
    return self.init_runs.get(int(run_id))

  def list_init_runs(self, node_name: str, limit: int = 20) -> list[NodeInitRunRecord]:
    return sorted(
      [r for r in self.init_runs.values() if r.node_name == node_name],
      key=lambda r: r.started_at, reverse=True,
    )[:limit]

  def update_init_run(self, run_id: int, *, status=None, current_step=None,
                      append_log=None, exit_code=None, finished=False) -> None:
    rec = self.init_runs.get(int(run_id))
    if rec is None:
      return
    if status is not None:
      rec.status = status
    if current_step is not None:
      rec.current_step = current_step
    if append_log:
      rec.log_text = (rec.log_text or "") + append_log
    if exit_code is not None:
      rec.exit_code = exit_code
    if finished:
      rec.finished_at = datetime.now(tz=UTC)

  # services -------------------------------------------------------------
  def list_services(self) -> list[ServiceRecord]:
    return sorted(self.services.values(), key=lambda s: s.name)

  def get_service(self, name: str) -> ServiceRecord | None:
    return self.services.get(name)

  def insert_service(self, service: ServiceRecord) -> ServiceRecord:
    if service.name in self.services:
      raise RuntimeError(f"duplicate service: {service.name}")
    self.services[service.name] = service
    return service

  def update_service(self, name: str, fields: dict) -> ServiceRecord | None:
    s = self.services.get(name)
    if s is None:
      return None
    for k, v in fields.items():
      if hasattr(s, k):
        # Handle both default_env (dict) and config_files (dict) the same way
        setattr(s, k, v)
    s.updated_at = datetime.now(tz=UTC)
    return s

  def delete_service(self, name: str) -> bool:
    return self.services.pop(name, None) is not None


def make_config(mode: str = "readwrite") -> AppConfig:
  return AppConfig(
    mode=mode,
    postgres=PostgresConfig(dsn="postgresql://example"),
    sync=SyncConfig(),
    paths=PathsConfig(state_dir=Path("/tmp/state"), log_dir=Path("/tmp/log")),
    caddy=CaddyConfig(reload_command=["/usr/bin/true"]),
    acme=AcmeConfig(email="ops@example.com"),
    logging=LoggingConfig(),
    admin=AdminConfig(enabled=True, token="t"),
  )


def make_context(mode: str = "readwrite", database: FakeDatabase | None = None) -> AdminContext:
  return AdminContext(config=make_config(mode), database=database or FakeDatabase())


def test_normalize_domain_strips_and_lowercases() -> None:
  assert _normalize_domain("  API.Example.COM.  ") == "api.example.com"


def test_normalize_domain_rejects_wildcard() -> None:
  with pytest.raises(HttpError, match="wildcard"):
    _normalize_domain("*.example.com")


def test_normalize_domain_rejects_empty() -> None:
  with pytest.raises(HttpError, match="required"):
    _normalize_domain("")


def test_normalize_upstream_target_accepts_bare_port() -> None:
  assert _normalize_upstream_target("6111") == "127.0.0.1:6111"


def test_normalize_upstream_target_accepts_host_port() -> None:
  assert _normalize_upstream_target("127.0.0.1:6111") == "127.0.0.1:6111"
  assert _normalize_upstream_target("backend.internal:6111") == "backend.internal:6111"


def test_normalize_upstream_target_accepts_empty_as_none() -> None:
  assert _normalize_upstream_target(None) is None
  assert _normalize_upstream_target("") is None


def test_normalize_upstream_target_rejects_bad_input() -> None:
  with pytest.raises(HttpError, match="upstream"):
    _normalize_upstream_target("not a target")


def test_create_route_creates_row() -> None:
  ctx = make_context()
  result = create_route(ctx, {"domain": "api.example.com", "upstream_target": "6111"})
  assert result["domain"] == "api.example.com"
  assert result["upstream_target"] == "127.0.0.1:6111"
  assert result["enabled"] is True
  assert "api.example.com" in ctx.database.routes


def test_create_route_conflicts_on_existing() -> None:
  ctx = make_context()
  create_route(ctx, {"domain": "api.example.com", "upstream_target": "6111"})
  with pytest.raises(HttpError) as err:
    create_route(ctx, {"domain": "api.example.com", "upstream_target": "6112"})
  assert err.value.status == 409


def test_create_route_requires_readwrite() -> None:
  ctx = make_context(mode="readonly")
  with pytest.raises(HttpError) as err:
    create_route(ctx, {"domain": "api.example.com", "upstream_target": "6111"})
  assert err.value.status == 403


def test_update_route_changes_target_and_enabled() -> None:
  ctx = make_context()
  create_route(ctx, {"domain": "api.example.com", "upstream_target": "6111"})
  updated = update_route(ctx, "api.example.com", {"upstream_target": "10.0.0.5:6111", "enabled": False})
  assert updated["upstream_target"] == "10.0.0.5:6111"
  assert updated["enabled"] is False


def test_update_route_404_when_missing() -> None:
  ctx = make_context()
  with pytest.raises(HttpError) as err:
    update_route(ctx, "missing.example.com", {"enabled": False})
  assert err.value.status == 404


def test_create_route_accepts_multiple_upstreams_and_lb_policy() -> None:
  ctx = make_context()
  result = create_route(
    ctx,
    {
      "domain": "balanced.example.com",
      "upstreams": [
        {"target": "10.0.0.10:6111", "weight": 1},
        {"target": "10.0.0.11:6111", "weight": 1},
        {"target": "10.0.0.12:6111", "weight": 2},
      ],
      "lb_policy": "ip_hash",
    },
  )
  assert result["lb_policy"] == "ip_hash"
  assert len(result["upstreams"]) == 3
  assert result["upstreams"][0] == {"target": "10.0.0.10:6111", "weight": 1}
  assert result["upstream_target"] == "10.0.0.10:6111"
  stored = ctx.database.routes["balanced.example.com"]
  assert stored.lb_policy == "ip_hash"
  assert [u.target for u in stored.upstreams] == [
    "10.0.0.10:6111",
    "10.0.0.11:6111",
    "10.0.0.12:6111",
  ]


def test_create_route_rejects_non_random_policy_with_single_upstream() -> None:
  ctx = make_context()
  with pytest.raises(HttpError) as err:
    create_route(
      ctx,
      {
        "domain": "bad.example.com",
        "upstreams": [{"target": "10.0.0.10:6111", "weight": 1}],
        "lb_policy": "ip_hash",
      },
    )
  assert err.value.status == 400


def test_create_route_rejects_unknown_lb_policy() -> None:
  ctx = make_context()
  with pytest.raises(HttpError) as err:
    create_route(
      ctx,
      {
        "domain": "bad.example.com",
        "upstream_target": "10.0.0.10:6111",
        "lb_policy": "magic",
      },
    )
  assert err.value.status == 400


def test_update_route_replaces_upstreams_and_changes_policy() -> None:
  ctx = make_context()
  create_route(ctx, {"domain": "api.example.com", "upstream_target": "10.0.0.10:6111"})
  updated = update_route(
    ctx,
    "api.example.com",
    {
      "upstreams": [
        {"target": "10.0.0.20:6111"},
        {"target": "10.0.0.21:6111"},
      ],
      "lb_policy": "round_robin",
    },
  )
  assert updated["lb_policy"] == "round_robin"
  assert [u["target"] for u in updated["upstreams"]] == ["10.0.0.20:6111", "10.0.0.21:6111"]
  assert updated["upstream_target"] == "10.0.0.20:6111"


def test_update_route_rejects_non_random_policy_when_effective_upstreams_too_few() -> None:
  ctx = make_context()
  create_route(ctx, {"domain": "api.example.com", "upstream_target": "10.0.0.10:6111"})
  with pytest.raises(HttpError) as err:
    update_route(ctx, "api.example.com", {"lb_policy": "ip_hash"})
  assert err.value.status == 400


def test_delete_route_without_purge() -> None:
  ctx = make_context()
  create_route(ctx, {"domain": "api.example.com", "upstream_target": "6111"})
  result = delete_route(ctx, "api.example.com", purge=False)
  assert result == {"domain": "api.example.com", "purged": False}
  assert "api.example.com" not in ctx.database.routes


def test_delete_route_blocked_by_certificate_without_purge() -> None:
  ctx = make_context()
  create_route(ctx, {"domain": "api.example.com", "upstream_target": "6111"})
  now = datetime.now(tz=UTC)
  ctx.database.certificates["api.example.com"] = CertificateRecord(
    domain="api.example.com",
    fullchain_pem="pem",
    private_key_pem="key",
    not_before=now,
    not_after=now + timedelta(days=90),
    version=1,
    status="active",
    source="certbot",
    retry_after=None,
    updated_at=now,
    last_error=None,
  )
  with pytest.raises(HttpError) as err:
    delete_route(ctx, "api.example.com", purge=False)
  assert err.value.status == 409


def test_delete_route_with_purge_cleans_certificate() -> None:
  ctx = make_context()
  create_route(ctx, {"domain": "api.example.com", "upstream_target": "6111"})
  now = datetime.now(tz=UTC)
  ctx.database.certificates["api.example.com"] = CertificateRecord(
    domain="api.example.com",
    fullchain_pem="pem",
    private_key_pem="key",
    not_before=now,
    not_after=now + timedelta(days=90),
    version=1,
    status="active",
    source="certbot",
    retry_after=None,
    updated_at=now,
    last_error=None,
  )
  result = delete_route(ctx, "api.example.com", purge=True)
  assert result == {"domain": "api.example.com", "purged": True}
  assert "api.example.com" not in ctx.database.routes
  assert "api.example.com" not in ctx.database.certificates


def test_get_route_detail_includes_certificate() -> None:
  ctx = make_context()
  create_route(ctx, {"domain": "api.example.com", "upstream_target": "6111"})
  now = datetime.now(tz=UTC)
  ctx.database.certificates["api.example.com"] = CertificateRecord(
    domain="api.example.com",
    fullchain_pem="pem",
    private_key_pem="key",
    not_before=now,
    not_after=now + timedelta(days=30),
    version=2,
    status="active",
    source="certbot",
    retry_after=None,
    updated_at=now,
    last_error=None,
  )
  detail = get_route_detail(ctx, "api.example.com")
  assert detail["route"]["domain"] == "api.example.com"
  assert detail["certificate"] is not None
  assert detail["certificate"]["version"] == 2
  assert detail["certificate"]["has_key_material"] is True


def test_list_routes_summary_sorts_by_domain() -> None:
  ctx = make_context()
  create_route(ctx, {"domain": "b.example.com", "upstream_target": "6111"})
  create_route(ctx, {"domain": "a.example.com", "upstream_target": "6112"})
  rows = list_routes_summary(ctx)
  assert [r["domain"] for r in rows] == ["a.example.com", "b.example.com"]


def test_upsert_zone_validates_fields() -> None:
  ctx = make_context()
  with pytest.raises(HttpError, match="zone_id"):
    upsert_zone(ctx, {"zone_name": "example.com", "api_token": "t"})
  with pytest.raises(HttpError, match="api_token"):
    upsert_zone(ctx, {"zone_name": "example.com", "zone_id": "zid"})
  with pytest.raises(HttpError, match="invalid zone_name"):
    upsert_zone(ctx, {"zone_name": "not-a-domain", "zone_id": "zid", "api_token": "t"})


def test_upsert_zone_masks_token_in_list() -> None:
  ctx = make_context()
  upsert_zone(ctx, {"zone_name": "example.com", "zone_id": "zid123", "api_token": "longtokenvalue"})
  rows = list_zones(ctx)
  assert rows[0]["zone_name"] == "example.com"
  assert rows[0]["api_token"] != "longtokenvalue"
  assert "***" in rows[0]["api_token"]


def test_upsert_zone_can_reveal_token() -> None:
  ctx = make_context()
  upsert_zone(ctx, {"zone_name": "example.com", "zone_id": "zid", "api_token": "secret-token"})
  rows = list_zones(ctx, reveal_token=True)
  assert rows[0]["api_token"] == "secret-token"


def test_delete_zone_removes_record() -> None:
  ctx = make_context()
  upsert_zone(ctx, {"zone_name": "example.com", "zone_id": "zid", "api_token": "secret"})
  result = delete_zone(ctx, "example.com")
  assert result == {"zone_name": "example.com", "deleted": True}


def test_delete_zone_404_when_missing() -> None:
  ctx = make_context()
  with pytest.raises(HttpError) as err:
    delete_zone(ctx, "missing.example.com")
  assert err.value.status == 404


def test_build_overview_counts_expiring_and_expired(tmp_path: Path) -> None:
  ctx = make_context()
  now = datetime.now(tz=UTC)
  ctx.database.routes["a.example.com"] = RouteRecord(
    domain="a.example.com", upstream_target="127.0.0.1:1", enabled=True, updated_at=now,
  )
  ctx.database.routes["b.example.com"] = RouteRecord(
    domain="b.example.com", upstream_target=None, enabled=False, updated_at=now,
  )
  ctx.database.certificates["a.example.com"] = CertificateRecord(
    domain="a.example.com", fullchain_pem="p", private_key_pem="k",
    not_before=now - timedelta(days=30), not_after=now + timedelta(days=7),
    version=1, status="active", source="certbot", retry_after=None,
    updated_at=now, last_error=None,
  )
  ctx.database.certificates["b.example.com"] = CertificateRecord(
    domain="b.example.com", fullchain_pem="", private_key_pem="",
    not_before=now - timedelta(days=90), not_after=now - timedelta(days=1),
    version=1, status="error", source="certbot", retry_after=None,
    updated_at=now, last_error="dns failure",
  )
  overview = build_overview(ctx)
  counts = overview["counts"]
  assert counts["routes_total"] == 2
  assert counts["routes_enabled"] == 1
  assert counts["routes_disabled"] == 1
  assert counts["certificates_expiring_soon"] == 1
  assert counts["certificates_expired"] == 1
  assert counts["certificate_status"]["active"] == 1
  assert counts["certificate_status"]["error"] == 1


def test_tail_file_reads_last_lines(tmp_path: Path) -> None:
  path = tmp_path / "log.txt"
  path.write_text("\n".join(f"line {i}" for i in range(1, 21)) + "\n")
  assert tail_file(path, max_lines=5) == ["line 16", "line 17", "line 18", "line 19", "line 20"]


def test_tail_file_returns_empty_when_missing(tmp_path: Path) -> None:
  assert tail_file(tmp_path / "missing.log", max_lines=10) == []


def test_static_bundle_contains_index_html() -> None:
  from ssl_proxy_controller.admin import STATIC_DIR

  assert STATIC_DIR.is_dir()
  index = STATIC_DIR / "index.html"
  assert index.is_file()
  content = index.read_text()
  # Basic smoke check: the SPA expects these API endpoints.
  for needle in ["/api/overview", "/api/routes", "/api/certificates", "/api/zones", "/api/logs", "/api/sync", "/api/nodes"]:
    assert needle in content, f"index.html is missing reference to {needle}"


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


from ssl_proxy_controller.admin import (  # noqa: E402
  create_node,
  delete_node,
  deploy_node_action,
  get_node_detail,
  list_nodes,
  probe_node_action,
  update_node,
  update_node_action,
)
from ssl_proxy_controller import nodes as nodes_mod  # noqa: E402


def _node_payload(**overrides) -> dict:
  base = {
    "name": "edge-1",
    "host": "1.2.3.4",
    "ssh_port": 22,
    "ssh_user": "root",
    "auth_method": "password",
    "ssh_password": "secret",
    "description": "test node",
    "tags": ["edge", "sg"],
  }
  base.update(overrides)
  return base


def test_create_node_inserts_with_password_auth() -> None:
  ctx = make_context()
  result = create_node(ctx, _node_payload())
  assert result["name"] == "edge-1"
  assert result["auth_method"] == "password"
  assert result["has_ssh_password"] is True
  assert result["has_ssh_private_key"] is False
  # Per product decision, secrets ARE returned in plaintext.
  assert result["ssh_password"] == "secret"
  assert result["ssh_private_key"] is None
  assert "edge-1" in ctx.database.nodes


def test_create_node_requires_secret_for_chosen_auth() -> None:
  ctx = make_context()
  with pytest.raises(HttpError) as err:
    create_node(ctx, _node_payload(auth_method="key", ssh_password=None))
  assert err.value.status == 400
  assert err.value.code == "private_key_required"


def test_create_node_rejects_duplicate() -> None:
  ctx = make_context()
  create_node(ctx, _node_payload())
  with pytest.raises(HttpError) as err:
    create_node(ctx, _node_payload())
  assert err.value.status == 409


def test_create_node_rejects_invalid_name() -> None:
  ctx = make_context()
  with pytest.raises(HttpError) as err:
    create_node(ctx, _node_payload(name="bad name with spaces"))
  assert err.value.status == 400


def test_create_node_requires_readwrite() -> None:
  ctx = make_context(mode="readonly")
  with pytest.raises(HttpError) as err:
    create_node(ctx, _node_payload())
  assert err.value.status == 403


def test_update_node_changes_host_and_keeps_secrets_when_blank() -> None:
  ctx = make_context()
  create_node(ctx, _node_payload())
  updated = update_node(ctx, "edge-1", {"host": "9.9.9.9", "description": "moved"})
  assert updated["host"] == "9.9.9.9"
  assert updated["description"] == "moved"
  # password unchanged
  assert ctx.database.nodes["edge-1"].ssh_password == "secret"


def test_update_node_can_swap_auth_method_to_key() -> None:
  ctx = make_context()
  create_node(ctx, _node_payload())
  fake_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"
  updated = update_node(ctx, "edge-1", {
    "auth_method": "key",
    "ssh_private_key": fake_key,
    "ssh_password": None,  # clearing the password is fine when switching
  })
  assert updated["auth_method"] == "key"
  assert updated["has_ssh_private_key"] is True
  assert updated["has_ssh_password"] is False


def test_delete_node_returns_404_when_missing() -> None:
  ctx = make_context()
  with pytest.raises(HttpError) as err:
    delete_node(ctx, "ghost")
  assert err.value.status == 404


def test_delete_node_removes_status_too() -> None:
  ctx = make_context()
  create_node(ctx, _node_payload())
  ctx.database.upsert_node_status(NodeStatusRecord(
    node_name="edge-1", reachable=True, service_installed=True, service_running=True,
    service_mode="readonly", service_version="git abc1234",
    uptime_seconds=12345, load_avg="0.10 0.05 0.01",
    memory="128/512 MB", disk_usage="22% used of 50G",
    os_release="Ubuntu 22.04", last_probed_at=datetime.now(tz=UTC),
    last_probe_error=None,
  ))
  delete_node(ctx, "edge-1")
  assert "edge-1" not in ctx.database.nodes
  assert "edge-1" not in ctx.database.node_statuses


def test_list_nodes_includes_status_payload() -> None:
  ctx = make_context()
  create_node(ctx, _node_payload())
  ctx.database.upsert_node_status(NodeStatusRecord(
    node_name="edge-1", reachable=True, service_installed=True, service_running=True,
    service_mode="readwrite", service_version="git abc",
    uptime_seconds=999, load_avg="0.1", memory="100/200 MB", disk_usage="10%",
    os_release="Ubuntu 22.04", last_probed_at=datetime.now(tz=UTC),
    last_probe_error=None,
  ))
  rows = list_nodes(ctx)
  assert rows[0]["name"] == "edge-1"
  assert rows[0]["status"]["reachable"] is True
  assert rows[0]["status"]["service_mode"] == "readwrite"


def test_get_node_detail_404_when_missing() -> None:
  ctx = make_context()
  with pytest.raises(HttpError) as err:
    get_node_detail(ctx, "missing")
  assert err.value.status == 404


def test_probe_node_action_uses_module_and_persists_status(monkeypatch) -> None:
  ctx = make_context()
  create_node(ctx, _node_payload())
  fake_status = NodeStatusRecord(
    node_name="edge-1", reachable=True, service_installed=True, service_running=True,
    service_mode="readonly", service_version="git deadbeef",
    uptime_seconds=42, load_avg="0.0 0.0 0.0",
    memory="50/100 MB", disk_usage="5% used of 50G",
    os_release="Debian 12", last_probed_at=datetime.now(tz=UTC),
    last_probe_error=None, raw_probe={"sections": {}},
  )
  monkeypatch.setattr(nodes_mod, "probe_node", lambda node: fake_status)
  result = probe_node_action(ctx, "edge-1")
  assert result["reachable"] is True
  assert result["service_mode"] == "readonly"
  assert "edge-1" in ctx.database.node_statuses


def test_deploy_node_action_runs_command(monkeypatch) -> None:
  ctx = make_context()
  create_node(ctx, _node_payload(deploy_command="echo deploy"))
  captured = {}
  def fake_deploy(node, override_command=None):
    captured["override"] = override_command
    captured["node_name"] = node.name
    return nodes_mod.CommandResult("echo deploy", 0, "deploy ok\n", "", 0.01)
  monkeypatch.setattr(nodes_mod, "deploy_service", fake_deploy)
  result = deploy_node_action(ctx, "edge-1", {})
  assert result["exit_code"] == 0
  assert "deploy ok" in result["stdout"]
  assert captured["node_name"] == "edge-1"


def test_update_node_action_uses_override_command(monkeypatch) -> None:
  ctx = make_context()
  create_node(ctx, _node_payload())
  captured = {}
  def fake_update(node, override_command=None):
    captured["override"] = override_command
    return nodes_mod.CommandResult(override_command or "default", 0, "ok\n", "", 0.01)
  monkeypatch.setattr(nodes_mod, "update_service", fake_update)
  result = update_node_action(ctx, "edge-1", {"command": "git pull && systemctl restart x"})
  assert result["exit_code"] == 0
  assert captured["override"] == "git pull && systemctl restart x"


# ---------------------------------------------------------------------------
# Init runs + host ssh keys
# ---------------------------------------------------------------------------


from ssl_proxy_controller.admin import (  # noqa: E402
  start_init_run,
  get_init_run as get_init_run_action,
  list_init_runs as list_init_runs_action,
  list_host_ssh_keys,
  read_host_ssh_key,
)
from ssl_proxy_controller import nodes_init as nodes_init_mod  # noqa: E402


def test_start_init_run_persists_payload_to_node(monkeypatch) -> None:
  ctx = make_context()
  create_node(ctx, _node_payload())
  scheduled = {}
  def fake_schedule(database, node, cfg):
    scheduled["node_name"] = node.name
    scheduled["cfg"] = cfg
    rec = database.insert_init_run(node.name, config_snapshot=cfg.to_json())
    database.update_init_run(rec.id, status="success", finished=True, exit_code=0)
    return rec
  monkeypatch.setattr(nodes_init_mod, "schedule_init_run", fake_schedule)
  result = start_init_run(ctx, "edge-1", {
    "init_git_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
    "init_git_user_name": "Alice",
    "init_git_user_email": "alice@example.com",
    "init_desired_ssh_port": 60101,
    "init_install_codex": True,
    "init_codex_base_url": "https://api.openai.com/v1",
    "init_codex_api_key": "sk-test",
  })
  assert result["status"] in ("success", "queued", "running")
  # Node row got updated:
  stored = ctx.database.nodes["edge-1"]
  assert stored.init_git_user_name == "Alice"
  assert stored.init_codex_api_key == "sk-test"
  assert stored.init_desired_ssh_port == 60101
  # The cfg passed to schedule reflects the new values.
  assert scheduled["cfg"].git_user_name == "Alice"
  assert scheduled["cfg"].codex_api_key == "sk-test"


def test_get_init_run_404_for_other_node() -> None:
  ctx = make_context()
  create_node(ctx, _node_payload())
  ctx.database.insert_node(NodeRecord(
    name="other", host="2.2.2.2", ssh_port=22, ssh_user="root",
    auth_method="password", ssh_password="x", ssh_private_key=None, ssh_key_passphrase=None,
    description=None, tags=[], deploy_command=None, update_command=None,
    created_at=datetime.now(tz=UTC), updated_at=datetime.now(tz=UTC),
  ))
  rec = ctx.database.insert_init_run("other", config_snapshot=None)
  with pytest.raises(HttpError) as err:
    get_init_run_action(ctx, "edge-1", rec.id)
  assert err.value.status == 404


def test_list_host_ssh_keys_finds_simulated_key(monkeypatch, tmp_path: Path) -> None:
  fake_ssh = tmp_path / ".ssh"
  fake_ssh.mkdir()
  (fake_ssh / "id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nbody\n-----END OPENSSH PRIVATE KEY-----\n")
  (fake_ssh / "id_ed25519.pub").write_text("ssh-ed25519 AAAA fake@host\n")
  (fake_ssh / "known_hosts").write_text("github.com ssh-ed25519 ...\n")
  from ssl_proxy_controller import admin as admin_mod
  monkeypatch.setattr(admin_mod, "_ssh_dir", lambda: fake_ssh)
  ctx = make_context()
  keys = list_host_ssh_keys(ctx)
  names = [k["name"] for k in keys]
  assert names == ["id_ed25519"]
  assert keys[0]["type"] == "ssh-ed25519"


def test_read_host_ssh_key_rejects_outside_ssh_dir(monkeypatch, tmp_path: Path) -> None:
  fake_ssh = tmp_path / ".ssh"
  fake_ssh.mkdir()
  outside = tmp_path / "outside"
  outside.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nbody\n-----END OPENSSH PRIVATE KEY-----\n")
  from ssl_proxy_controller import admin as admin_mod
  monkeypatch.setattr(admin_mod, "_ssh_dir", lambda: fake_ssh)
  ctx = make_context()
  with pytest.raises(HttpError) as err:
    read_host_ssh_key(ctx, {"path": str(outside)})
  assert err.value.status == 400


def test_read_host_ssh_key_returns_content(monkeypatch, tmp_path: Path) -> None:
  fake_ssh = tmp_path / ".ssh"
  fake_ssh.mkdir()
  key_path = fake_ssh / "id_ed25519"
  body = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"
  key_path.write_text(body)
  from ssl_proxy_controller import admin as admin_mod
  monkeypatch.setattr(admin_mod, "_ssh_dir", lambda: fake_ssh)
  ctx = make_context()
  result = read_host_ssh_key(ctx, {"path": str(key_path)})
  assert result["content"] == body
