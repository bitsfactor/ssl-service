#!/usr/bin/env python3
"""Run the ssl-service web admin locally without Postgres/Caddy.

This script spins up the HTTP admin server backed by an in-memory
"FakeDatabase" seeded with a few demo rows, so you can open the admin
UI in a browser and click through every screen end-to-end.

Usage:
  # defaults: http://127.0.0.1:8088, token "dev-token", mode readwrite
  python3 scripts/dev-admin.py

  # custom port / bind / token / mode
  python3 scripts/dev-admin.py --bind 0.0.0.0 --port 9000 --token my-token --mode readonly

  # run with no seed data (empty state)
  python3 scripts/dev-admin.py --no-seed

Requirements:
  - Python 3.11+
  - PyYAML (pip install pyyaml) -- for config loading (not actually used here,
    but the `ssl_proxy_controller` package imports it transitively)

The dev server does NOT talk to PostgreSQL or Caddy. `/api/sync` will
attempt to invoke the configured `reload_command` which defaults to
`/usr/bin/true`, so it always succeeds.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make the in-repo package importable without an install.
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if SRC.exists() and str(SRC) not in sys.path:
  sys.path.insert(0, str(SRC))

from ssl_proxy_controller.admin import AdminServer  # noqa: E402
from ssl_proxy_controller.config import (  # noqa: E402
  AcmeConfig,
  AdminConfig,
  AppConfig,
  CaddyConfig,
  LoggingConfig,
  PathsConfig,
  PostgresConfig,
  SyncConfig,
)
from ssl_proxy_controller.db import (  # noqa: E402
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

UTC = timezone.utc


class FakeDatabase:
  """In-memory stand-in for the real Postgres-backed Database.

  Implements every method the admin server calls. Useful for local
  development and manual testing of the web UI.
  """

  def __init__(self) -> None:
    self.routes: dict[str, RouteRecord] = {}
    self.certificates: dict[str, CertificateRecord] = {}
    self.zones: dict[str, DnsZoneTokenRecord] = {}
    self.nodes: dict[str, NodeRecord] = {}
    self.node_statuses: dict[str, NodeStatusRecord] = {}
    self.init_runs: dict[int, NodeInitRunRecord] = {}
    self._init_run_seq: int = 0
    self.services: dict[str, ServiceRecord] = {}

  # routes -----------------------------------------------------------
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
      raise RuntimeError("foreign key violation: certificate exists")
    return self.routes.pop(domain, None) is not None

  def purge_route(self, domain: str) -> bool:
    self.certificates.pop(domain, None)
    return self.routes.pop(domain, None) is not None

  # certificates -----------------------------------------------------
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

  # zones ------------------------------------------------------------
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

  # nodes ------------------------------------------------------------
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

  # init runs ----------------------------------------------------------
  def insert_init_run(self, node_name: str, config_snapshot: dict | None = None) -> NodeInitRunRecord:
    self._init_run_seq += 1
    rec = NodeInitRunRecord(
      id=self._init_run_seq, node_name=node_name, status="queued",
      current_step=None, log_text="", exit_code=None,
      started_at=datetime.now(tz=UTC), finished_at=None,
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

  # services -----------------------------------------------------------
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
        setattr(s, k, v)
    s.updated_at = datetime.now(tz=UTC)
    return s

  def delete_service(self, name: str) -> bool:
    return self.services.pop(name, None) is not None


def seed_demo_data(db: FakeDatabase) -> None:
  now = datetime.now(tz=UTC)

  db.insert_route("api.example.com", "127.0.0.1:6111", enabled=True)
  db.insert_route("app.example.com", "127.0.0.1:6112", enabled=True)
  db.insert_route("stage.example.com", "127.0.0.1:6113", enabled=False)
  db.insert_route("legacy.example.com", None, enabled=True)
  # Demo of the multi-upstream + load-balancing feature: three backends
  # behind one domain, with client-IP session stickiness.
  db.insert_route(
    "balanced.example.com",
    upstream_target=None,
    enabled=True,
    upstreams=[
      UpstreamRecord(target="10.0.0.10:6111", weight=1),
      UpstreamRecord(target="10.0.0.11:6111", weight=1),
      UpstreamRecord(target="10.0.0.12:6111", weight=2),
    ],
    lb_policy="ip_hash",
  )

  db.certificates["api.example.com"] = CertificateRecord(
    domain="api.example.com",
    fullchain_pem="-----BEGIN CERTIFICATE-----\n(demo)\n-----END CERTIFICATE-----",
    private_key_pem="-----BEGIN PRIVATE KEY-----\n(demo)\n-----END PRIVATE KEY-----",
    not_before=now - timedelta(days=30),
    not_after=now + timedelta(days=60),
    version=3,
    status="active",
    source="certbot",
    retry_after=None,
    updated_at=now - timedelta(hours=6),
    last_error=None,
  )
  db.certificates["app.example.com"] = CertificateRecord(
    domain="app.example.com",
    fullchain_pem="-----BEGIN CERTIFICATE-----\n(demo)\n-----END CERTIFICATE-----",
    private_key_pem="-----BEGIN PRIVATE KEY-----\n(demo)\n-----END PRIVATE KEY-----",
    not_before=now - timedelta(days=85),
    not_after=now + timedelta(days=5),  # expiring soon
    version=2,
    status="active",
    source="certbot",
    retry_after=None,
    updated_at=now - timedelta(days=85),
    last_error=None,
  )
  db.certificates["stage.example.com"] = CertificateRecord(
    domain="stage.example.com",
    fullchain_pem="",
    private_key_pem="",
    not_before=now - timedelta(days=1),
    not_after=now + timedelta(days=90),
    version=0,
    status="error",
    source="certbot",
    retry_after=now + timedelta(hours=1),
    updated_at=now - timedelta(minutes=20),
    last_error="DNS-01 propagation timed out waiting for _acme-challenge.stage.example.com",
  )

  db.upsert_dns_zone_token(
    "example.com",
    zone_id="demo-zone-id-abc123def456",
    api_token="cfapi-demo-token-abcdef0123456789",
    provider="cloudflare",
  )
  db.upsert_dns_zone_token(
    "example.net",
    zone_id="demo-zone-id-xyz789uvw012",
    api_token="cfapi-demo-token-zyxwvu9876543210",
    provider="cloudflare",
  )


def build_config(args: argparse.Namespace) -> AppConfig:
  return AppConfig(
    mode=args.mode,
    postgres=PostgresConfig(dsn="postgresql://dev-admin/nope"),  # not used
    sync=SyncConfig(
      poll_interval_seconds=30,
      renew_before_days=30,
      retry_backoff_seconds=3600,
      loop_error_backoff_seconds=10,
    ),
    paths=PathsConfig(
      state_dir=Path("/tmp/ssl-service-dev/state"),
      log_dir=Path("/tmp/ssl-service-dev/logs"),
    ),
    caddy=CaddyConfig(reload_command=["/usr/bin/true"]),
    acme=AcmeConfig(
      email="dev@example.com",
      staging=True,
      challenge_type="dns-01",
      dns_provider="cloudflare",
    ),
    logging=LoggingConfig(
      level="INFO",
      controller_log_path="/tmp/ssl-service-dev/logs/controller.log",
      caddy_log_path="/tmp/ssl-service-dev/logs/caddy.log",
    ),
    admin=AdminConfig(
      enabled=True, bind=args.bind, port=args.port, token=args.token
    ),
  )


def ensure_demo_logs(cfg: AppConfig) -> None:
  Path(cfg.paths.log_dir).mkdir(parents=True, exist_ok=True)
  controller_log = Path(cfg.logging.controller_log_path)
  caddy_log = Path(cfg.logging.caddy_log_path)
  now = datetime.now(tz=UTC).isoformat()
  if not controller_log.exists():
    controller_log.write_text(
      "\n".join(
        f"{now} INFO ssl_proxy_controller startup line {i:02d}"
        for i in range(1, 21)
      )
      + "\n"
    )
  if not caddy_log.exists():
    caddy_log.write_text(
      "\n".join(
        f"{now} level=info msg=\"caddy demo log line {i:02d}\""
        for i in range(1, 21)
      )
      + "\n"
    )


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(description="Run the ssl-service admin UI in dev mode")
  parser.add_argument("--bind", default="127.0.0.1", help="interface to bind (default 127.0.0.1)")
  parser.add_argument("--port", type=int, default=8088, help="port (default 8088)")
  parser.add_argument("--token", default="dev-token", help="admin token (default 'dev-token')")
  parser.add_argument(
    "--mode",
    default="readwrite",
    choices=["readonly", "readwrite"],
    help="readwrite allows mutations, readonly blocks them (default readwrite)",
  )
  parser.add_argument("--no-seed", action="store_true", help="do not seed demo data")
  args = parser.parse_args(argv)

  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
  )

  cfg = build_config(args)
  ensure_demo_logs(cfg)

  db = FakeDatabase()
  if not args.no_seed:
    seed_demo_data(db)

  server = AdminServer(cfg, db)
  server.start()

  bind = args.bind if args.bind != "0.0.0.0" else "localhost"
  print()
  print("=" * 72)
  print(f"  ssl-service admin (dev mode) listening on http://{bind}:{args.port}/")
  print(f"  mode:   {args.mode}")
  print(f"  token:  {args.token}")
  print(f"  seed:   {'no' if args.no_seed else 'yes (demo routes, certs, zones)'}")
  print("=" * 72)
  print()
  print("Open the URL above in a browser and paste the token to sign in.")
  print("The backend is in-memory — data resets every time you restart this.")
  print()
  print("Press Ctrl-C to stop.")
  print()

  stop_event = {"done": False}

  def _handle_stop(*_a: object) -> None:
    stop_event["done"] = True

  signal.signal(signal.SIGINT, _handle_stop)
  signal.signal(signal.SIGTERM, _handle_stop)

  try:
    while not stop_event["done"]:
      signal.pause()
  finally:
    print("shutting down...")
    server.stop()
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
