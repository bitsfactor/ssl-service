from __future__ import annotations

import logging
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator

import psycopg
from psycopg.rows import dict_row

# Connection pool — optional. Without psycopg_pool we fall back to
# opening a fresh connection per call, which is slow over the public
# internet (TLS + Postgres startup adds 0.5–2 s per request).
try:  # pragma: no cover — import-only guard
  from psycopg_pool import ConnectionPool  # type: ignore
except Exception:  # noqa: BLE001
  ConnectionPool = None  # type: ignore

LOGGER = logging.getLogger("ssl_proxy_controller.db")


LB_POLICIES = ("random", "round_robin", "ip_hash", "uri_hash")


@dataclass(slots=True)
class UpstreamRecord:
  target: str
  weight: int = 1


@dataclass(slots=True)
class RouteRecord:
  domain: str
  upstream_target: str | None
  enabled: bool
  updated_at: datetime
  upstreams: list[UpstreamRecord] = None  # type: ignore[assignment]
  lb_policy: str = "random"

  def __post_init__(self) -> None:
    if self.upstreams is None:
      # Backward compat: a legacy record created without explicit
      # upstreams (tests, seed data, older callers) gets a single-item
      # list derived from upstream_target.
      self.upstreams = (
        [UpstreamRecord(target=self.upstream_target, weight=1)]
        if self.upstream_target
        else []
      )
    if self.lb_policy not in LB_POLICIES:
      raise ValueError(f"invalid lb_policy: {self.lb_policy}")


@dataclass(slots=True)
class CertificateRecord:
  domain: str
  fullchain_pem: str
  private_key_pem: str
  not_before: datetime
  not_after: datetime
  version: int
  status: str
  source: str
  retry_after: datetime | None
  updated_at: datetime
  last_error: str | None


@dataclass(slots=True)
class DnsZoneTokenRecord:
  zone_name: str
  provider: str
  zone_id: str
  api_token: str
  updated_at: datetime


NODE_AUTH_METHODS = ("password", "key", "auto")


@dataclass(slots=True)
class NodeRecord:
  name: str
  host: str
  ssh_port: int
  ssh_user: str
  auth_method: str
  ssh_password: str | None
  ssh_private_key: str | None
  ssh_key_passphrase: str | None
  description: str | None
  tags: list[str]
  deploy_command: str | None
  update_command: str | None
  created_at: datetime
  updated_at: datetime
  # Initialization defaults — see "Init wizard" feature.
  init_git_private_key: str | None = None
  init_git_user_name: str | None = None
  init_git_user_email: str | None = None
  init_desired_ssh_port: int | None = 60101
  init_install_codex: bool = True
  init_codex_base_url: str | None = None
  init_codex_api_key: str | None = None
  init_timezone: str | None = "Asia/Shanghai"


INIT_RUN_STATUSES = ("queued", "running", "success", "failed", "cancelled")


@dataclass(slots=True)
class ServiceRecord:
  """A registered deployable service.

  `default_env` is a dict of key→string values that will be written into
  a .env file on the node before `docker compose up -d --build` runs.
  `compose_template`, when set, is written to {install_dir}/{compose_file}
  on the node before deploy (overriding whatever's in the repo).
  `config_files` is a dict of {relative_path: file_content} that we write
  alongside the compose file, with `${KEY}` env substitution from the
  effective .env values via remote envsubst.
  Per-deployment overrides come in via the deploy action payload.
  """
  name: str
  display_name: str
  description: str | None
  github_repo_url: str
  default_branch: str
  compose_file: str
  install_dir_template: str
  default_env: dict
  pre_deploy_command: str | None
  post_deploy_command: str | None
  compose_template: str | None
  config_files: dict
  created_at: datetime
  updated_at: datetime
  # Manifest fields populated from `.deploy.yaml` at fetch time.
  required_env: list[str] = None  # type: ignore[assignment]
  healthcheck: dict = None  # type: ignore[assignment]
  depends_on: list[str] = None  # type: ignore[assignment]
  exposed_ports: list[int] = None  # type: ignore[assignment]
  deploy_yaml: str | None = None
  deploy_yaml_fetched_at: datetime | None = None

  def __post_init__(self) -> None:
    if self.required_env is None:
      self.required_env = []
    if self.healthcheck is None:
      self.healthcheck = {}
    if self.depends_on is None:
      self.depends_on = []
    if self.exposed_ports is None:
      self.exposed_ports = []


@dataclass(slots=True)
class ServiceDeploymentRecord:
  id: int
  service_name: str
  node_name: str
  revision: str | None
  status: str
  healthcheck_passed: bool | None
  healthcheck_detail: str | None
  env_snapshot: dict
  log_text: str
  exit_code: int | None
  started_at: datetime
  finished_at: datetime | None
  triggered_by: str | None


@dataclass(slots=True)
class ServiceNodeStateRecord:
  service_name: str
  node_name: str
  revision: str | None
  status: str | None
  last_deployment_id: int | None
  updated_at: datetime


@dataclass(slots=True)
class NodeInitRunRecord:
  id: int
  node_name: str
  status: str
  current_step: str | None
  log_text: str
  exit_code: int | None
  started_at: datetime
  finished_at: datetime | None
  config_snapshot: dict | None


@dataclass(slots=True)
class NodeStatusRecord:
  node_name: str
  reachable: bool
  service_installed: bool | None
  service_running: bool | None
  service_mode: str | None
  service_version: str | None
  uptime_seconds: int | None
  load_avg: str | None
  memory: str | None
  disk_usage: str | None
  os_release: str | None
  last_probed_at: datetime | None
  last_probe_error: str | None
  raw_probe: dict | None = None


# Static IP registry --------------------------------------------------
IP_PROTOCOLS = (
  "tcp", "udp", "http", "https", "ssh", "socks5", "socks4",
  "shadowsocks", "ss", "trojan", "vmess", "vless", "wireguard",
  "openvpn", "hysteria", "hysteria2", "icmp", "other",
)


@dataclass(slots=True)
class StaticIpRecord:
  id: int
  ip: str
  port: int | None
  protocol: str
  country: str | None
  provider: str | None
  label: str | None
  notes: str | None
  static_info: dict
  loop_test_seconds: int | None
  last_test_at: datetime | None
  last_test_success: bool | None
  last_test_latency_ms: int | None
  last_test_error: str | None
  last_probe_at: datetime | None
  created_at: datetime
  updated_at: datetime


@dataclass(slots=True)
class SshKeyRecord:
  id: int
  name: str
  description: str | None
  key_type: str
  bits: int | None
  private_key: str
  public_key: str
  fingerprint_sha256: str
  comment: str | None
  passphrase: str | None
  source: str
  tags: list[str]
  created_at: datetime
  updated_at: datetime


@dataclass(slots=True)
class IpTestResultRecord:
  id: int
  ip_id: int
  test_kind: str
  success: bool
  latency_ms: int | None
  error: str | None
  raw: dict
  created_at: datetime


class Database:
  def __init__(
    self,
    dsn: str,
    *,
    pool_min_size: int = 3,
    pool_max_size: int = 10,
    pool_timeout: float = 30.0,
    use_pool: bool = True,
  ) -> None:
    self._dsn = dsn
    self._pool = None
    if use_pool and ConnectionPool is not None:
      try:
        self._pool = ConnectionPool(
          dsn,
          min_size=pool_min_size,
          max_size=pool_max_size,
          timeout=pool_timeout,
          open=True,
          kwargs={"row_factory": dict_row},
        )
        # Block until at least one connection is ready so the first
        # request after startup doesn't pay the full TLS/handshake tax.
        self._pool.wait(timeout=pool_timeout)
        LOGGER.info(
          "psycopg connection pool ready (min=%d, max=%d)",
          pool_min_size, pool_max_size,
        )
      except Exception as exc:  # noqa: BLE001
        LOGGER.warning(
          "could not start psycopg connection pool (%s); "
          "falling back to per-call connections",
          exc,
        )
        self._pool = None

  def close(self) -> None:
    """Close the underlying pool. Safe to call multiple times."""
    if self._pool is not None:
      try:
        self._pool.close()
      finally:
        self._pool = None

  @contextmanager
  def connect(self) -> Iterator[psycopg.Connection]:
    if self._pool is not None:
      with self._pool.connection() as connection:
        yield connection
    else:
      with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
        yield connection

  _ROUTE_SELECT_COLUMNS = """
    domain,
    COALESCE(upstream_target, CASE WHEN upstream_port IS NULL THEN NULL ELSE '127.0.0.1:' || upstream_port::text END) AS upstream_target,
    enabled,
    updated_at,
    COALESCE(lb_policy, 'random') AS lb_policy
  """

  def _hydrate_upstreams(self, cursor: psycopg.Cursor, domains: list[str]) -> dict[str, list[UpstreamRecord]]:
    """Fetch upstream rows for a set of domains and group by domain.

    Returns a dict of domain → ordered list of UpstreamRecord. The
    ordering is deterministic: primary key `id` ascending, which means
    the first upstream ever inserted for a domain stays first.
    """
    if not domains:
      return {}
    cursor.execute(
      """
      SELECT domain, target, weight
      FROM route_upstreams
      WHERE domain = ANY(%s)
      ORDER BY domain ASC, id ASC
      """,
      (domains,),
    )
    grouped: dict[str, list[UpstreamRecord]] = {}
    for row in cursor.fetchall():
      grouped.setdefault(row["domain"], []).append(
        UpstreamRecord(target=row["target"], weight=int(row["weight"]))
      )
    return grouped

  def _build_route_records(
    self,
    base_rows: list[dict],
    upstreams_by_domain: dict[str, list[UpstreamRecord]],
  ) -> list[RouteRecord]:
    records: list[RouteRecord] = []
    for row in base_rows:
      ups = upstreams_by_domain.get(row["domain"], [])
      # If route_upstreams has entries, derive upstream_target from the
      # first one (the canonical "primary"). Otherwise fall back to the
      # legacy column so old-shape routes still read cleanly.
      primary = ups[0].target if ups else row["upstream_target"]
      records.append(
        RouteRecord(
          domain=row["domain"],
          upstream_target=primary,
          enabled=row["enabled"],
          updated_at=row["updated_at"],
          upstreams=list(ups)
          if ups
          else (
            [UpstreamRecord(target=row["upstream_target"], weight=1)]
            if row["upstream_target"]
            else []
          ),
          lb_policy=row["lb_policy"] or "random",
        )
      )
    return records

  def fetch_routes(self) -> list[RouteRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._ROUTE_SELECT_COLUMNS} FROM routes WHERE enabled = TRUE ORDER BY domain ASC"
        )
        rows = cursor.fetchall()
        upstreams = self._hydrate_upstreams(cursor, [r["domain"] for r in rows])
        return self._build_route_records(rows, upstreams)

  def list_routes(self) -> list[RouteRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._ROUTE_SELECT_COLUMNS} FROM routes ORDER BY domain ASC"
        )
        rows = cursor.fetchall()
        upstreams = self._hydrate_upstreams(cursor, [r["domain"] for r in rows])
        return self._build_route_records(rows, upstreams)

  def get_route(self, domain: str) -> RouteRecord | None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._ROUTE_SELECT_COLUMNS} FROM routes WHERE domain = %s",
          (domain,),
        )
        row = cursor.fetchone()
        if row is None:
          return None
        upstreams = self._hydrate_upstreams(cursor, [row["domain"]])
        return self._build_route_records([row], upstreams)[0]

  def insert_route(
    self,
    domain: str,
    upstream_target: str | None,
    enabled: bool = True,
    *,
    upstreams: list[UpstreamRecord] | None = None,
    lb_policy: str = "random",
  ) -> RouteRecord:
    """Insert a new route.

    The call can take either the legacy single `upstream_target` or a
    list of `upstreams`. When both are given the list wins; the legacy
    scalar column is set to the first upstream's target so older
    readers of `routes.upstream_target` still see something useful.
    """
    if lb_policy not in LB_POLICIES:
      raise ValueError(f"invalid lb_policy: {lb_policy}")
    effective_upstreams: list[UpstreamRecord]
    if upstreams:
      effective_upstreams = list(upstreams)
    elif upstream_target is not None:
      effective_upstreams = [UpstreamRecord(target=upstream_target, weight=1)]
    else:
      effective_upstreams = []
    primary = effective_upstreams[0].target if effective_upstreams else None

    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO routes (domain, upstream_target, enabled, updated_at, lb_policy)
          VALUES (%s, %s, %s, NOW(), %s)
          RETURNING domain
          """,
          (domain, primary, enabled, lb_policy),
        )
        if cursor.fetchone() is None:
          raise RuntimeError(f"insert did not return a row for domain: {domain}")
        for up in effective_upstreams:
          cursor.execute(
            """
            INSERT INTO route_upstreams (domain, target, weight, updated_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (domain, target) DO UPDATE
              SET weight = EXCLUDED.weight, updated_at = NOW()
            """,
            (domain, up.target, up.weight),
          )
      connection.commit()

    result = self.get_route(domain)
    if result is None:
      raise RuntimeError(f"route disappeared right after insert: {domain}")
    return result

  def update_route_target(self, domain: str, upstream_target: str | None) -> bool:
    """Legacy single-upstream update. Kept for older callers & CLI.

    Replaces the full upstream list with either zero rows (when the
    target is None) or one row containing `upstream_target`.
    """
    new_upstreams = (
      [UpstreamRecord(target=upstream_target, weight=1)]
      if upstream_target is not None
      else []
    )
    return self.replace_route_upstreams(domain, new_upstreams)

  def replace_route_upstreams(
    self, domain: str, upstreams: list[UpstreamRecord]
  ) -> bool:
    """Transactionally replace all upstreams for a domain.

    Returns True if the route exists (and therefore was updated), else
    False. The scalar `routes.upstream_target` mirror column is updated
    to match the new primary (first) upstream, or NULL when the list is
    empty, so existing backward-compat readers keep working.
    """
    primary = upstreams[0].target if upstreams else None
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          UPDATE routes
          SET upstream_target = %s, upstream_port = NULL, updated_at = NOW()
          WHERE domain = %s
          RETURNING domain
          """,
          (primary, domain),
        )
        if cursor.fetchone() is None:
          return False
        cursor.execute("DELETE FROM route_upstreams WHERE domain = %s", (domain,))
        for up in upstreams:
          cursor.execute(
            """
            INSERT INTO route_upstreams (domain, target, weight, updated_at)
            VALUES (%s, %s, %s, NOW())
            """,
            (domain, up.target, up.weight),
          )
      connection.commit()
      return True

  def set_route_lb_policy(self, domain: str, lb_policy: str) -> bool:
    if lb_policy not in LB_POLICIES:
      raise ValueError(f"invalid lb_policy: {lb_policy}")
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          UPDATE routes
          SET lb_policy = %s, updated_at = NOW()
          WHERE domain = %s
          RETURNING domain
          """,
          (lb_policy, domain),
        )
        row = cursor.fetchone()
      connection.commit()
      return row is not None

  def set_route_enabled(self, domain: str, enabled: bool) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          UPDATE routes
          SET enabled = %s, updated_at = NOW()
          WHERE domain = %s
          RETURNING domain
          """,
          (enabled, domain),
        )
        row = cursor.fetchone()
      connection.commit()
      return row is not None

  def delete_route(self, domain: str) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          "DELETE FROM routes WHERE domain = %s RETURNING domain",
          (domain,),
        )
        row = cursor.fetchone()
      connection.commit()
      return row is not None

  def purge_route(self, domain: str) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          "DELETE FROM certificates WHERE domain = %s",
          (domain,),
        )
        cursor.execute(
          "DELETE FROM routes WHERE domain = %s RETURNING domain",
          (domain,),
        )
        row = cursor.fetchone()
      connection.commit()
      return row is not None

  def fetch_certificates(self) -> dict[str, CertificateRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT domain, fullchain_pem, private_key_pem, not_before, not_after,
                 version, status, source, retry_after, updated_at, last_error
          FROM certificates
          WHERE status IN ('active', 'error')
          ORDER BY domain ASC
          """
        )
        return {row["domain"]: CertificateRecord(**row) for row in cursor.fetchall()}

  def list_dns_zone_tokens(self) -> list[DnsZoneTokenRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT zone_name, provider, zone_id, api_token, updated_at
          FROM dns_zone_tokens
          ORDER BY zone_name ASC
          """
        )
        return [DnsZoneTokenRecord(**row) for row in cursor.fetchall()]

  def upsert_dns_zone_token(
    self,
    zone_name: str,
    zone_id: str,
    api_token: str,
    provider: str = "cloudflare",
  ) -> DnsZoneTokenRecord:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO dns_zone_tokens (zone_name, provider, zone_id, api_token, updated_at)
          VALUES (%s, %s, %s, %s, NOW())
          ON CONFLICT (zone_name) DO UPDATE
          SET provider = EXCLUDED.provider,
              zone_id = EXCLUDED.zone_id,
              api_token = EXCLUDED.api_token,
              updated_at = NOW()
          RETURNING zone_name, provider, zone_id, api_token, updated_at
          """,
          (zone_name, provider, zone_id, api_token),
        )
        row = cursor.fetchone()
      connection.commit()
    if row is None:
      raise RuntimeError(f"upsert did not return a row for zone: {zone_name}")
    return DnsZoneTokenRecord(**row)

  def delete_dns_zone_token(self, zone_name: str) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          "DELETE FROM dns_zone_tokens WHERE zone_name = %s RETURNING zone_name",
          (zone_name,),
        )
        row = cursor.fetchone()
      connection.commit()
      return row is not None

  def get_dns_zone_token_for_domain(self, domain: str) -> DnsZoneTokenRecord | None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT zone_name, provider, zone_id, api_token, updated_at
          FROM dns_zone_tokens
          WHERE %s = zone_name OR %s LIKE '%%.' || zone_name
          ORDER BY char_length(zone_name) DESC
          LIMIT 1
          """,
          (domain, domain),
        )
        row = cursor.fetchone()
        return None if row is None else DnsZoneTokenRecord(**row)

  def upsert_certificate(self, certificate: CertificateRecord) -> None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO certificates (
            domain, fullchain_pem, private_key_pem, not_before, not_after,
            version, status, source, retry_after, updated_at, last_error
          ) VALUES (
            %(domain)s, %(fullchain_pem)s, %(private_key_pem)s, %(not_before)s, %(not_after)s,
            %(version)s, %(status)s, %(source)s, %(retry_after)s, NOW(), %(last_error)s
          )
          ON CONFLICT (domain) DO UPDATE
          SET
            fullchain_pem = EXCLUDED.fullchain_pem,
            private_key_pem = EXCLUDED.private_key_pem,
            not_before = EXCLUDED.not_before,
            not_after = EXCLUDED.not_after,
            version = certificates.version + 1,
            status = EXCLUDED.status,
            source = EXCLUDED.source,
            retry_after = EXCLUDED.retry_after,
            updated_at = NOW(),
            last_error = EXCLUDED.last_error
          """,
          {
            "domain": certificate.domain,
            "fullchain_pem": certificate.fullchain_pem,
            "private_key_pem": certificate.private_key_pem,
            "not_before": certificate.not_before,
            "not_after": certificate.not_after,
            "version": max(certificate.version, 1),
            "status": certificate.status,
            "source": certificate.source,
            "retry_after": certificate.retry_after,
            "last_error": certificate.last_error,
          },
        )
      connection.commit()

  def record_certificate_error(self, domain: str, last_error: str, retry_after: datetime) -> None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO certificates (
            domain, fullchain_pem, private_key_pem, not_before, not_after,
            version, status, source, retry_after, updated_at, last_error
          ) VALUES (
            %s, '', '', NOW(), NOW(),
            1, 'error', 'certbot', %s, NOW(), %s
          )
          ON CONFLICT (domain) DO UPDATE
          SET
            status = 'error',
            retry_after = EXCLUDED.retry_after,
            updated_at = NOW(),
            last_error = EXCLUDED.last_error
          """,
          (domain, retry_after, last_error),
        )
      connection.commit()

  def clear_certificate_retry_after(self, domain: str) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          UPDATE certificates
          SET retry_after = NULL, updated_at = NOW()
          WHERE domain = %s
          RETURNING domain
          """,
          (domain,),
        )
        row = cursor.fetchone()
      connection.commit()
      return row is not None

  # ---------- Node management ----------

  _NODE_COLUMNS = (
    "name, host, ssh_port, ssh_user, auth_method, "
    "ssh_password, ssh_private_key, ssh_key_passphrase, "
    "description, tags, deploy_command, update_command, "
    "created_at, updated_at, "
    "init_git_private_key, init_git_user_name, init_git_user_email, "
    "init_desired_ssh_port, init_install_codex, "
    "init_codex_base_url, init_codex_api_key, init_timezone"
  )

  @staticmethod
  def _row_to_node(row: dict) -> NodeRecord:
    return NodeRecord(
      name=row["name"],
      host=row["host"],
      ssh_port=int(row["ssh_port"]),
      ssh_user=row["ssh_user"],
      auth_method=row["auth_method"],
      ssh_password=row.get("ssh_password"),
      ssh_private_key=row.get("ssh_private_key"),
      ssh_key_passphrase=row.get("ssh_key_passphrase"),
      description=row.get("description"),
      tags=list(row.get("tags") or []),
      deploy_command=row.get("deploy_command"),
      update_command=row.get("update_command"),
      created_at=row["created_at"],
      updated_at=row["updated_at"],
      init_git_private_key=row.get("init_git_private_key"),
      init_git_user_name=row.get("init_git_user_name"),
      init_git_user_email=row.get("init_git_user_email"),
      init_desired_ssh_port=row.get("init_desired_ssh_port"),
      init_install_codex=bool(row["init_install_codex"]) if row.get("init_install_codex") is not None else True,
      init_codex_base_url=row.get("init_codex_base_url"),
      init_codex_api_key=row.get("init_codex_api_key"),
      init_timezone=row.get("init_timezone") or "Asia/Shanghai",
    )

  @staticmethod
  def _row_to_node_status(row: dict) -> NodeStatusRecord:
    return NodeStatusRecord(
      node_name=row["node_name"],
      reachable=bool(row["reachable"]),
      service_installed=row.get("service_installed"),
      service_running=row.get("service_running"),
      service_mode=row.get("service_mode"),
      service_version=row.get("service_version"),
      uptime_seconds=row.get("uptime_seconds"),
      load_avg=row.get("load_avg"),
      memory=row.get("memory"),
      disk_usage=row.get("disk_usage"),
      os_release=row.get("os_release"),
      last_probed_at=row.get("last_probed_at"),
      last_probe_error=row.get("last_probe_error"),
      raw_probe=row.get("raw_probe"),
    )

  def list_nodes(self) -> list[NodeRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(f"SELECT {self._NODE_COLUMNS} FROM nodes ORDER BY name ASC")
        return [self._row_to_node(row) for row in cursor.fetchall()]

  def get_node(self, name: str) -> NodeRecord | None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._NODE_COLUMNS} FROM nodes WHERE name = %s",
          (name,),
        )
        row = cursor.fetchone()
        return None if row is None else self._row_to_node(row)

  def insert_node(self, node: NodeRecord) -> NodeRecord:
    if node.auth_method not in NODE_AUTH_METHODS:
      raise ValueError(f"invalid auth_method: {node.auth_method}")
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"""
          INSERT INTO nodes (name, host, ssh_port, ssh_user, auth_method,
            ssh_password, ssh_private_key, ssh_key_passphrase,
            description, tags, deploy_command, update_command,
            init_git_private_key, init_git_user_name, init_git_user_email,
            init_desired_ssh_port, init_install_codex,
            init_codex_base_url, init_codex_api_key, init_timezone,
            created_at, updated_at)
          VALUES (%(name)s, %(host)s, %(ssh_port)s, %(ssh_user)s, %(auth_method)s,
            %(ssh_password)s, %(ssh_private_key)s, %(ssh_key_passphrase)s,
            %(description)s, %(tags)s, %(deploy_command)s, %(update_command)s,
            %(init_git_private_key)s, %(init_git_user_name)s, %(init_git_user_email)s,
            %(init_desired_ssh_port)s, %(init_install_codex)s,
            %(init_codex_base_url)s, %(init_codex_api_key)s, %(init_timezone)s,
            NOW(), NOW())
          RETURNING {self._NODE_COLUMNS}
          """,
          {
            "name": node.name,
            "host": node.host,
            "ssh_port": node.ssh_port,
            "ssh_user": node.ssh_user,
            "auth_method": node.auth_method,
            "ssh_password": node.ssh_password,
            "ssh_private_key": node.ssh_private_key,
            "ssh_key_passphrase": node.ssh_key_passphrase,
            "description": node.description,
            "tags": list(node.tags or []),
            "deploy_command": node.deploy_command,
            "update_command": node.update_command,
            "init_git_private_key": node.init_git_private_key,
            "init_git_user_name": node.init_git_user_name,
            "init_git_user_email": node.init_git_user_email,
            "init_desired_ssh_port": node.init_desired_ssh_port,
            "init_install_codex": node.init_install_codex,
            "init_codex_base_url": node.init_codex_base_url,
            "init_codex_api_key": node.init_codex_api_key,
            "init_timezone": node.init_timezone,
          },
        )
        row = cursor.fetchone()
      connection.commit()
    if row is None:
      raise RuntimeError(f"insert did not return row for node: {node.name}")
    return self._row_to_node(row)

  def update_node(self, name: str, fields: dict) -> NodeRecord | None:
    """Patch any subset of mutable fields by name. Unknown keys are ignored."""
    allowed = {
      "host", "ssh_port", "ssh_user", "auth_method",
      "ssh_password", "ssh_private_key", "ssh_key_passphrase",
      "description", "tags", "deploy_command", "update_command",
      "init_git_private_key", "init_git_user_name", "init_git_user_email",
      "init_desired_ssh_port", "init_install_codex",
      "init_codex_base_url", "init_codex_api_key", "init_timezone",
    }
    sets = []
    params: dict = {"name": name}
    for k, v in fields.items():
      if k not in allowed:
        continue
      sets.append(f"{k} = %({k})s")
      params[k] = v
    if not sets:
      return self.get_node(name)
    if "auth_method" in params and params["auth_method"] not in NODE_AUTH_METHODS:
      raise ValueError(f"invalid auth_method: {params['auth_method']}")
    sets.append("updated_at = NOW()")
    sql = f"UPDATE nodes SET {', '.join(sets)} WHERE name = %(name)s RETURNING {self._NODE_COLUMNS}"
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()
      connection.commit()
    return None if row is None else self._row_to_node(row)

  def delete_node(self, name: str) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute("DELETE FROM nodes WHERE name = %s RETURNING name", (name,))
        row = cursor.fetchone()
      connection.commit()
      return row is not None

  def rename_node(self, current_name: str, new_name: str) -> NodeRecord | None:
    """Rename a node. Relies on ON UPDATE CASCADE on the FKs so child
    tables (node_status, node_init_runs) follow automatically."""
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"""
          UPDATE nodes
          SET name = %s, updated_at = NOW()
          WHERE name = %s
          RETURNING {self._NODE_COLUMNS}
          """,
          (new_name, current_name),
        )
        row = cursor.fetchone()
      connection.commit()
    return None if row is None else self._row_to_node(row)

  def get_node_status(self, name: str) -> NodeStatusRecord | None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          "SELECT * FROM node_status WHERE node_name = %s",
          (name,),
        )
        row = cursor.fetchone()
        return None if row is None else self._row_to_node_status(row)

  def list_node_statuses(self) -> dict[str, NodeStatusRecord]:
    """List all node_status rows EXCLUDING raw_probe (which can be a
    multi-KB jsonb blob per row). The list endpoint never displays
    raw_probe; callers that need it should use get_node_status() for
    a single node instead."""
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT node_name, reachable, service_installed, service_running,
                 service_mode, service_version, uptime_seconds, load_avg,
                 memory, disk_usage, os_release, last_probed_at,
                 last_probe_error
          FROM node_status
          """
        )
        return {r["node_name"]: self._row_to_node_status(r) for r in cursor.fetchall()}

  def upsert_node_status(self, status: NodeStatusRecord) -> NodeStatusRecord:
    import json as _json
    raw = _json.dumps(status.raw_probe) if status.raw_probe is not None else None
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO node_status (node_name, reachable, service_installed, service_running,
            service_mode, service_version, uptime_seconds, load_avg, memory, disk_usage,
            os_release, last_probed_at, last_probe_error, raw_probe)
          VALUES (%(node_name)s, %(reachable)s, %(service_installed)s, %(service_running)s,
            %(service_mode)s, %(service_version)s, %(uptime_seconds)s, %(load_avg)s,
            %(memory)s, %(disk_usage)s, %(os_release)s, NOW(),
            %(last_probe_error)s, %(raw_probe)s::jsonb)
          ON CONFLICT (node_name) DO UPDATE SET
            reachable = EXCLUDED.reachable,
            service_installed = EXCLUDED.service_installed,
            service_running = EXCLUDED.service_running,
            service_mode = EXCLUDED.service_mode,
            service_version = EXCLUDED.service_version,
            uptime_seconds = EXCLUDED.uptime_seconds,
            load_avg = EXCLUDED.load_avg,
            memory = EXCLUDED.memory,
            disk_usage = EXCLUDED.disk_usage,
            os_release = EXCLUDED.os_release,
            last_probed_at = EXCLUDED.last_probed_at,
            last_probe_error = EXCLUDED.last_probe_error,
            raw_probe = EXCLUDED.raw_probe
          RETURNING *
          """,
          {
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
            "last_probe_error": status.last_probe_error,
            "raw_probe": raw,
          },
        )
        row = cursor.fetchone()
      connection.commit()
    return self._row_to_node_status(row)

  # ---------- Service catalog ----------

  _SERVICE_COLUMNS = (
    "name, display_name, description, github_repo_url, default_branch, "
    "compose_file, install_dir_template, default_env, "
    "pre_deploy_command, post_deploy_command, "
    "compose_template, config_files, created_at, updated_at, "
    "COALESCE(required_env, ARRAY[]::TEXT[]) AS required_env, "
    "COALESCE(healthcheck, '{}'::jsonb) AS healthcheck, "
    "COALESCE(depends_on, ARRAY[]::TEXT[]) AS depends_on, "
    "COALESCE(exposed_ports, ARRAY[]::INTEGER[]) AS exposed_ports, "
    "deploy_yaml, deploy_yaml_fetched_at"
  )

  @staticmethod
  def _row_to_service(row: dict) -> ServiceRecord:
    healthcheck = row.get("healthcheck") or {}
    if isinstance(healthcheck, str):
      import json as _json
      try: healthcheck = _json.loads(healthcheck)
      except Exception: healthcheck = {}
    return ServiceRecord(
      name=row["name"],
      display_name=row["display_name"],
      description=row.get("description"),
      github_repo_url=row["github_repo_url"],
      default_branch=row.get("default_branch") or "main",
      compose_file=row.get("compose_file") or "docker-compose.yml",
      install_dir_template=row.get("install_dir_template") or "/opt/{name}",
      default_env=dict(row.get("default_env") or {}),
      pre_deploy_command=row.get("pre_deploy_command"),
      post_deploy_command=row.get("post_deploy_command"),
      compose_template=row.get("compose_template"),
      config_files=dict(row.get("config_files") or {}),
      created_at=row["created_at"],
      updated_at=row["updated_at"],
      required_env=list(row.get("required_env") or []),
      healthcheck=dict(healthcheck) if isinstance(healthcheck, dict) else {},
      depends_on=list(row.get("depends_on") or []),
      exposed_ports=[int(p) for p in (row.get("exposed_ports") or [])],
      deploy_yaml=row.get("deploy_yaml"),
      deploy_yaml_fetched_at=row.get("deploy_yaml_fetched_at"),
    )

  def list_services(self) -> list[ServiceRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(f"SELECT {self._SERVICE_COLUMNS} FROM services ORDER BY name ASC")
        return [self._row_to_service(r) for r in cursor.fetchall()]

  def get_service(self, name: str) -> ServiceRecord | None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._SERVICE_COLUMNS} FROM services WHERE name = %s",
          (name,),
        )
        row = cursor.fetchone()
        return None if row is None else self._row_to_service(row)

  def insert_service(self, service: ServiceRecord) -> ServiceRecord:
    import json as _json
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"""
          INSERT INTO services (name, display_name, description, github_repo_url,
            default_branch, compose_file, install_dir_template,
            default_env, pre_deploy_command, post_deploy_command,
            compose_template, config_files,
            created_at, updated_at)
          VALUES (%(name)s, %(display_name)s, %(description)s, %(github_repo_url)s,
            %(default_branch)s, %(compose_file)s, %(install_dir_template)s,
            %(default_env)s::jsonb, %(pre_deploy_command)s, %(post_deploy_command)s,
            %(compose_template)s, %(config_files)s::jsonb,
            NOW(), NOW())
          RETURNING {self._SERVICE_COLUMNS}
          """,
          {
            "name": service.name,
            "display_name": service.display_name,
            "description": service.description,
            "github_repo_url": service.github_repo_url,
            "default_branch": service.default_branch,
            "compose_file": service.compose_file,
            "install_dir_template": service.install_dir_template,
            "default_env": _json.dumps(service.default_env or {}),
            "pre_deploy_command": service.pre_deploy_command,
            "post_deploy_command": service.post_deploy_command,
            "compose_template": service.compose_template,
            "config_files": _json.dumps(service.config_files or {}),
          },
        )
        row = cursor.fetchone()
      connection.commit()
    if row is None:
      raise RuntimeError(f"insert did not return service: {service.name}")
    return self._row_to_service(row)

  def update_service(self, name: str, fields: dict) -> ServiceRecord | None:
    import json as _json
    allowed = {"display_name", "description", "github_repo_url", "default_branch",
               "compose_file", "install_dir_template", "default_env",
               "pre_deploy_command", "post_deploy_command",
               "compose_template", "config_files",
               # Manifest fields written by the deploy machinery.
               "required_env", "healthcheck", "depends_on", "exposed_ports",
               "deploy_yaml", "deploy_yaml_fetched_at"}
    sets = []
    params: dict = {"name": name}
    for k, v in fields.items():
      if k not in allowed:
        continue
      if k in ("default_env", "config_files", "healthcheck"):
        sets.append(f"{k} = %({k})s::jsonb")
        params[k] = _json.dumps(v or {})
      elif k in ("required_env", "depends_on"):
        sets.append(f"{k} = %({k})s")
        params[k] = list(v or [])
      elif k == "exposed_ports":
        sets.append(f"{k} = %({k})s")
        params[k] = [int(p) for p in (v or [])]
      else:
        sets.append(f"{k} = %({k})s")
        params[k] = v
    if not sets:
      return self.get_service(name)
    sets.append("updated_at = NOW()")
    sql = f"UPDATE services SET {', '.join(sets)} WHERE name = %(name)s RETURNING {self._SERVICE_COLUMNS}"
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()
      connection.commit()
    return None if row is None else self._row_to_service(row)

  def delete_service(self, name: str) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute("DELETE FROM services WHERE name = %s RETURNING name", (name,))
        row = cursor.fetchone()
      connection.commit()
      return row is not None

  # ---------- Node init runs ----------

  @staticmethod
  def _row_to_init_run(row: dict) -> NodeInitRunRecord:
    return NodeInitRunRecord(
      id=int(row["id"]),
      node_name=row["node_name"],
      status=row["status"],
      current_step=row.get("current_step"),
      log_text=row.get("log_text") or "",
      exit_code=row.get("exit_code"),
      started_at=row["started_at"],
      finished_at=row.get("finished_at"),
      config_snapshot=row.get("config_snapshot"),
    )

  def insert_init_run(self, node_name: str, config_snapshot: dict | None = None) -> NodeInitRunRecord:
    import json as _json
    snap = _json.dumps(config_snapshot) if config_snapshot is not None else None
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO node_init_runs (node_name, status, current_step, log_text,
            exit_code, started_at, finished_at, config_snapshot)
          VALUES (%s, 'queued', NULL, '', NULL, NOW(), NULL, %s::jsonb)
          RETURNING id, node_name, status, current_step, log_text, exit_code, started_at, finished_at, config_snapshot
          """,
          (node_name, snap),
        )
        row = cursor.fetchone()
      connection.commit()
    if row is None:
      raise RuntimeError(f"failed to insert init run for: {node_name}")
    return self._row_to_init_run(row)

  def get_init_run(self, run_id: int) -> NodeInitRunRecord | None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT id, node_name, status, current_step, log_text, exit_code,
                 started_at, finished_at, config_snapshot
          FROM node_init_runs WHERE id = %s
          """,
          (run_id,),
        )
        row = cursor.fetchone()
        return None if row is None else self._row_to_init_run(row)

  def list_init_runs(self, node_name: str, limit: int = 20) -> list[NodeInitRunRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT id, node_name, status, current_step, log_text, exit_code,
                 started_at, finished_at, config_snapshot
          FROM node_init_runs WHERE node_name = %s
          ORDER BY started_at DESC LIMIT %s
          """,
          (node_name, limit),
        )
        return [self._row_to_init_run(r) for r in cursor.fetchall()]

  def latest_init_run_per_node(self, node_names: list[str]) -> dict[str, NodeInitRunRecord]:
    """Bulk: latest init run per node, for the supplied set. Single
    round-trip to the DB. Used by the pre-deploy "is initialized?" check."""
    if not node_names:
      return {}
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT DISTINCT ON (node_name)
                 id, node_name, status, current_step, log_text, exit_code,
                 started_at, finished_at, config_snapshot
          FROM node_init_runs
          WHERE node_name = ANY(%s)
          ORDER BY node_name, started_at DESC
          """,
          (list(node_names),),
        )
        return {r["node_name"]: self._row_to_init_run(r) for r in cursor.fetchall()}

  def update_init_run(
    self,
    run_id: int,
    *,
    status: str | None = None,
    current_step: str | None = None,
    append_log: str | None = None,
    exit_code: int | None = None,
    finished: bool = False,
  ) -> None:
    sets: list[str] = []
    params: dict = {"run_id": run_id}
    if status is not None:
      sets.append("status = %(status)s")
      params["status"] = status
    if current_step is not None:
      sets.append("current_step = %(current_step)s")
      params["current_step"] = current_step
    if append_log:
      sets.append("log_text = log_text || %(append_log)s")
      params["append_log"] = append_log
    if exit_code is not None:
      sets.append("exit_code = %(exit_code)s")
      params["exit_code"] = exit_code
    if finished:
      sets.append("finished_at = NOW()")
    if not sets:
      return
    sql = f"UPDATE node_init_runs SET {', '.join(sets)} WHERE id = %(run_id)s"
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(sql, params)
      connection.commit()

  # static IPs ------------------------------------------------------
  _STATIC_IP_COLUMNS = """
    id, ip, port, protocol, country, provider, label, notes,
    COALESCE(static_info, '{}'::jsonb) AS static_info,
    loop_test_seconds, last_test_at, last_test_success,
    last_test_latency_ms, last_test_error, last_probe_at,
    created_at, updated_at
  """

  def _row_to_static_ip(self, row: dict) -> StaticIpRecord:
    info = row["static_info"] or {}
    if isinstance(info, str):
      import json as _json
      try:
        info = _json.loads(info)
      except Exception as exc:  # noqa: BLE001
        LOGGER.warning("static_ips.id=%s static_info JSON decode failed: %s; raw[:200]=%r",
                       row.get("id"), exc, info[:200] if isinstance(info, str) else info)
        info = {}
    return StaticIpRecord(
      id=int(row["id"]),
      ip=row["ip"],
      port=(int(row["port"]) if row["port"] is not None else None),
      protocol=row["protocol"],
      country=row["country"],
      provider=row["provider"],
      label=row["label"],
      notes=row["notes"],
      static_info=info if isinstance(info, dict) else {},
      loop_test_seconds=(
        int(row["loop_test_seconds"]) if row["loop_test_seconds"] is not None else None
      ),
      last_test_at=row["last_test_at"],
      last_test_success=row["last_test_success"],
      last_test_latency_ms=(
        int(row["last_test_latency_ms"]) if row["last_test_latency_ms"] is not None else None
      ),
      last_test_error=row["last_test_error"],
      last_probe_at=row["last_probe_at"],
      created_at=row["created_at"],
      updated_at=row["updated_at"],
    )

  def list_static_ips(
    self,
    *,
    sort: str = "country",
  ) -> list[StaticIpRecord]:
    sort_clauses = {
      "country": "country NULLS LAST, provider NULLS LAST, ip ASC",
      "provider": "provider NULLS LAST, country NULLS LAST, ip ASC",
      "ip": "ip ASC",
      "created": "created_at DESC",
    }
    order = sort_clauses.get(sort, sort_clauses["country"])
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._STATIC_IP_COLUMNS} FROM static_ips ORDER BY {order}"
        )
        return [self._row_to_static_ip(r) for r in cursor.fetchall()]

  def get_static_ip(self, ip_id: int) -> StaticIpRecord | None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._STATIC_IP_COLUMNS} FROM static_ips WHERE id = %s",
          (int(ip_id),),
        )
        row = cursor.fetchone()
        return None if row is None else self._row_to_static_ip(row)

  def insert_static_ip(
    self,
    *,
    ip: str,
    port: int | None,
    protocol: str,
    country: str | None = None,
    provider: str | None = None,
    label: str | None = None,
    notes: str | None = None,
    static_info: dict | None = None,
    loop_test_seconds: int | None = None,
  ) -> StaticIpRecord:
    import json as _json
    info = _json.dumps(static_info or {})
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"""
          INSERT INTO static_ips
            (ip, port, protocol, country, provider, label, notes,
             static_info, loop_test_seconds)
          VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
          ON CONFLICT (ip, COALESCE(port, 0), protocol) DO UPDATE SET
            country = COALESCE(EXCLUDED.country, static_ips.country),
            provider = COALESCE(EXCLUDED.provider, static_ips.provider),
            label = COALESCE(EXCLUDED.label, static_ips.label),
            notes = COALESCE(EXCLUDED.notes, static_ips.notes),
            updated_at = NOW()
          RETURNING {self._STATIC_IP_COLUMNS}
          """,
          (ip, port, protocol, country, provider, label, notes, info, loop_test_seconds),
        )
        row = cursor.fetchone()
      connection.commit()
      return self._row_to_static_ip(row)

  # Whitelist of columns the admin layer is allowed to update on
  # static_ips. Treat this as the SQL identifier safety boundary —
  # f-strings below are only safe BECAUSE every key is checked against
  # this set before substitution.
  _STATIC_IP_UPDATABLE_COLUMNS: frozenset[str] = frozenset({
    "ip", "port", "protocol", "country", "provider", "label", "notes",
    "static_info", "loop_test_seconds",
    "last_test_at", "last_test_success", "last_test_latency_ms",
    "last_test_error", "last_probe_at",
  })

  def bulk_insert_static_ips(
    self, records: list[dict]
  ) -> tuple[list[StaticIpRecord], list[dict]]:
    """Bulk-upsert many records in a single round trip.

    Each record dict can have ``ip`` (required) plus any of ``port``,
    ``protocol``, ``country``, ``provider``, ``label``, ``notes``,
    ``loop_test_seconds``. Same ON CONFLICT semantics as
    ``insert_static_ip``.

    Returns ``(committed_records, per_record_errors)``. Errors are
    surfaced for rows that fail validation BEFORE the SQL is sent;
    the bulk SQL itself is all-or-nothing — if it fails, the whole
    list goes into the error bucket so the caller can fall back to
    per-row inserts.
    """
    import json as _json
    if not records:
      return [], []

    valid: list[tuple] = []
    raw_for_index: list[dict] = []
    pre_errors: list[dict] = []
    for rec in records:
      ip = (rec.get("ip") or "").strip()
      if not ip:
        pre_errors.append({"input": rec, "error": "empty ip"})
        continue
      port = rec.get("port")
      if port == "":
        port = None
      protocol = (rec.get("protocol") or "tcp")
      country = rec.get("country") or None
      provider = rec.get("provider") or None
      label = rec.get("label") or None
      notes = rec.get("notes") or None
      info = _json.dumps(rec.get("static_info") or {})
      loop_seconds = rec.get("loop_test_seconds")
      valid.append((
        ip, port, protocol, country, provider, label, notes, info, loop_seconds,
      ))
      raw_for_index.append(rec)

    if not valid:
      return [], pre_errors

    placeholders = ",\n          ".join(
      ["(%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)"] * len(valid)
    )
    sql = f"""
      INSERT INTO static_ips
        (ip, port, protocol, country, provider, label, notes,
         static_info, loop_test_seconds)
      VALUES
        {placeholders}
      ON CONFLICT (ip, COALESCE(port, 0), protocol) DO UPDATE SET
        country = COALESCE(EXCLUDED.country, static_ips.country),
        provider = COALESCE(EXCLUDED.provider, static_ips.provider),
        label = COALESCE(EXCLUDED.label, static_ips.label),
        notes = COALESCE(EXCLUDED.notes, static_ips.notes),
        updated_at = NOW()
      RETURNING {self._STATIC_IP_COLUMNS}
    """
    flat: list = []
    for tup in valid:
      flat.extend(tup)
    try:
      with self.connect() as connection:
        with connection.cursor() as cursor:
          cursor.execute(sql, flat)
          rows = cursor.fetchall()
        connection.commit()
    except Exception as exc:  # noqa: BLE001
      LOGGER.exception("bulk_insert_static_ips failed for %d rows", len(valid))
      # Surface each row as an error so the caller can decide on a
      # fallback path.
      pre_errors.extend(
        {"input": r, "error": f"bulk insert failed: {exc}"[:300]}
        for r in raw_for_index
      )
      return [], pre_errors
    return [self._row_to_static_ip(r) for r in rows], pre_errors

  def update_static_ip(self, ip_id: int, fields: dict) -> StaticIpRecord | None:
    if not fields:
      return self.get_static_ip(ip_id)
    sets: list[str] = []
    params: list = []
    for key, value in fields.items():
      if key not in self._STATIC_IP_UPDATABLE_COLUMNS:
        continue
      if key == "static_info":
        import json as _json
        sets.append(f"{key} = %s::jsonb")
        params.append(_json.dumps(value or {}))
      else:
        sets.append(f"{key} = %s")
        params.append(value)
    if not sets:
      return self.get_static_ip(ip_id)
    params.append(int(ip_id))
    sql = (
      f"UPDATE static_ips SET {', '.join(sets)} "
      f"WHERE id = %s RETURNING {self._STATIC_IP_COLUMNS}"
    )
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()
      connection.commit()
      return None if row is None else self._row_to_static_ip(row)

  def delete_static_ip(self, ip_id: int) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute("DELETE FROM static_ips WHERE id = %s", (int(ip_id),))
        deleted = cursor.rowcount
      connection.commit()
      return deleted > 0

  def insert_ip_test_result(
    self,
    *,
    ip_id: int,
    test_kind: str,
    success: bool,
    latency_ms: int | None,
    error: str | None,
    raw: dict | None = None,
  ) -> IpTestResultRecord:
    import json as _json
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO ip_test_results
            (ip_id, test_kind, success, latency_ms, error, raw)
          VALUES (%s, %s, %s, %s, %s, %s::jsonb)
          RETURNING id, ip_id, test_kind, success, latency_ms, error, raw, created_at
          """,
          (int(ip_id), test_kind, bool(success), latency_ms, error, _json.dumps(raw or {})),
        )
        row = cursor.fetchone()
      connection.commit()
    raw_val = row["raw"] or {}
    if isinstance(raw_val, str):
      try:
        raw_val = _json.loads(raw_val)
      except Exception:
        raw_val = {}
    return IpTestResultRecord(
      id=int(row["id"]),
      ip_id=int(row["ip_id"]),
      test_kind=row["test_kind"],
      success=row["success"],
      latency_ms=(int(row["latency_ms"]) if row["latency_ms"] is not None else None),
      error=row["error"],
      raw=raw_val if isinstance(raw_val, dict) else {},
      created_at=row["created_at"],
    )

  def list_ip_test_results(
    self, ip_id: int, *, limit: int = 100
  ) -> list[IpTestResultRecord]:
    import json as _json
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT id, ip_id, test_kind, success, latency_ms, error,
                 COALESCE(raw, '{}'::jsonb) AS raw, created_at
          FROM ip_test_results
          WHERE ip_id = %s
          ORDER BY created_at DESC
          LIMIT %s
          """,
          (int(ip_id), int(limit)),
        )
        out: list[IpTestResultRecord] = []
        for r in cursor.fetchall():
          raw_val = r["raw"] or {}
          if isinstance(raw_val, str):
            try:
              raw_val = _json.loads(raw_val)
            except Exception:
              raw_val = {}
          out.append(IpTestResultRecord(
            id=int(r["id"]),
            ip_id=int(r["ip_id"]),
            test_kind=r["test_kind"],
            success=r["success"],
            latency_ms=(int(r["latency_ms"]) if r["latency_ms"] is not None else None),
            error=r["error"],
            raw=raw_val if isinstance(raw_val, dict) else {},
            created_at=r["created_at"],
          ))
        return out

  # service_deployments --------------------------------------------
  _DEPLOYMENT_COLUMNS = (
    "id, service_name, node_name, revision, status, "
    "healthcheck_passed, healthcheck_detail, "
    "COALESCE(env_snapshot, '{}'::jsonb) AS env_snapshot, "
    "log_text, exit_code, started_at, finished_at, triggered_by"
  )

  @staticmethod
  def _row_to_deployment(row: dict) -> ServiceDeploymentRecord:
    snap = row.get("env_snapshot") or {}
    if isinstance(snap, str):
      import json as _json
      try: snap = _json.loads(snap)
      except Exception: snap = {}
    return ServiceDeploymentRecord(
      id=int(row["id"]),
      service_name=row["service_name"],
      node_name=row["node_name"],
      revision=row.get("revision"),
      status=row["status"],
      healthcheck_passed=row.get("healthcheck_passed"),
      healthcheck_detail=row.get("healthcheck_detail"),
      env_snapshot=dict(snap) if isinstance(snap, dict) else {},
      log_text=row.get("log_text") or "",
      exit_code=(int(row["exit_code"]) if row.get("exit_code") is not None else None),
      started_at=row["started_at"],
      finished_at=row.get("finished_at"),
      triggered_by=row.get("triggered_by"),
    )

  def insert_service_deployment(
    self,
    *,
    service_name: str,
    node_name: str,
    revision: str | None,
    env_snapshot: dict,
    triggered_by: str | None = None,
  ) -> ServiceDeploymentRecord:
    import json as _json
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"""
          INSERT INTO service_deployments
            (service_name, node_name, revision, status, env_snapshot, triggered_by)
          VALUES (%s, %s, %s, 'running', %s::jsonb, %s)
          RETURNING {self._DEPLOYMENT_COLUMNS}
          """,
          (service_name, node_name, revision,
           _json.dumps(env_snapshot or {}), triggered_by),
        )
        row = cursor.fetchone()
      connection.commit()
    return self._row_to_deployment(row)

  def finalize_service_deployment(
    self,
    deployment_id: int,
    *,
    status: str,
    healthcheck_passed: bool | None,
    healthcheck_detail: str | None,
    log_text: str,
    exit_code: int | None,
    revision: str | None = None,
  ) -> ServiceDeploymentRecord | None:
    sets = ["status = %s", "healthcheck_passed = %s", "healthcheck_detail = %s",
            "log_text = %s", "exit_code = %s", "finished_at = NOW()"]
    params: list = [status, healthcheck_passed, healthcheck_detail,
                    log_text or "", exit_code]
    if revision is not None:
      sets.append("revision = %s")
      params.append(revision)
    params.append(int(deployment_id))
    sql = (
      f"UPDATE service_deployments SET {', '.join(sets)} "
      f"WHERE id = %s RETURNING {self._DEPLOYMENT_COLUMNS}"
    )
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()
      connection.commit()
    return None if row is None else self._row_to_deployment(row)

  def list_service_deployments(
    self, *, service_name: str | None = None,
    node_name: str | None = None, limit: int = 50,
  ) -> list[ServiceDeploymentRecord]:
    where = []
    params: list = []
    if service_name:
      where.append("service_name = %s")
      params.append(service_name)
    if node_name:
      where.append("node_name = %s")
      params.append(node_name)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    params.append(int(limit))
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._DEPLOYMENT_COLUMNS} FROM service_deployments "
          f"{clause} ORDER BY started_at DESC LIMIT %s",
          params,
        )
        return [self._row_to_deployment(r) for r in cursor.fetchall()]

  def upsert_service_node_state(
    self, *, service_name: str, node_name: str,
    revision: str | None, status: str | None,
    last_deployment_id: int | None,
  ) -> None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO service_node_state
            (service_name, node_name, revision, status, last_deployment_id, updated_at)
          VALUES (%s, %s, %s, %s, %s, NOW())
          ON CONFLICT (service_name, node_name) DO UPDATE SET
            revision = EXCLUDED.revision,
            status = EXCLUDED.status,
            last_deployment_id = EXCLUDED.last_deployment_id,
            updated_at = NOW()
          """,
          (service_name, node_name, revision, status, last_deployment_id),
        )
      connection.commit()

  def list_service_node_states(
    self, *, service_name: str | None = None,
  ) -> list[ServiceNodeStateRecord]:
    where = ""
    params: list = []
    if service_name:
      where = "WHERE service_name = %s"
      params.append(service_name)
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"""SELECT service_name, node_name, revision, status,
                     last_deployment_id, updated_at
              FROM service_node_state {where}
              ORDER BY service_name, node_name""",
          params,
        )
        return [
          ServiceNodeStateRecord(
            service_name=r["service_name"],
            node_name=r["node_name"],
            revision=r.get("revision"),
            status=r.get("status"),
            last_deployment_id=(int(r["last_deployment_id"])
                                 if r.get("last_deployment_id") is not None else None),
            updated_at=r["updated_at"],
          )
          for r in cursor.fetchall()
        ]

  # ssh_keys --------------------------------------------------------
  _SSH_KEY_COLUMNS = """
    id, name, description, key_type, bits, private_key, public_key,
    fingerprint_sha256, comment, passphrase, source,
    COALESCE(tags, ARRAY[]::TEXT[]) AS tags,
    created_at, updated_at
  """

  _SSH_KEY_UPDATABLE_COLUMNS: frozenset[str] = frozenset({
    "name", "description", "comment", "passphrase", "tags",
    "private_key", "public_key", "fingerprint_sha256", "key_type", "bits",
    "source",
  })

  def _row_to_ssh_key(self, row: dict) -> SshKeyRecord:
    return SshKeyRecord(
      id=int(row["id"]),
      name=row["name"],
      description=row["description"],
      key_type=row["key_type"],
      bits=int(row["bits"]) if row["bits"] is not None else None,
      private_key=row["private_key"],
      public_key=row["public_key"],
      fingerprint_sha256=row["fingerprint_sha256"],
      comment=row["comment"],
      passphrase=row["passphrase"],
      source=row["source"],
      tags=list(row["tags"] or []),
      created_at=row["created_at"],
      updated_at=row["updated_at"],
    )

  def list_ssh_keys(self) -> list[SshKeyRecord]:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._SSH_KEY_COLUMNS} FROM ssh_keys ORDER BY name ASC"
        )
        return [self._row_to_ssh_key(r) for r in cursor.fetchall()]

  def get_ssh_key(self, key_id: int) -> SshKeyRecord | None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._SSH_KEY_COLUMNS} FROM ssh_keys WHERE id = %s",
          (int(key_id),),
        )
        row = cursor.fetchone()
        return None if row is None else self._row_to_ssh_key(row)

  def get_ssh_key_by_name(self, name: str) -> SshKeyRecord | None:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"SELECT {self._SSH_KEY_COLUMNS} FROM ssh_keys WHERE name = %s",
          (name,),
        )
        row = cursor.fetchone()
        return None if row is None else self._row_to_ssh_key(row)

  def insert_ssh_key(
    self,
    *,
    name: str,
    key_type: str,
    bits: int | None,
    private_key: str,
    public_key: str,
    fingerprint_sha256: str,
    comment: str | None = None,
    passphrase: str | None = None,
    description: str | None = None,
    source: str = "generated",
    tags: list[str] | None = None,
  ) -> SshKeyRecord:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          f"""
          INSERT INTO ssh_keys
            (name, description, key_type, bits, private_key, public_key,
             fingerprint_sha256, comment, passphrase, source, tags)
          VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
          RETURNING {self._SSH_KEY_COLUMNS}
          """,
          (
            name, description, key_type, bits, private_key, public_key,
            fingerprint_sha256, comment, passphrase, source,
            list(tags or []),
          ),
        )
        row = cursor.fetchone()
      connection.commit()
    return self._row_to_ssh_key(row)

  def update_ssh_key(self, key_id: int, fields: dict) -> SshKeyRecord | None:
    if not fields:
      return self.get_ssh_key(key_id)
    sets: list[str] = []
    params: list = []
    for key, value in fields.items():
      if key not in self._SSH_KEY_UPDATABLE_COLUMNS:
        continue
      sets.append(f"{key} = %s")
      params.append(value)
    if not sets:
      return self.get_ssh_key(key_id)
    params.append(int(key_id))
    sql = (
      f"UPDATE ssh_keys SET {', '.join(sets)} "
      f"WHERE id = %s RETURNING {self._SSH_KEY_COLUMNS}"
    )
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()
      connection.commit()
    return None if row is None else self._row_to_ssh_key(row)

  def delete_ssh_key(self, key_id: int) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute("DELETE FROM ssh_keys WHERE id = %s", (int(key_id),))
        deleted = cursor.rowcount
      connection.commit()
      return deleted > 0

  def count_nodes_using_key(self, private_key: str, *, key_id: int | None = None) -> int:
    """Return how many nodes use this key — either inlined in
    ``nodes.ssh_private_key`` OR linked via ``node_ssh_keys`` (when
    ``key_id`` is provided). Counted once per node even if both
    paths apply."""
    with self.connect() as connection:
      with connection.cursor() as cursor:
        if key_id is None and not private_key:
          return 0
        if key_id is None:
          cursor.execute(
            "SELECT COUNT(*) AS n FROM nodes WHERE ssh_private_key = %s",
            (private_key,),
          )
        else:
          cursor.execute(
            """
            SELECT COUNT(*) AS n FROM (
              SELECT name FROM nodes WHERE ssh_private_key = %s
              UNION
              SELECT node_name AS name FROM node_ssh_keys WHERE ssh_key_id = %s
            ) u
            """,
            (private_key or "", int(key_id)),
          )
        row = cursor.fetchone()
        return int(row["n"]) if row else 0

  # node ↔ ssh_key linkage ------------------------------------------
  def list_node_ssh_key_links(self, node_name: str) -> list[dict]:
    """Returns ``[{ssh_key_id, name, key_type, bits, fingerprint_sha256,
    private_key, passphrase, priority}, …]`` ordered by priority."""
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT k.id AS ssh_key_id, k.name, k.key_type, k.bits,
                 k.fingerprint_sha256, k.private_key, k.passphrase,
                 l.priority
          FROM node_ssh_keys l
          JOIN ssh_keys k ON k.id = l.ssh_key_id
          WHERE l.node_name = %s
          ORDER BY l.priority ASC, k.name ASC
          """,
          (node_name,),
        )
        return list(cursor.fetchall())

  def list_all_node_ssh_key_links(self) -> dict[str, list[dict]]:
    """Bulk variant — one round trip, groups by node_name. Used by the
    /api/nodes list endpoint to avoid N+1 over a remote DB."""
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          SELECT l.node_name,
                 k.id AS ssh_key_id, k.name, k.key_type, k.bits,
                 k.fingerprint_sha256, k.private_key, k.passphrase,
                 l.priority
          FROM node_ssh_keys l
          JOIN ssh_keys k ON k.id = l.ssh_key_id
          ORDER BY l.node_name ASC, l.priority ASC, k.name ASC
          """,
        )
        out: dict[str, list[dict]] = {}
        for row in cursor.fetchall():
          out.setdefault(row["node_name"], []).append({
            "ssh_key_id": row["ssh_key_id"],
            "name": row["name"],
            "key_type": row["key_type"],
            "bits": row["bits"],
            "fingerprint_sha256": row["fingerprint_sha256"],
            "private_key": row["private_key"],
            "passphrase": row["passphrase"],
            "priority": row["priority"],
          })
        return out

  def set_node_ssh_keys(
    self, node_name: str, key_ids: list[int],
  ) -> None:
    """Replace a node's linked-key set with exactly ``key_ids``."""
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          "DELETE FROM node_ssh_keys WHERE node_name = %s",
          (node_name,),
        )
        if key_ids:
          # priority defaults to insertion order * 10 so the operator
          # can re-order via UI later if we expose it.
          values = []
          for idx, kid in enumerate(key_ids):
            values.append((node_name, int(kid), 100 + idx * 10))
          cursor.executemany(
            "INSERT INTO node_ssh_keys (node_name, ssh_key_id, priority) "
            "VALUES (%s, %s, %s) ON CONFLICT (node_name, ssh_key_id) DO NOTHING",
            values,
          )
      connection.commit()

  def attach_ssh_key_to_node(self, node_name: str, private_key: str,
                              passphrase: str | None) -> bool:
    """Copy a key's private material into a node row, switching it to key auth."""
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          UPDATE nodes
          SET auth_method = 'key',
              ssh_private_key = %s,
              ssh_key_passphrase = %s,
              ssh_password = NULL,
              updated_at = NOW()
          WHERE name = %s
          """,
          (private_key, passphrase, node_name),
        )
        affected = cursor.rowcount
      connection.commit()
      return affected > 0

  # system_config -------------------------------------------------
  def list_system_config(self) -> dict[str, dict]:
    import json as _json
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          "SELECT key, COALESCE(value, '{}'::jsonb) AS value FROM system_config ORDER BY key"
        )
        out: dict[str, dict] = {}
        for row in cursor.fetchall():
          val = row["value"]
          if isinstance(val, str):
            try:
              val = _json.loads(val)
            except Exception:
              val = {}
          out[row["key"]] = val if isinstance(val, dict) else {}
        return out

  def get_system_config(self, key: str) -> dict | None:
    import json as _json
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          "SELECT COALESCE(value, '{}'::jsonb) AS value FROM system_config WHERE key = %s",
          (key,),
        )
        row = cursor.fetchone()
        if row is None:
          return None
        val = row["value"]
        if isinstance(val, str):
          try:
            val = _json.loads(val)
          except Exception:
            val = {}
        return val if isinstance(val, dict) else {}

  def upsert_system_config(self, key: str, value: dict) -> dict:
    import json as _json
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute(
          """
          INSERT INTO system_config (key, value)
          VALUES (%s, %s::jsonb)
          ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
          RETURNING COALESCE(value, '{}'::jsonb) AS value
          """,
          (key, _json.dumps(value or {})),
        )
        row = cursor.fetchone()
      connection.commit()
    val = row["value"]
    if isinstance(val, str):
      try:
        val = _json.loads(val)
      except Exception:
        val = {}
    return val if isinstance(val, dict) else {}

  def delete_system_config(self, key: str) -> bool:
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute("DELETE FROM system_config WHERE key = %s", (key,))
        deleted = cursor.rowcount
      connection.commit()
      return deleted > 0

  def try_advisory_lock(self, connection: psycopg.Connection, key: str) -> bool:
    with connection.cursor() as cursor:
      cursor.execute("SELECT pg_try_advisory_lock(hashtext(%s)) AS locked", (key,))
      row = cursor.fetchone()
      return bool(row["locked"])

  def unlock(self, connection: psycopg.Connection, key: str) -> None:
    with connection.cursor() as cursor:
      cursor.execute("SELECT pg_advisory_unlock(hashtext(%s))", (key,))
