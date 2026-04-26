from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator

import psycopg
from psycopg.rows import dict_row


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


NODE_AUTH_METHODS = ("password", "key")


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


class Database:
  def __init__(self, dsn: str) -> None:
    self._dsn = dsn

  @contextmanager
  def connect(self) -> Iterator[psycopg.Connection]:
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
    with self.connect() as connection:
      with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM node_status")
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
    "compose_template, config_files, created_at, updated_at"
  )

  @staticmethod
  def _row_to_service(row: dict) -> ServiceRecord:
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
               "compose_template", "config_files"}
    sets = []
    params: dict = {"name": name}
    for k, v in fields.items():
      if k not in allowed:
        continue
      if k in ("default_env", "config_files"):
        sets.append(f"{k} = %({k})s::jsonb")
        params[k] = _json.dumps(v or {})
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

  def try_advisory_lock(self, connection: psycopg.Connection, key: str) -> bool:
    with connection.cursor() as cursor:
      cursor.execute("SELECT pg_try_advisory_lock(hashtext(%s)) AS locked", (key,))
      row = cursor.fetchone()
      return bool(row["locked"])

  def unlock(self, connection: psycopg.Connection, key: str) -> None:
    with connection.cursor() as cursor:
      cursor.execute("SELECT pg_advisory_unlock(hashtext(%s))", (key,))
