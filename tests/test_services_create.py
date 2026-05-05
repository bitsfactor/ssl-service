"""End-to-end test of the New Service flow (services_create.create_service).

The flow's external dependencies are:
  - filesystem (real, into a tempdir)
  - git CLI (real, on PATH)
  - GitHub REST API (mocked — we stub services_create._github_create_repo
    and rewrite the push remote so it lands in a local bare repo)
  - PostgreSQL (substituted with FakeDb below — implements the methods
    services_create / admin call against Database)

This means every step except real GitHub network IO is exercised
against actual code. The test asserts on:
  - structured per-step progress
  - rendered file tree on disk
  - git history (initial commit on main)
  - in-memory DB state (services row, routes row, route ↔ service link)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

# Make `src/` importable when running pytest from anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ssl_proxy_controller import services_create  # noqa: E402
from ssl_proxy_controller.db import (  # noqa: E402
  NodeRecord,
  RouteRecord,
  ServiceRecord,
  UpstreamRecord,
)


# ---------------------------------------------------------------------------
# In-memory Database substitute
# ---------------------------------------------------------------------------


@dataclass
class FakeDb:
  """Implements just the Database surface area services_create relies on.
  Everything is in-memory dicts; tests inspect them directly."""

  services: dict[str, ServiceRecord] = field(default_factory=dict)
  routes: dict[str, RouteRecord] = field(default_factory=dict)
  route_service_name: dict[str, str | None] = field(default_factory=dict)
  nodes: dict[str, NodeRecord] = field(default_factory=dict)
  config: dict[str, dict] = field(default_factory=dict)

  # ---- system_config ---------------------------------------------------

  def get_system_config(self, key: str) -> dict | None:
    return self.config.get(key)

  # ---- nodes -----------------------------------------------------------

  def get_node(self, name: str) -> NodeRecord | None:
    return self.nodes.get(name)

  def list_nodes(self) -> list[NodeRecord]:
    return list(self.nodes.values())

  # ---- services --------------------------------------------------------

  def list_services(self) -> list[ServiceRecord]:
    return list(self.services.values())

  def get_service(self, name: str) -> ServiceRecord | None:
    return self.services.get(name)

  def insert_service(self, record: ServiceRecord) -> ServiceRecord:
    if record.name in self.services:
      raise RuntimeError(f"duplicate service: {record.name}")
    # Mimic the real DB: stamp created_at/updated_at, leave the rest of the
    # ServiceRecord as-is (we already populated it in services_create).
    now = datetime.now(UTC)
    record.created_at = now
    record.updated_at = now
    self.services[record.name] = record
    return record

  def update_service(self, name: str, fields: dict) -> ServiceRecord | None:
    s = self.services.get(name)
    if s is None:
      return None
    allowed = {
      "display_name", "description", "github_repo_url", "default_branch",
      "compose_file", "install_dir_template", "default_env",
      "pre_deploy_command", "post_deploy_command",
      "compose_template", "config_files",
      "required_env", "healthcheck", "depends_on", "exposed_ports",
      "deploy_yaml", "deploy_yaml_fetched_at", "config_schema",
      "assigned_port", "local_repo_dir", "default_node_name",
      "status", "product_yaml", "product_enabled",
    }
    for k, v in fields.items():
      if k in allowed:
        setattr(s, k, v)
    s.updated_at = datetime.now(UTC)
    return s

  # ---- routes ----------------------------------------------------------

  def get_route(self, domain: str) -> RouteRecord | None:
    return self.routes.get(domain)

  def list_routes(self) -> list[RouteRecord]:
    return list(self.routes.values())

  def insert_route(
    self,
    domain: str,
    upstream_target: str | None,
    enabled: bool = True,
    *,
    upstreams: list[UpstreamRecord] | None = None,
    lb_policy: str = "random",
  ) -> RouteRecord:
    if domain in self.routes:
      raise RuntimeError(f"duplicate route: {domain}")
    effective = list(upstreams or [])
    if not effective and upstream_target:
      effective = [UpstreamRecord(target=upstream_target, weight=1)]
    primary = effective[0].target if effective else None
    rec = RouteRecord(
      domain=domain,
      upstream_target=primary,
      enabled=enabled,
      updated_at=datetime.now(UTC),
      upstreams=effective,
      lb_policy=lb_policy,
    )
    self.routes[domain] = rec
    return rec

  def set_route_service(self, domain: str, service_name: str | None) -> bool:
    if domain not in self.routes:
      return False
    self.route_service_name[domain] = service_name
    return True

  # ---- atomic create ---------------------------------------------------

  # Tests can inject a mid-flight failure here to exercise rollback —
  # set this to one of {"after_service_insert", "after_route_insert"}.
  fail_atomic_at: str | None = None

  def create_service_and_route_atomic(
    self,
    service: ServiceRecord,
    *,
    manifest_fields: dict,
    route_domain: str,
    route_upstreams: list[UpstreamRecord],
    route_lb_policy: str = "random",
  ):
    """In-memory equivalent of Database.create_service_and_route_atomic.

    Real Postgres transactions roll back on any exception inside the
    `with self.connect()` block. Here we simulate that by snapshotting
    the in-memory state at entry and restoring it if anything raises —
    the test sees the same all-or-nothing semantics it would see
    against a real DB.
    """
    snap_services = dict(self.services)
    snap_routes = dict(self.routes)
    snap_route_svc = dict(self.route_service_name)
    try:
      self.insert_service(service)
      self.update_service(service.name, manifest_fields)
      if self.fail_atomic_at == "after_service_insert":
        raise RuntimeError("injected failure: after_service_insert")
      self.insert_route(
        route_domain, upstream_target=None, enabled=True,
        upstreams=route_upstreams, lb_policy=route_lb_policy,
      )
      if self.fail_atomic_at == "after_route_insert":
        raise RuntimeError("injected failure: after_route_insert")
      self.set_route_service(route_domain, service.name)
    except Exception:
      self.services = snap_services
      self.routes = snap_routes
      self.route_service_name = snap_route_svc
      raise
    return self.services[service.name], self.routes[route_domain]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def workdir(tmp_path: Path):
  """Tempdir layout shared across tests:
      <tmp>/
        repos/        -- where create_service renders new services
        fakegh/       -- bare git repos that simulate GitHub
  """
  (tmp_path / "repos").mkdir()
  (tmp_path / "fakegh").mkdir()
  return tmp_path


@pytest.fixture
def db(workdir: Path):
  d = FakeDb()
  # Sane defaults that satisfy _resolve_settings.
  d.config["services.local_repos_dir"] = {"path": str(workdir / "repos")}
  d.config["services.port_pool"] = {"start": 8100, "end": 8110}
  d.config["services.default_domain_suffix"] = {"suffix": "develop.cc"}
  d.config["github.api_token"] = {"token": "ghp_FAKE_TOKEN"}
  # One node so validate_node passes.
  d.nodes["dev-1"] = NodeRecord(
    name="dev-1", host="10.0.0.1", ssh_port=22, ssh_user="root",
    # validate_node requires at least one credential path; give dev-1
    # an inline key so the happy-path tests pass. The
    # test_validate_node_rejects_no_ssh_credentials test below uses a
    # separate node it constructs ad-hoc.
    auth_method="key", ssh_password=None,
    ssh_private_key="-----BEGIN OPENSSH KEY-----\nfake-key-for-tests\n",
    ssh_key_passphrase=None, description=None, tags=[],
    deploy_command=None, update_command=None,
    created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
  )
  return d


@pytest.fixture
def patch_github(monkeypatch, workdir: Path):
  """Patch services_create's GitHub-touching helpers so the test never
  hits the network. Returns a small object the test can use to inspect
  what would have been sent.
  """
  calls: dict[str, Any] = {"created": [], "push_target": None}

  def fake_create_repo(token, repo_name):
    # The real implementation always goes through /user/repos and the
    # owner comes back in the response's full_name. Fake that here.
    resolved_owner = "token-user"
    calls["created"].append({
      "token": token, "repo": repo_name, "resolved_owner": resolved_owner,
    })
    # Materialise a bare repo at <fakegh>/<owner>__<repo>.git so the
    # subsequent `git push` lands somewhere real.
    bare = workdir / "fakegh" / f"{resolved_owner}__{repo_name}.git"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(bare)],
                   check=True, capture_output=True)
    return resolved_owner

  monkeypatch.setattr(services_create, "_github_create_repo", fake_create_repo)

  # Override `_run` *only* for the `git remote add origin <token-url>` call
  # so the URL points at our local bare repo. The unmodified _run still runs
  # for git init / commit / push / set-url.
  real_run = services_create._run

  def smart_run(cmd, *, cwd):
    # Translate any github.com URL in this argv to the local bare repo.
    if cmd[:3] == ["git", "remote", "add"] and len(cmd) >= 5:
      url = cmd[4]
      if "github.com/" in url:
        # Extract owner/repo from URL.
        tail = url.split("github.com/", 1)[1].rstrip(".git")
        owner_repo = tail.split("/", 1)
        if len(owner_repo) == 2:
          owner, repo = owner_repo
          local = workdir / "fakegh" / f"{owner}__{repo}.git"
          calls["push_target"] = str(local)
          cmd = [*cmd[:4], str(local)]
    elif cmd[:3] == ["git", "remote", "set-url"] and len(cmd) >= 5:
      # The cleanup step. Just rewrite to a clean placeholder so it doesn't
      # leave a token URL behind.
      url = cmd[4]
      if "github.com/" in url:
        cmd = [*cmd[:4], f"https://github.com/PLACEHOLDER.git"]
    return real_run(cmd, cwd=cwd)

  monkeypatch.setattr(services_create, "_run", smart_run)
  return calls


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_create_local_only_no_repo(workdir: Path, db: FakeDb):
  """push_to_github=False → all steps run except github_*; status=draft."""
  result = services_create.create_service(
    db,
    name="sub-link",
    display_name="订阅链接获取",
    repo_name=None,
    deploy_node_name="dev-1",
    domain="sub-link.develop.cc",
    push_to_github=False,
  )

  step_names = [s.name for s in result.steps]
  # New ordering (post-bug-fix #7): DB write happens BEFORE the GitHub
  # round-trip, so a DB failure can't leak an orphan GitHub repo.
  assert step_names == [
    "validate_name", "resolve_settings", "validate_node",
    "validate_domain", "allocate_port",
    "render_templates", "git_init",
    "db_write_atomic", "github_create_repo",
  ], f"unexpected step order: {step_names}"

  github_step = next(s for s in result.steps if s.name == "github_create_repo")
  assert github_step.status == "skip"
  assert "push_to_github=false" in github_step.message

  # Every non-skip step is "ok".
  for s in result.steps:
    assert s.status in ("ok", "skip"), f"step {s.name} → {s.status}: {s.message}"

  # Filesystem
  repo_dir = workdir / "repos" / "sub-link"
  assert repo_dir.is_dir()
  assert (repo_dir / ".deploy.yaml").is_file()
  assert (repo_dir / "CLAUDE.md").is_file()
  assert (repo_dir / "AGENTS.md").is_file()
  assert (repo_dir / "CLAUDE.md").read_text() == (repo_dir / "AGENTS.md").read_text()
  # Substitution worked
  deploy_yaml = (repo_dir / ".deploy.yaml").read_text()
  assert "service: sub-link" in deploy_yaml
  assert "  - 8100" in deploy_yaml  # first port from pool
  # No leftover placeholders
  for p in repo_dir.rglob("*"):
    if p.is_file():
      text = p.read_text(encoding="utf-8", errors="ignore")
      assert "{{name}}" not in text
      assert "{{port}}" not in text

  # Git
  log = subprocess.run(["git", "log", "--oneline"], cwd=repo_dir,
                      capture_output=True, text=True, check=True).stdout
  assert "init: sub-link" in log
  branch = subprocess.run(["git", "branch", "--show-current"], cwd=repo_dir,
                         capture_output=True, text=True, check=True).stdout.strip()
  assert branch == "main"

  # DB
  s = db.services["sub-link"]
  assert s.assigned_port == 8100
  assert s.default_node_name == "dev-1"
  assert s.status == "draft"
  assert s.local_repo_dir == str(repo_dir)
  assert s.exposed_ports == [8100]
  assert s.healthcheck.get("expect_status") == 200
  assert s.product_enabled is False
  assert s.product_yaml is not None
  assert "slug: sub-link" in s.product_yaml

  r = db.routes["sub-link.develop.cc"]
  assert r.upstream_target == "10.0.0.1:8100"   # node host, NOT 127.0.0.1
  assert len(r.upstreams) == 1
  assert r.upstreams[0].target == "10.0.0.1:8100"
  assert db.route_service_name["sub-link.develop.cc"] == "sub-link"

  # Result return
  assert result.local_repo_dir == str(repo_dir)
  assert result.route_domain == "sub-link.develop.cc"
  assert result.github_repo_url is None


def test_create_with_mocked_github(workdir: Path, db: FakeDb, patch_github):
  """push_to_github=True with mocked GitHub → push happens, status=active."""
  result = services_create.create_service(
    db,
    name="echo",
    display_name=None,
    repo_name="echo",
    deploy_node_name="dev-1",
    domain="echo.develop.cc",
    push_to_github=True,
  )

  step_names = [s.name for s in result.steps]
  # Post-fix ordering: db_write_atomic happens BEFORE github_create_repo
  # so a DB failure leaves no orphan repo on GitHub. After a successful
  # github_push, promote_service updates the row to set the URL and
  # promote status from "draft" to "active".
  assert "github_create_repo" in step_names
  assert "github_push" in step_names
  assert "promote_service" in step_names
  i_db = step_names.index("db_write_atomic")
  i_create = step_names.index("github_create_repo")
  i_push = step_names.index("github_push")
  i_promote = step_names.index("promote_service")
  assert i_db < i_create < i_push < i_promote, f"out of order: {step_names}"

  for s in result.steps:
    assert s.status == "ok", f"{s.name}: {s.status}: {s.message}"

  assert patch_github["created"] == [
    {"token": "ghp_FAKE_TOKEN", "repo": "echo",
     "resolved_owner": "token-user"},
  ]
  assert patch_github["push_target"] is not None

  # Confirm the bare repo received the push.
  bare = Path(patch_github["push_target"])
  assert bare.is_dir()
  log = subprocess.run(
    ["git", "--git-dir", str(bare), "log", "--oneline"],
    capture_output=True, text=True, check=True,
  ).stdout
  assert "init: echo" in log

  # Local remote should have been rewritten away from the token URL.
  remote_url = subprocess.run(
    ["git", "remote", "get-url", "origin"], cwd=workdir / "repos" / "echo",
    capture_output=True, text=True, check=True,
  ).stdout.strip()
  assert "ghp_FAKE_TOKEN" not in remote_url, f"token leaked into git config: {remote_url}"

  s = db.services["echo"]
  assert s.status == "active"
  # owner is auto-detected from the (faked) /user/repos response → token-user
  assert s.github_repo_url == "https://github.com/token-user/echo"


def test_duplicate_name_fails_fast(workdir: Path, db: FakeDb):
  """validate_name catches dups; nothing else runs; CreateServiceError is raised."""
  db.services["sub-link"] = ServiceRecord(
    name="sub-link", display_name="x", description=None,
    github_repo_url="", default_branch="main",
    compose_file="docker-compose.yml", install_dir_template="/opt/{name}",
    default_env={}, pre_deploy_command=None, post_deploy_command=None,
    compose_template=None, config_files={},
    created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
  )

  with pytest.raises(services_create.CreateServiceError) as excinfo:
    services_create.create_service(
      db,
      name="sub-link",
      display_name=None,
      repo_name=None,
      deploy_node_name="dev-1",
      domain="sub-link.develop.cc",
      push_to_github=False,
    )

  result = excinfo.value.result
  assert [s.name for s in result.steps] == ["validate_name"]
  assert result.steps[0].status == "error"
  assert "already exists" in result.steps[0].message
  # Nothing got rendered or inserted.
  assert not (workdir / "repos" / "sub-link").exists()
  assert "sub-link" in db.services  # only the pre-seeded one


def test_invalid_name_rejected(workdir: Path, db: FakeDb):
  with pytest.raises(services_create.CreateServiceError) as excinfo:
    services_create.create_service(
      db, name="Bad_Name", display_name=None, repo_name=None,
      deploy_node_name="dev-1", domain="x.develop.cc", push_to_github=False,
    )
  assert excinfo.value.result.steps[0].name == "validate_name"
  assert excinfo.value.result.steps[0].status == "error"


def test_invalid_domain_rejected(workdir: Path, db: FakeDb):
  with pytest.raises(services_create.CreateServiceError) as excinfo:
    services_create.create_service(
      db, name="ok-name", display_name=None, repo_name=None,
      deploy_node_name="dev-1", domain="not_a_domain", push_to_github=False,
    )
  failed = excinfo.value.result.steps[-1]
  assert failed.name == "validate_domain"
  assert failed.status == "error"


def test_local_repos_dir_missing_raises(workdir: Path, db: FakeDb):
  db.config["services.local_repos_dir"] = {"path": ""}
  with pytest.raises(services_create.CreateServiceError) as excinfo:
    services_create.create_service(
      db, name="x-svc", display_name=None, repo_name=None,
      deploy_node_name="dev-1", domain="x-svc.develop.cc", push_to_github=False,
    )
  failed = excinfo.value.result.steps[-1]
  assert failed.name == "resolve_settings"
  assert failed.status == "error"
  assert "local_repos_dir" in failed.message


def test_unknown_node_rejected(workdir: Path, db: FakeDb):
  with pytest.raises(services_create.CreateServiceError) as excinfo:
    services_create.create_service(
      db, name="x-svc", display_name=None, repo_name=None,
      deploy_node_name="ghost-node", domain="x-svc.develop.cc", push_to_github=False,
    )
  failed = excinfo.value.result.steps[-1]
  assert failed.name == "validate_node"
  assert failed.status == "error"


def test_port_pool_exhausted(workdir: Path, db: FakeDb):
  # Squeeze the pool to a single port that's already taken on the same
  # deploy host. (post-refactor, the conflict check is per-host, so the
  # pre-existing service has to be on dev-1's host to block.)
  db.config["services.port_pool"] = {"start": 8200, "end": 8200}
  db.services["pre-existing"] = ServiceRecord(
    name="pre-existing", display_name="x", description=None,
    github_repo_url="", default_branch="main",
    compose_file="docker-compose.yml", install_dir_template="/opt/{name}",
    default_env={}, pre_deploy_command=None, post_deploy_command=None,
    compose_template=None, config_files={},
    created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
    assigned_port=8200,
    default_node_name="dev-1",
  )
  with pytest.raises(services_create.CreateServiceError) as excinfo:
    services_create.create_service(
      db, name="newer-svc", display_name=None, repo_name=None,
      deploy_node_name="dev-1", domain="newer-svc.develop.cc", push_to_github=False,
    )
  failed = excinfo.value.result.steps[-1]
  assert failed.name == "allocate_port"
  assert "no free port" in failed.message


def test_port_conflict_against_routes_skips_taken_port(workdir: Path, db: FakeDb):
  """A manually-configured route_upstream on the deploy node must be
  treated as a port-in-use so the New Service flow allocates a different
  one. Pre-refactor, services_create only checked services.assigned_port
  and would happily collide with hand-rolled upstreams."""
  # Constrain the pool to two ports so the test is deterministic.
  db.config["services.port_pool"] = {"start": 8200, "end": 8201}
  # Hand-rolled upstream on dev-1 (host 10.0.0.1) at port 8200.
  db.routes["existing.example.com"] = RouteRecord(
    domain="existing.example.com",
    upstream_target="10.0.0.1:8200",
    enabled=True,
    updated_at=datetime.now(UTC),
    upstreams=[UpstreamRecord(target_host="10.0.0.1", target_port=8200, weight=1)],
    lb_policy="random",
  )

  result = services_create.create_service(
    db, name="new-svc", display_name=None, repo_name=None,
    deploy_node_name="dev-1", domain="new-svc.develop.cc",
    push_to_github=False,
  )
  s = db.services["new-svc"]
  # Should have skipped 8200, picked 8201.
  assert s.assigned_port == 8201, f"expected 8201, got {s.assigned_port}"
  # And the upstream the route now uses is also 8201.
  up = db.routes["new-svc.develop.cc"].upstreams[0]
  assert up.target_host == "10.0.0.1"
  assert up.target_port == 8201
  # Plus the structured target string is composed correctly.
  assert up.target == "10.0.0.1:8201"


def test_port_conflict_other_host_is_not_a_conflict(workdir: Path, db: FakeDb):
  """An upstream on a DIFFERENT host doesn't block port allocation here.
  Same port can legitimately exist on two different deploy nodes."""
  db.config["services.port_pool"] = {"start": 8300, "end": 8300}
  db.routes["other-host.example.com"] = RouteRecord(
    domain="other-host.example.com",
    upstream_target="9.9.9.9:8300",
    enabled=True,
    updated_at=datetime.now(UTC),
    upstreams=[UpstreamRecord(target_host="9.9.9.9", target_port=8300, weight=1)],
    lb_policy="random",
  )
  # 8300 is free on 10.0.0.1 (only used on 9.9.9.9), so allocation succeeds.
  result = services_create.create_service(
    db, name="other-svc", display_name=None, repo_name=None,
    deploy_node_name="dev-1", domain="other-svc.develop.cc",
    push_to_github=False,
  )
  assert db.services["other-svc"].assigned_port == 8300


def test_port_conflict_via_loopback_alias(workdir: Path, db: FakeDb):
  """A route_upstream pointing at 127.0.0.1:8400 on dev-1 must be treated
  as occupying port 8400 on dev-1 (host=10.0.0.1) — without the loopback
  equivalence in _allocate_port, the new service would happily collide
  with the hand-rolled loopback route at runtime via Caddy's loopback
  rewrite."""
  db.config["services.port_pool"] = {"start": 8400, "end": 8401}
  db.routes["legacy.example.com"] = RouteRecord(
    domain="legacy.example.com",
    upstream_target="127.0.0.1:8400",
    enabled=True,
    updated_at=datetime.now(UTC),
    upstreams=[UpstreamRecord(target_host="127.0.0.1", target_port=8400, weight=1)],
    lb_policy="random",
  )
  services_create.create_service(
    db, name="lb-svc", display_name=None, repo_name=None,
    deploy_node_name="dev-1", domain="lb-svc.develop.cc",
    push_to_github=False,
  )
  assert db.services["lb-svc"].assigned_port == 8401


def test_github_create_failure_leaves_service_as_draft(workdir: Path, db: FakeDb,
                                                        monkeypatch):
  """If github_create_repo raises (e.g. 422 name-already-exists), the
  service row is already in DB (we write before GitHub now), but stays
  'draft' with empty github_repo_url, and the promote_service step
  doesn't run. This is the v1 footgun fixed by #7."""
  def boom(token, repo):
    raise RuntimeError("github API returned 422: Repository creation failed (name already exists)")
  monkeypatch.setattr(services_create, "_github_create_repo", boom)

  with pytest.raises(services_create.CreateServiceError) as excinfo:
    services_create.create_service(
      db, name="failing-svc", display_name=None, repo_name="failing-svc",
      deploy_node_name="dev-1", domain="failing-svc.develop.cc",
      push_to_github=True,
    )
  steps = excinfo.value.result.steps
  step_names = [s.name for s in steps]
  # The failure should be at github_create_repo, AFTER db_write_atomic
  assert "db_write_atomic" in step_names
  assert step_names[-1] == "github_create_repo"
  assert steps[-1].status == "error"
  # Service is in DB, still as draft, with empty URL
  s = db.services["failing-svc"]
  assert s.status == "draft"
  assert s.github_repo_url == ""
  # promote_service never ran
  assert "promote_service" not in step_names


def test_validate_node_rejects_no_ssh_credentials(workdir: Path, db: FakeDb):
  """validate_node must refuse a node that has neither password nor key
  configured — deploy would fail at SSH otherwise, and we'd rather
  surface that at create time than after rendering and DB write."""
  db.nodes["bare-node"] = NodeRecord(
    name="bare-node", host="2.2.2.2", ssh_port=22, ssh_user="root",
    auth_method="key",
    ssh_password=None, ssh_private_key=None, ssh_key_passphrase=None,
    description=None, tags=[],
    deploy_command=None, update_command=None,
    created_at=datetime.now(UTC), updated_at=datetime.now(UTC),
  )
  with pytest.raises(services_create.CreateServiceError) as excinfo:
    services_create.create_service(
      db, name="ssh-test", display_name=None, repo_name=None,
      deploy_node_name="bare-node", domain="ssh-test.develop.cc",
      push_to_github=False,
    )
  failed = excinfo.value.result.steps[-1]
  assert failed.name == "validate_node"
  assert "no usable SSH credentials" in failed.message


def test_atomic_rollback_when_route_insert_fails(workdir: Path, db: FakeDb):
  """If anything inside the atomic DB block fails, the service row must
  not be left behind — that was the v1 footgun this refactor closed."""
  db.fail_atomic_at = "after_route_insert"
  with pytest.raises(services_create.CreateServiceError) as excinfo:
    services_create.create_service(
      db, name="atomic-test", display_name=None, repo_name=None,
      deploy_node_name="dev-1", domain="atomic-test.develop.cc",
      push_to_github=False,
    )
  failed = excinfo.value.result.steps[-1]
  assert failed.name == "db_write_atomic"
  assert failed.status == "error"
  # The point: the service row that was tentatively inserted is GONE.
  assert "atomic-test" not in db.services
  # And no orphan route either.
  assert "atomic-test.develop.cc" not in db.routes


def test_local_source_tar_filter_excludes_dotgit_and_dotenv(tmp_path: Path):
  """The local-deploy tar filter must exclude .git, .env (and friends),
  caches, and build artifacts — but keep .env.example / .env.sample,
  source dirs, and dotfiles like .gitignore. Regression test for the
  ``.lstrip("./")`` bug that was eating the leading "." of ".git"."""
  import tarfile, io
  from ssl_proxy_controller.nodes import _local_source_tar_filter

  src = tmp_path / "src"
  src.mkdir()
  # Files we WANT to ship
  (src / "Dockerfile").write_text("FROM scratch\n")
  (src / ".gitignore").write_text("*.pyc\n")
  (src / ".env.example").write_text("PORT=8000\n")
  (src / ".env.sample").write_text("PORT=8000\n")
  (src / "app").mkdir()
  (src / "app" / "main.py").write_text("print('hi')\n")
  # Files we want EXCLUDED
  (src / ".git").mkdir()
  (src / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
  (src / ".env").write_text("SECRET=leaked\n")
  (src / ".env.local").write_text("ALSO_SECRET=leaked\n")
  (src / ".env.production").write_text("PROD_SECRET=leaked\n")
  (src / "__pycache__").mkdir()
  (src / "__pycache__" / "x.pyc").write_text("bytecode\n")
  (src / ".pytest_cache").mkdir()
  (src / ".pytest_cache" / "v").mkdir()

  buf = io.BytesIO()
  with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    tar.add(str(src), arcname=".", filter=_local_source_tar_filter)

  buf.seek(0)
  with tarfile.open(fileobj=buf, mode="r:gz") as tar:
    members = {m.name for m in tar.getmembers()}

  # Must KEEP
  assert "./Dockerfile" in members
  assert "./.gitignore" in members
  assert "./.env.example" in members
  assert "./.env.sample" in members
  assert "./app" in members
  assert "./app/main.py" in members
  # Must EXCLUDE — every path under these prefixes
  for bad in (
    "./.git",
    "./.git/HEAD",
    "./.env",
    "./.env.local",
    "./.env.production",
    "./__pycache__",
    "./__pycache__/x.pyc",
    "./.pytest_cache",
    "./.pytest_cache/v",
  ):
    assert bad not in members, f"filter leaked {bad}"


def test_render_templates_directly(tmp_path: Path):
  """Spot-check the renderer in isolation: dotfile prefix translates,
  .tpl placeholders substitute, CLAUDE.md mirrors to AGENTS.md, scripts
  are executable."""
  dst = tmp_path / "rendered"
  services_create._render_templates(
    services_create._TEMPLATE_DIR,
    dst,
    {"name": "svc", "port": "9000", "domain": "svc.example",
     "display_name": "Svc", "repo_url": "https://github.com/x/svc",
     "node_host": "1.1.1.1"},
  )
  assert (dst / ".deploy.yaml").is_file()
  assert (dst / ".gitignore").is_file()
  assert (dst / ".env.example").is_file()
  assert (dst / ".dockerignore").is_file()
  assert (dst / "Dockerfile").is_file()
  assert (dst / "CLAUDE.md").read_text() == (dst / "AGENTS.md").read_text()

  for sh in (dst / "scripts").iterdir():
    if sh.suffix == ".sh":
      assert os.access(sh, os.X_OK), f"{sh.name} not executable"

  for p in dst.rglob("*"):
    if p.is_file():
      text = p.read_text(encoding="utf-8", errors="ignore")
      assert "{{" not in text or "}}" not in text, (
        f"un-substituted placeholder in {p.relative_to(dst)}"
      )
