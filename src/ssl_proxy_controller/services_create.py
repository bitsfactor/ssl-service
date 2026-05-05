"""New Service flow — admin-driven creation of a brand-new service repo.

The admin's "New Service" form calls :func:`create_service`. It renders
the template tree under ``templates/service/`` to a local directory,
runs ``git init`` + initial commit, optionally creates a private GitHub
repo (via REST API) and pushes to it, registers the service in the
``services`` table, and creates a route pointing at the chosen deploy
node. It returns a :class:`CreateServiceResult` with structured progress
so the admin UI can show what happened step by step.

Design notes:

- Stdlib-only for the GitHub API call (``urllib.request``) — no extra deps.
- Spawns ``git`` via subprocess; assumes git is on PATH on the host that
  runs ssl-service.
- Settings (paths, port pool, defaults, GitHub token) live in
  ``system_config``; the function reads them, validates, and refuses to
  run when something required is missing — admin surfaces a friendly
  error with the missing key.
- Synchronous: the whole flow runs in the request thread. Total wall
  time is dominated by GitHub create + push (~3-5s on a normal network).
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .db import Database, ServiceRecord, UpstreamRecord


LOGGER = logging.getLogger("ssl_proxy_controller.services_create")

# Slug constraints: lowercase, starts with a letter, ends with letter/digit,
# hyphens internally, length 3..40. Same shape we'd accept in a public URL.
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,38}[a-z0-9]$")

# Domain label: lowercase letter/digit, hyphens internal, no leading/trailing
# hyphen. The fully qualified domain must have at least two labels.
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates" / "service"

# Placeholder keys recognised by the renderer. Adding a new key here
# without updating templates is harmless; using a key in a template
# without registering it here leaves it un-substituted.
_PLACEHOLDER_KEYS = ("name", "port", "domain", "display_name", "repo_url", "node_host")


# ---------------------------------------------------------------------------
# Result / error types
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Step:
  name: str
  status: str               # "ok" | "error" | "skip"
  message: str = ""
  elapsed_ms: int = 0


@dataclass(slots=True)
class CreateServiceResult:
  steps: list[_Step] = field(default_factory=list)
  service: ServiceRecord | None = None
  route_domain: str | None = None
  local_repo_dir: str = ""
  github_repo_url: str | None = None

  def to_dict(self) -> dict[str, Any]:
    return {
      "steps": [asdict(s) for s in self.steps],
      "service": _service_to_dict(self.service) if self.service else None,
      "route_domain": self.route_domain,
      "local_repo_dir": self.local_repo_dir,
      "github_repo_url": self.github_repo_url,
    }


class CreateServiceError(Exception):
  """Raised on validation / IO failure during :func:`create_service`.

  Carries the partial :class:`CreateServiceResult` so the caller can
  surface what was done before the failure.
  """

  def __init__(self, message: str, *, result: CreateServiceResult | None = None,
               code: str = "create_failed") -> None:
    super().__init__(message)
    self.result = result or CreateServiceResult()
    self.code = code


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def create_service(
  database: Database,
  *,
  name: str,
  display_name: str | None,
  repo_name: str | None,
  deploy_node_name: str,
  domain: str,
  push_to_github: bool = True,
) -> CreateServiceResult:
  """Run the full New Service flow synchronously.

  Returns the final :class:`CreateServiceResult`. Raises
  :class:`CreateServiceError` on failure; the exception's ``result``
  attribute holds whatever steps did complete.
  """
  result = CreateServiceResult()

  def _step(step_name: str, fn: Callable[[], Any]) -> Any:
    """Run one step, time it, append to result.steps. Convert raised
    exceptions to a structured error step + CreateServiceError."""
    t0 = time.monotonic()
    try:
      out = fn()
    except CreateServiceError:
      raise
    except Exception as exc:  # noqa: BLE001 — convert to structured step
      elapsed_ms = int((time.monotonic() - t0) * 1000)
      result.steps.append(_Step(step_name, "error", str(exc), elapsed_ms))
      raise CreateServiceError(f"{step_name}: {exc}", result=result) from exc
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    msg = out if isinstance(out, str) else ""
    result.steps.append(_Step(step_name, "ok", msg, elapsed_ms))
    return out

  # 1. Validate name shape and uniqueness.
  def _validate_name() -> str:
    if not _NAME_RE.match(name or ""):
      raise ValueError(
        "name must be lowercase, start with a letter, "
        "use only letters/digits/hyphens, length 3..40"
      )
    if database.get_service(name) is not None:
      raise ValueError(f"a service named '{name}' already exists")
    return name

  _step("validate_name", _validate_name)

  # 2. Read settings from system_config.
  settings = _step("resolve_settings", lambda: _resolve_settings(database))

  # 3. Validate node exists, has a host, and has SSH credentials we can
  #    actually use (otherwise the eventual deploy step has no chance).
  def _validate_node() -> str:
    node = database.get_node(deploy_node_name)
    if node is None:
      raise ValueError(f"deploy node '{deploy_node_name}' does not exist")
    if not (node.host or "").strip():
      raise ValueError(f"node '{deploy_node_name}' has no host configured")
    has_inline_pw = bool((node.ssh_password or "").strip())
    has_inline_key = bool((node.ssh_private_key or "").strip())
    has_linked_key = False
    # The real Database exposes ``list_node_ssh_key_links``; FakeDb in
    # the unit tests doesn't (and that's fine — those paths supply
    # inline credentials when they need a passing node). We deliberately
    # only swallow AttributeError here so a real DB error (connection
    # drop, query failure) propagates instead of being misreported as
    # "no usable SSH credentials".
    get_links = getattr(database, "list_node_ssh_key_links", None)
    if get_links is not None:
      has_linked_key = bool(get_links(deploy_node_name))
    if not (has_inline_pw or has_inline_key or has_linked_key):
      raise ValueError(
        f"node '{deploy_node_name}' has no usable SSH credentials "
        f"(no password, no inline key, no linked ssh_keys)"
      )
    return node.host

  node_host = _step("validate_node", _validate_node)

  # 4. Validate domain shape and uniqueness against routes.
  def _validate_domain() -> str:
    candidate = (domain or "").strip().lower()
    labels = candidate.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL_RE.match(label) for label in labels):
      raise ValueError(f"domain '{domain}' is not a valid hostname")
    if database.get_route(candidate) is not None:
      raise ValueError(f"a route for '{candidate}' already exists")
    return candidate

  effective_domain = _step("validate_domain", _validate_domain)

  # 5. Allocate port from configured pool. Conflict detection considers
  #    BOTH services already on this node AND any route_upstreams that
  #    point at <node_host>:<port>, so a manually-configured upstream
  #    can't be silently overwritten.
  port = _step("allocate_port",
               lambda: _allocate_port(database, settings["port_pool"], node_host))

  # 6. Render templates to local_repo_dir.
  display = (display_name or name).strip() or name
  local_repo_dir = (Path(settings["local_repos_dir"]).expanduser() / name).resolve()

  effective_repo_name = (repo_name or "").strip()
  # github_repo_url is filled in AFTER the GitHub create call (which
  # tells us the actual owner). At template-render time we don't know
  # it yet, so the {{repo_url}} placeholder gets an empty string. The
  # only template that uses it is README.md and showing an empty
  # "Repo:" line is acceptable; the real URL gets added to the service
  # row via the ``promote_service`` step at the end.
  github_repo_url = ""

  placeholders = {
    "name": name,
    "port": str(port),
    "domain": effective_domain,
    "display_name": display,
    "repo_url": github_repo_url,
    "node_host": node_host,
  }

  def _render() -> str:
    if local_repo_dir.exists():
      raise ValueError(f"target directory already exists: {local_repo_dir}")
    _render_templates(_TEMPLATE_DIR, local_repo_dir, placeholders)
    return f"rendered to {local_repo_dir}"

  _step("render_templates", _render)
  result.local_repo_dir = str(local_repo_dir)

  # 7. git init + initial commit.
  def _git_init() -> str:
    _run(["git", "init", "-b", "main"], cwd=local_repo_dir)
    # Configure local user/email so the commit doesn't fail on machines
    # with empty global git config.
    _run(["git", "config", "user.email", "service@bitsfactor.com"], cwd=local_repo_dir)
    _run(["git", "config", "user.name", "BitsFactor Service"], cwd=local_repo_dir)
    _run(["git", "add", "-A"], cwd=local_repo_dir)
    _run(["git", "commit", "-m", f"init: {name}"], cwd=local_repo_dir)
    return "initial commit on main"

  _step("git_init", _git_init)

  # 8. Atomic DB write FIRST (before any external GitHub call). This
  #    ordering means: if the DB write fails, no orphan GitHub repo got
  #    created, so retrying with the same name is clean. We initially
  #    insert with ``github_repo_url=""`` and ``status="draft"`` and
  #    only promote to "active" + set the URL after the push succeeds.
  manifest_fields = {
    "exposed_ports": [port],
    "required_env": [],
    "healthcheck": {
      "url": "http://localhost:${PORT}/health",
      "expect_status": 200,
      "timeout_seconds": 30,
      "retries": 6,
      "interval_seconds": 5,
    },
    "depends_on": [],
    "config_schema": [],
  }

  now = datetime.now(UTC)
  service_record = ServiceRecord(
    name=name,
    display_name=display,
    description=None,
    github_repo_url="",
    default_branch="main",
    compose_file="docker-compose.yml",
    install_dir_template="/opt/{name}",
    default_env={"PORT": str(port), "LOG_LEVEL": "info", "TZ": "Asia/Shanghai"},
    pre_deploy_command=None,
    post_deploy_command=None,
    compose_template=None,
    config_files={},
    created_at=now,
    updated_at=now,
    exposed_ports=[port],
    assigned_port=port,
    local_repo_dir=str(local_repo_dir),
    default_node_name=deploy_node_name,
    status="draft",
    product_yaml=_read_rendered_product_yaml(local_repo_dir),
    product_enabled=False,
  )

  def _atomic_db_write() -> str:
    upstream = UpstreamRecord(target_host=node_host, target_port=port, weight=1)
    inserted_service, inserted_route = database.create_service_and_route_atomic(
      service_record,
      manifest_fields=manifest_fields,
      route_domain=effective_domain,
      route_upstreams=[upstream],
    )
    result.service = inserted_service
    result.route_domain = inserted_route.domain
    return (
      f"service={service_record.name}, "
      f"route={effective_domain} → {upstream.target}"
    )

  _step("db_write_atomic", _atomic_db_write)

  # 9. GitHub: create repo + push. Skipped (no error) when any
  #    REQUIRED input is missing — push_to_github, repo_name, or token.
  #    The owner is always auto-detected from the create-repo response,
  #    so the operator never has to configure it.
  #    On success we update the service row to set github_repo_url and
  #    promote status from "draft" to "active".
  pushed = False
  github_token = settings.get("github_api_token") or ""
  skip_reason: str | None = None
  if not push_to_github:
    skip_reason = "push_to_github=false; service stays as draft"
  elif not effective_repo_name:
    skip_reason = "no repo_name given; service stays as draft"
  elif not github_token:
    skip_reason = "github.api_token not set in system_config; service stays as draft"

  resolved_owner = ""

  if skip_reason is not None:
    result.steps.append(_Step("github_create_repo", "skip", skip_reason))
  else:
    def _gh_create() -> str:
      nonlocal resolved_owner
      resolved_owner = _github_create_repo(github_token, effective_repo_name)
      return f"created github.com/{resolved_owner}/{effective_repo_name}"

    _step("github_create_repo", _gh_create)

    # Now that we know the owner GitHub put the repo under, build the
    # canonical URL.
    github_repo_url = (
      f"https://github.com/{resolved_owner}/{effective_repo_name}"
    )

    def _gh_push() -> str:
      token_url = (
        f"https://x-access-token:{github_token}@github.com/"
        f"{resolved_owner}/{effective_repo_name}.git"
      )
      clean_url = (
        f"https://github.com/{resolved_owner}/{effective_repo_name}.git"
      )
      _run(["git", "remote", "add", "origin", token_url], cwd=local_repo_dir)
      _run(["git", "push", "-u", "origin", "main"], cwd=local_repo_dir)
      # Don't leave the API token in the local git remote URL — anyone
      # who clones / inspects the repo could exfiltrate it. Rewrite to
      # the clean public URL after the push.
      _run(["git", "remote", "set-url", "origin", clean_url], cwd=local_repo_dir)
      return "pushed to origin/main"

    _step("github_push", _gh_push)
    pushed = True

  if pushed:
    def _promote() -> str:
      database.update_service(name, {
        "github_repo_url": github_repo_url,
        "status": "active",
      })
      refreshed = database.get_service(name)
      if refreshed is not None:
        result.service = refreshed
      return f"github_repo_url set, status=active"

    _step("promote_service", _promote)

  # Surface github_repo_url ONLY when the push actually happened — the
  # DB row reflects this faithfully (only _promote sets it), and result
  # should match. Otherwise the UI would show a "View on GitHub" link
  # that 404s.
  result.github_repo_url = github_repo_url if pushed else None
  return result


# ---------------------------------------------------------------------------
# Settings / port pool
# ---------------------------------------------------------------------------


def _resolve_settings(database: Database) -> dict[str, Any]:
  """Pull the system_config keys this flow depends on. Defaults applied
  for purely numeric / cosmetic settings; required string settings raise
  if missing so the admin can surface "configure X first".
  """
  def cfg(key: str) -> dict[str, Any]:
    return database.get_system_config(key) or {}

  ports = cfg("services.port_pool")
  start = int(ports.get("start") or 8100)
  end = int(ports.get("end") or 8999)
  # start == end is legal (single-port pool); start > end is not.
  if not (1024 < start <= end < 65536):
    raise ValueError(
      f"system_config services.port_pool invalid: start={start} end={end}"
    )

  repos_dir = (cfg("services.local_repos_dir") or {}).get("path", "")
  if not repos_dir:
    raise ValueError(
      "system_config services.local_repos_dir.path is not set; "
      "configure it in Settings before creating services"
    )

  github_token = (cfg("github.api_token") or {}).get("token", "")

  return {
    "port_pool": (start, end),
    "local_repos_dir": repos_dir,
    "github_api_token": github_token,
  }


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def _hosts_equivalent(a: str, b: str) -> bool:
  """Two host strings are 'the same machine' when they're literally
  equal OR when one of them is a loopback alias and the other is the
  node's actual public IP. This matters for port-conflict detection:
  an existing route ``127.0.0.1:8100`` on a deploy node would otherwise
  not flag a collision when a new service tries to grab 8100 on the
  same node's public IP. Caddy's loopback-rewrite (in caddy.py) makes
  these host strings reach the same listener at runtime, so the conflict
  check has to mirror that semantic."""
  if a == b:
    return True
  if a in _LOOPBACK_HOSTS and b not in _LOOPBACK_HOSTS:
    return True
  if b in _LOOPBACK_HOSTS and a not in _LOOPBACK_HOSTS:
    return True
  return False


def _allocate_port(database: Database, port_pool: tuple[int, int],
                   node_host: str) -> int:
  """Pick the first free port in ``port_pool`` for ``node_host``.

  A port is considered "in use on this host" if either:

  - some service has ``assigned_port == port`` AND its
    ``default_node_name`` resolves to a node whose ``host`` matches; OR
  - some route upstream has ``target_host`` equivalent to ``node_host``
    (literal match OR loopback alias) AND ``target_port == port``.

  The loopback-alias check catches manually-configured routes that
  point a domain at ``127.0.0.1:8100`` on this same node — without
  it, a new service would grab the same port and silently collide.
  """
  start, end = port_pool
  used: set[int] = set()

  # Map: node name → host, so we can compare services.default_node_name
  # against node_host without an N+1 lookup.
  node_host_by_name = {n.name: n.host for n in database.list_nodes()}

  for s in database.list_services():
    if not s.assigned_port:
      continue
    svc_host = node_host_by_name.get(s.default_node_name or "") or ""
    if _hosts_equivalent(svc_host, node_host):
      used.add(int(s.assigned_port))

  for r in database.list_routes():
    for up in (r.upstreams or []):
      if _hosts_equivalent(up.target_host, node_host):
        used.add(int(up.target_port))

  for candidate in range(start, end + 1):
    if candidate not in used:
      return candidate
  raise ValueError(
    f"no free port in pool {start}..{end} on host {node_host} "
    f"({len(used)} in use)"
  )


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------


_BINARY_SUFFIXES = frozenset({
  ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
  ".pdf", ".zip", ".tar", ".tgz", ".gz",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
})


def _render_templates(src: Path, dst: Path, placeholders: dict[str, str]) -> None:
  """Walk the template tree under ``src`` and materialise it to ``dst``.

  Rules:
  - Any path segment starting with ``_dot_`` becomes ``.<rest>``.
  - Any file ending in ``.tpl`` has the suffix dropped and its body
    passed through :func:`_substitute`.
  - Files with binary suffixes (image / archive / font types — see
    ``_BINARY_SUFFIXES``) are copied byte-for-byte without text decode
    or substitution. Use this for product preview images, etc.
  - Shell scripts (``*.sh``) get mode 0o755.
  - The rendered ``CLAUDE.md`` is mirrored to ``AGENTS.md`` so both
    AI-agent instruction files stay byte-identical. CLAUDE.md.tpl is
    REQUIRED in the template tree for this mirror to work; the
    smoke test in ``tests/test_services_create.py`` enforces it.
  """
  if not src.is_dir():
    raise FileNotFoundError(f"template tree missing: {src}")
  dst.mkdir(parents=True, exist_ok=False)
  rendered_claude_md: str | None = None
  for path in sorted(src.rglob("*")):
    rel = path.relative_to(src)
    out_rel = _translate_name(rel)
    if path.is_dir():
      (dst / out_rel).mkdir(parents=True, exist_ok=True)
      continue
    out_path = dst / out_rel
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Binary path: byte-for-byte copy, never decode, never substitute.
    if out_path.suffix.lower() in _BINARY_SUFFIXES:
      out_path.write_bytes(path.read_bytes())
      continue
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".tpl":
      text = _substitute(text, placeholders)
    out_path.write_text(text, encoding="utf-8")
    if out_path.suffix == ".sh":
      os.chmod(out_path, 0o755)
    if out_rel.name == "CLAUDE.md":
      rendered_claude_md = text
  if rendered_claude_md is not None:
    (dst / "AGENTS.md").write_text(rendered_claude_md, encoding="utf-8")
  else:
    # CLAUDE.md.tpl is load-bearing; if it goes missing, the AGENTS.md
    # mirror silently doesn't write. Fail loudly so we catch the
    # template-tree breakage early.
    raise RuntimeError(
      "template tree is missing CLAUDE.md(.tpl) — the AGENTS.md "
      "mirror has nothing to copy from"
    )


def _translate_name(rel: Path) -> Path:
  parts: list[str] = []
  for part in rel.parts:
    new = part
    if new.startswith("_dot_"):
      new = "." + new[len("_dot_"):]
    if new.endswith(".tpl"):
      new = new[: -len(".tpl")]
    parts.append(new)
  return Path(*parts)


def _substitute(text: str, placeholders: dict[str, str]) -> str:
  for key in _PLACEHOLDER_KEYS:
    text = text.replace("{{" + key + "}}", placeholders.get(key, ""))
  return text


# ---------------------------------------------------------------------------
# Subprocess wrapper / GitHub API
# ---------------------------------------------------------------------------


def _run(cmd: list[str], *, cwd: Path) -> None:
  # 60s is comfortably more than a fresh `git push` of a 20-file repo
  # over a normal network; if we exceed it something is genuinely stuck
  # and the request thread should not hang on it.
  #
  # For git commands, force-disable interactive credential prompting:
  # GIT_TERMINAL_PROMPT=0 makes git fail fast instead of blocking
  # waiting for a password, and overriding GIT_ASKPASS / SSH_ASKPASS to
  # /bin/true closes the credential-helper escape hatch on machines
  # that have one configured. Together they mean a misconfigured
  # remote URL fails the step in seconds, not at the 60s timeout.
  env = None
  if cmd and cmd[0] == "git":
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "/bin/true"
    env["SSH_ASKPASS"] = "/bin/true"
    env.setdefault("LANG", "C.UTF-8")
  result = subprocess.run(
    cmd, cwd=cwd, capture_output=True, text=True, check=False, timeout=60,
    env=env,
  )
  if result.returncode != 0:
    out = (result.stdout or "") + (result.stderr or "")
    raise RuntimeError(
      f"{' '.join(cmd)} failed (exit {result.returncode}): {out.strip()}"
    )


def _github_create_repo(token: str, repo_name: str) -> str:
  """Create a private repo named ``repo_name`` under the token's user
  and return the resolved owner (the GitHub login the repo lives under).

  We always POST ``/user/repos``; GitHub puts the repo under the
  authenticated user. The full_name in the response (``alice/foo``)
  tells us the owner without the operator having to configure it.

  Note: any error after this call but before the subsequent push
  leaves an empty repo on GitHub. Retrying with the same name hits
  422 — operator deletes it manually.
  """
  body = json.dumps({"name": repo_name, "private": True}).encode("utf-8")
  user_url = "https://api.github.com/user/repos"
  try:
    response_json = _github_post(user_url, body, token)
  except urllib.error.HTTPError as exc:
    raise RuntimeError(_github_error_message("create repo", exc)) from exc
  full_name = (response_json or {}).get("full_name") or ""
  if not full_name or "/" not in full_name:
    raise RuntimeError(
      f"github API response missing or malformed full_name: {full_name!r}"
    )
  return full_name.split("/", 1)[0]


def _github_post(url: str, body: bytes, token: str) -> dict[str, Any] | None:
  """POST to the GitHub API, return the parsed JSON response.

  Raises ``urllib.error.HTTPError`` for non-2xx (caller decides whether
  to retry/fall back). Returns ``None`` if the response body isn't JSON.
  """
  request = urllib.request.Request(
    url,
    data=body,
    method="POST",
    headers={
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "ssl-service-admin",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  )
  with urllib.request.urlopen(request, timeout=15) as resp:
    raw = resp.read()
  try:
    return json.loads(raw.decode("utf-8"))
  except (UnicodeDecodeError, json.JSONDecodeError):
    return None


def _github_error_message(action: str, exc: urllib.error.HTTPError) -> str:
  """Build a readable error string from an HTTPError, including the
  GitHub-specific ``message`` field if present in the response body."""
  payload = b""
  try:
    payload = exc.read() or b""
  except Exception:  # noqa: BLE001 — best-effort body capture
    pass
  detail = ""
  try:
    parsed = json.loads(payload.decode("utf-8")) if payload else {}
    if isinstance(parsed, dict) and parsed.get("message"):
      detail = f": {parsed['message']}"
      errors = parsed.get("errors") or []
      if isinstance(errors, list) and errors:
        bits = [str(e.get("message") or e) for e in errors if isinstance(e, dict)]
        if bits:
          detail += f" ({'; '.join(bits)})"
  except Exception:  # noqa: BLE001
    detail = f": {payload[:200]!r}"
  return f"{action} failed (HTTP {exc.code}){detail}"


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def _read_rendered_product_yaml(local_repo_dir: Path) -> str | None:
  candidate = local_repo_dir / ".product.yaml"
  try:
    return candidate.read_text(encoding="utf-8")
  except OSError:
    return None


def _service_to_dict(s: ServiceRecord) -> dict[str, Any]:
  d = asdict(s)
  for key in ("created_at", "updated_at", "deploy_yaml_fetched_at"):
    if d.get(key) is not None:
      d[key] = str(d[key])
  return d


__all__ = [
  "CreateServiceError",
  "CreateServiceResult",
  "create_service",
]
