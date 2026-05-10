"""Operator command palette — backend executors for the admin SPA's
#/commands page.

The Commands page replaces the legacy ".command shell script + Finder
double-click + screenshot the terminal" loop with one-click forms backed
by audited backend endpoints. Each builtin or custom row in
``commands_catalog`` describes a button: its form schema, the executor
kind that runs it, and the args dict that gets merged with the operator's
form values at run time.

Executor kinds (matched on ``exec.kind``):

  * ``local-run``               — shell on the host where admin runs.
  * ``local-git-commit-push``   — convenience wrapper for the git
                                  add/commit/push trio against a path on
                                  this host.
  * ``local-repo-sync``         — discard local changes + pull origin to
                                  recover from a poisoned working tree.
  * ``service-deploy``          — dispatch to ``deploy_service_to_nodes``.
  * ``node-run``                — shell on a managed node via the SSH mux.
  * ``db-apply-schema``         — apply ``sql/schema.sql`` to a registered DB.
  * ``db-run-sql``              — run an arbitrary SQL statement on a registered DB.
  * ``admin-restart``           — re-exec the admin process.

The ``run_command`` entry-point dispatches by kind, returns a normalised
``CommandResult`` (success path or error envelope, never raises HttpError),
and persists an audit row to ``command_runs``. The HTTP layer in admin.py
just wraps this with auth + JSON serialisation.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

LOGGER = logging.getLogger("ssl_proxy_controller.commands")

# Anything written to stdout/stderr beyond this gets persisted as
# ``"...<truncated, n bytes elided>"`` in command_runs. The full output
# is still returned to the caller in the immediate HTTP response.
_PERSIST_OUTPUT_LIMIT = 64 * 1024

# Hard cap on per-command timeout — operators can override the default
# 60s up to this ceiling, but no further. Long deploys go through the
# dedicated /api/services/{name}/deploy endpoint.
_MAX_TIMEOUT_S = 600

# Default per-kind timeouts when the catalog row doesn't specify one.
_DEFAULT_TIMEOUT_S: dict[str, int] = {
  "local-run": 60,
  "local-git-commit-push": 120,
  "local-repo-sync": 60,
  "service-deploy": 600,
  "node-run": 60,
  "db-apply-schema": 60,
  "db-run-sql": 30,
  "admin-restart": 5,
}

# Where this admin's ssl-service checkout lives on disk. Relative
# ``repo_path`` arguments are resolved against this root so a builtin
# row can say ``repo_path: "."`` or ``repo_path: "service-source/chatbot"``
# without baking absolute paths into the seed.
_SSL_SERVICE_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass(slots=True)
class CommandResult:
  """Normalised return shape for every executor kind. The HTTP layer
  serialises this verbatim. ``ok=False`` indicates a non-zero exit or a
  caller-visible error (e.g. SSH failed, db not registered) — the
  response is still 200 so the operator sees the partial output."""

  ok: bool
  exit_code: int | None = None
  stdout: str = ""
  stderr: str = ""
  duration_ms: int = 0
  cwd: str | None = None
  command: str | None = None
  error: str | None = None
  extra: dict[str, Any] = field(default_factory=dict)

  def to_dict(self) -> dict[str, Any]:
    out: dict[str, Any] = {
      "ok": self.ok,
      "exit_code": self.exit_code,
      "stdout": self.stdout,
      "stderr": self.stderr,
      "duration_ms": self.duration_ms,
    }
    if self.cwd is not None:
      out["cwd"] = self.cwd
    if self.command is not None:
      out["command"] = self.command
    if self.error is not None:
      out["error"] = self.error
    if self.extra:
      out.update(self.extra)
    return out


# ---------------------------------------------------------------------------
# Argument resolution
# ---------------------------------------------------------------------------


def _resolve_repo_path(raw: Any) -> Path:
  """Turn a builtin's relative ``repo_path`` (e.g. ``.`` or
  ``service-source/chatbot``) into an absolute filesystem path under the
  ssl-service checkout. Absolute paths pass through unchanged so an
  operator-defined row can target an arbitrary directory.
  """
  text = (raw or "").strip() if isinstance(raw, str) else ""
  if not text:
    return _SSL_SERVICE_ROOT
  candidate = Path(text)
  if not candidate.is_absolute():
    candidate = (_SSL_SERVICE_ROOT / candidate).resolve()
  else:
    candidate = candidate.resolve()
  return candidate


def _coerce_timeout(args: dict[str, Any], default: int) -> float:
  """Pick a per-call timeout out of (args.timeout_s | catalog row default
  | kind default), clamped to ``_MAX_TIMEOUT_S``. Returns seconds as a
  float for ``subprocess.run(timeout=...)``."""
  raw = args.get("timeout_s") if isinstance(args, dict) else None
  try:
    if raw is None or raw == "":
      seconds = int(default)
    else:
      seconds = int(raw)
  except (TypeError, ValueError):
    seconds = int(default)
  if seconds <= 0:
    seconds = int(default) if default > 0 else 60
  if seconds > _MAX_TIMEOUT_S:
    seconds = _MAX_TIMEOUT_S
  return float(seconds)


def _trim(text: str | bytes, limit: int = _PERSIST_OUTPUT_LIMIT) -> str:
  if isinstance(text, bytes):
    try:
      text = text.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
      text = repr(text)
  if not isinstance(text, str):
    text = str(text)
  if len(text) <= limit:
    return text
  elided = len(text) - limit
  return text[:limit] + f"\n…<truncated, {elided} bytes elided>"


def _stringify_args_for_shell(args: dict[str, Any]) -> dict[str, str]:
  """Coerce form values into strings safe for ${...} substitution in a
  builtin's ``cmd`` template. Booleans become "1"/"0", lists join on
  comma, None and missing keys become "" so the resulting shell line
  doesn't break on unset variables.
  """
  out: dict[str, str] = {}
  for key, val in (args or {}).items():
    if val is None:
      out[key] = ""
    elif isinstance(val, bool):
      out[key] = "1" if val else "0"
    elif isinstance(val, (list, tuple)):
      out[key] = ",".join(str(item) for item in val)
    else:
      out[key] = str(val)
  return out


def _expand_template(text: str, args: dict[str, str]) -> str:
  """Cheap ``${var}`` and ``${var:-default}`` expansion. We deliberately
  do NOT pass through ``os.environ`` — only catalog-bound + form-value
  variables. Operator-controlled inputs flow into the resulting shell
  line as-is, which is intentional: the Commands page is the operator's
  console and already gates on the admin token."""
  if not text:
    return text
  import re
  pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z_0-9]*)(?::-([^}]*))?\}")

  def repl(match: "re.Match[str]") -> str:
    name = match.group(1)
    default = match.group(2) or ""
    value = args.get(name, "")
    if value == "" and default:
      return default
    return value

  return pattern.sub(repl, text)


# ---------------------------------------------------------------------------
# Executor: local-run
# ---------------------------------------------------------------------------


def run_local_shell(args: dict[str, Any]) -> CommandResult:
  """Run a shell command on the host where admin runs.

  ``args``:
    cmd        — required, the shell line to execute (passed to /bin/bash -lc)
    cwd        — optional, working directory. Relative paths resolve against
                 the ssl-service repo root. Defaults to the repo root.
    timeout_s  — optional, integer seconds. Default 60, clamp 600.
    env        — optional, dict of extra env vars (merged onto the parent env).
  """
  cmd = (args.get("cmd") or "").strip() if isinstance(args, dict) else ""
  if not cmd:
    return CommandResult(ok=False, exit_code=None, error="cmd is required")
  cwd_raw = args.get("cwd") or ""
  cwd_path = _resolve_repo_path(cwd_raw) if cwd_raw else _SSL_SERVICE_ROOT
  if not cwd_path.is_dir():
    return CommandResult(ok=False, exit_code=None,
                         error=f"cwd does not exist: {cwd_path}")
  timeout = _coerce_timeout(args, _DEFAULT_TIMEOUT_S["local-run"])
  env = dict(os.environ)
  extra_env = args.get("env") if isinstance(args, dict) else None
  if isinstance(extra_env, dict):
    for k, v in extra_env.items():
      if isinstance(k, str) and isinstance(v, (str, int, float, bool)):
        env[k] = str(v)
  t0 = time.monotonic()
  try:
    proc = subprocess.run(
      ["/bin/bash", "-lc", cmd],
      cwd=str(cwd_path),
      env=env,
      capture_output=True,
      timeout=timeout,
      check=False,
    )
  except subprocess.TimeoutExpired as exc:
    duration_ms = int((time.monotonic() - t0) * 1000)
    return CommandResult(
      ok=False, exit_code=None,
      stdout=_trim(exc.stdout or ""),
      stderr=_trim(exc.stderr or "") + f"\n…timeout after {timeout:.0f}s",
      duration_ms=duration_ms,
      cwd=str(cwd_path), command=cmd,
      error=f"timeout after {timeout:.0f}s",
    )
  except Exception as exc:  # noqa: BLE001
    duration_ms = int((time.monotonic() - t0) * 1000)
    return CommandResult(
      ok=False, exit_code=None,
      duration_ms=duration_ms,
      cwd=str(cwd_path), command=cmd,
      error=f"{type(exc).__name__}: {exc}",
    )
  duration_ms = int((time.monotonic() - t0) * 1000)
  return CommandResult(
    ok=(proc.returncode == 0),
    exit_code=proc.returncode,
    stdout=_trim(proc.stdout),
    stderr=_trim(proc.stderr),
    duration_ms=duration_ms,
    cwd=str(cwd_path), command=cmd,
  )


# ---------------------------------------------------------------------------
# Executor: local-git-commit-push
# ---------------------------------------------------------------------------


def run_local_git_commit_push(args: dict[str, Any]) -> CommandResult:
  """Stage, commit, and push to origin/<current-branch> in one shot.

  ``args``:
    repo_path   — required, relative or absolute path to the working tree.
    message     — required, commit message.
    paths       — optional, space-separated list of paths to stage. Blank
                  stages everything (``git add -A``).
    push_to     — optional, ``"<remote>:<branch>"`` override. Default is
                  ``origin:<current-branch>``.
    allow_empty — optional bool. If false (default), a no-op (nothing
                  staged) is treated as success and skips the commit/push.

  Returns the merged stdout/stderr of the staging+commit+push pipeline.
  """
  repo_path = _resolve_repo_path(args.get("repo_path"))
  if not (repo_path / ".git").exists() and not repo_path.joinpath(".git").is_file():
    return CommandResult(
      ok=False, exit_code=None,
      cwd=str(repo_path),
      error=f"not a git working tree: {repo_path}",
    )
  message = (args.get("message") or "").strip() if isinstance(args, dict) else ""
  if not message:
    return CommandResult(
      ok=False, exit_code=None, cwd=str(repo_path),
      error="message is required",
    )
  paths_raw = (args.get("paths") or "").strip() if isinstance(args, dict) else ""
  push_to = (args.get("push_to") or "").strip() if isinstance(args, dict) else ""
  allow_empty = bool(args.get("allow_empty"))
  timeout = _coerce_timeout(args, _DEFAULT_TIMEOUT_S["local-git-commit-push"])

  combined_stdout: list[str] = []
  combined_stderr: list[str] = []
  t0 = time.monotonic()

  def step(label: str, argv: list[str]) -> tuple[int, str, str]:
    try:
      proc = subprocess.run(
        argv, cwd=str(repo_path), capture_output=True,
        timeout=timeout, check=False,
      )
    except subprocess.TimeoutExpired as exc:
      return -1, _trim(exc.stdout or ""), _trim(exc.stderr or "") + f"\n…timeout after {timeout:.0f}s during {label}"
    except Exception as exc:  # noqa: BLE001
      return -1, "", f"{type(exc).__name__}: {exc} (during {label})"
    return proc.returncode, _trim(proc.stdout), _trim(proc.stderr)

  # 1. Stage
  if paths_raw:
    try:
      add_argv = ["git", "add", "--"] + shlex.split(paths_raw)
    except ValueError as exc:
      return CommandResult(
        ok=False, exit_code=None, cwd=str(repo_path),
        error=f"invalid paths: {exc}",
      )
  else:
    add_argv = ["git", "add", "-A"]
  rc, out, err = step("git-add", add_argv)
  combined_stdout.append(f"$ {' '.join(shlex.quote(a) for a in add_argv)}")
  if out: combined_stdout.append(out)
  if err: combined_stderr.append(err)
  if rc != 0:
    duration_ms = int((time.monotonic() - t0) * 1000)
    return CommandResult(
      ok=False, exit_code=rc, cwd=str(repo_path),
      stdout="\n".join(combined_stdout), stderr="\n".join(combined_stderr),
      duration_ms=duration_ms,
      error=f"git add failed (exit {rc})",
    )

  # 2. Detect "nothing staged"
  rc, out, _err = step("git-status", ["git", "status", "--porcelain"])
  staged = bool(out.strip())
  if not staged and not allow_empty:
    duration_ms = int((time.monotonic() - t0) * 1000)
    combined_stdout.append("(no changes staged — skipping commit + push)")
    return CommandResult(
      ok=True, exit_code=0, cwd=str(repo_path),
      stdout="\n".join(combined_stdout), stderr="\n".join(combined_stderr),
      duration_ms=duration_ms,
      command="git add … && git commit -m … && git push",
      extra={"staged": False, "sha": None},
    )

  # 3. Commit
  # When ``paths`` is provided, restrict the commit to exactly those
  # paths via the ``-- <paths>`` form. This is critical: a plain
  # ``git commit`` would also pick up anything else already in the
  # index from a prior session, conflating the operator's intended
  # change with stale staged work.
  commit_argv = ["git", "commit", "-m", message]
  if allow_empty:
    commit_argv.append("--allow-empty")
  if paths_raw:
    try:
      commit_argv.append("--")
      commit_argv.extend(shlex.split(paths_raw))
    except ValueError as exc:
      return CommandResult(
        ok=False, exit_code=None, cwd=str(repo_path),
        error=f"invalid paths: {exc}",
      )
  rc, out, err = step("git-commit", commit_argv)
  combined_stdout.append(f"$ git commit -m {shlex.quote(message)}")
  if out: combined_stdout.append(out)
  if err: combined_stderr.append(err)
  if rc != 0:
    duration_ms = int((time.monotonic() - t0) * 1000)
    return CommandResult(
      ok=False, exit_code=rc, cwd=str(repo_path),
      stdout="\n".join(combined_stdout), stderr="\n".join(combined_stderr),
      duration_ms=duration_ms,
      error=f"git commit failed (exit {rc})",
    )

  # 4. Resolve SHA before push (so a push failure still reports what
  # got committed locally).
  rc_sha, sha_out, _ = step("git-rev-parse", ["git", "rev-parse", "--short", "HEAD"])
  sha = sha_out.strip() if rc_sha == 0 else None

  # 5. Push
  if push_to and ":" in push_to:
    remote, _, branch = push_to.partition(":")
    push_argv = ["git", "push", remote.strip() or "origin", (branch.strip() or "HEAD")]
  else:
    push_argv = ["git", "push"]
  rc, out, err = step("git-push", push_argv)
  combined_stdout.append("$ " + " ".join(shlex.quote(a) for a in push_argv))
  if out: combined_stdout.append(out)
  if err: combined_stderr.append(err)
  duration_ms = int((time.monotonic() - t0) * 1000)
  if rc != 0:
    return CommandResult(
      ok=False, exit_code=rc, cwd=str(repo_path),
      stdout="\n".join(combined_stdout), stderr="\n".join(combined_stderr),
      duration_ms=duration_ms,
      error=f"git push failed (exit {rc}); commit landed locally as {sha or '?'}",
      extra={"staged": True, "sha": sha},
    )
  return CommandResult(
    ok=True, exit_code=0, cwd=str(repo_path),
    stdout="\n".join(combined_stdout), stderr="\n".join(combined_stderr),
    duration_ms=duration_ms,
    command="git add … && git commit -m … && git push",
    extra={"staged": True, "sha": sha},
  )


# ---------------------------------------------------------------------------
# Executor: local-repo-sync
# ---------------------------------------------------------------------------


def run_local_repo_sync(args: dict[str, Any]) -> CommandResult:
  """Discard local changes and pull origin/<branch>. Used to recover from
  "uncommitted changes block deploy" or a botched merge.

  ``args``:
    repo_path  — required.
    remote     — optional, default "origin".
    branch     — optional, default current branch.
  """
  repo_path = _resolve_repo_path(args.get("repo_path"))
  if not (repo_path / ".git").exists() and not repo_path.joinpath(".git").is_file():
    return CommandResult(
      ok=False, exit_code=None, cwd=str(repo_path),
      error=f"not a git working tree: {repo_path}",
    )
  remote = ((args.get("remote") or "").strip() or "origin") if isinstance(args, dict) else "origin"
  branch = (args.get("branch") or "").strip() if isinstance(args, dict) else ""
  timeout = _coerce_timeout(args, _DEFAULT_TIMEOUT_S["local-repo-sync"])

  combined_stdout: list[str] = []
  combined_stderr: list[str] = []
  t0 = time.monotonic()

  def step(label: str, argv: list[str]) -> tuple[int, str, str]:
    try:
      proc = subprocess.run(argv, cwd=str(repo_path),
                            capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
      return -1, _trim(exc.stdout or ""), _trim(exc.stderr or "") + f"\n…timeout during {label}"
    except Exception as exc:  # noqa: BLE001
      return -1, "", f"{type(exc).__name__}: {exc} (during {label})"
    return proc.returncode, _trim(proc.stdout), _trim(proc.stderr)

  if not branch:
    rc, out, _ = step("git-symbolic-ref", ["git", "rev-parse", "--abbrev-ref", "HEAD"])
    branch = out.strip() if rc == 0 else "main"

  for label, argv in [
    ("git-fetch",     ["git", "fetch", remote, branch]),
    ("git-reset",     ["git", "reset", "--hard", f"{remote}/{branch}"]),
    ("git-clean",     ["git", "clean", "-fdx"]),
  ]:
    rc, out, err = step(label, argv)
    combined_stdout.append("$ " + " ".join(shlex.quote(a) for a in argv))
    if out: combined_stdout.append(out)
    if err: combined_stderr.append(err)
    if rc != 0:
      duration_ms = int((time.monotonic() - t0) * 1000)
      return CommandResult(
        ok=False, exit_code=rc, cwd=str(repo_path),
        stdout="\n".join(combined_stdout), stderr="\n".join(combined_stderr),
        duration_ms=duration_ms,
        error=f"{label} failed (exit {rc})",
      )
  duration_ms = int((time.monotonic() - t0) * 1000)
  return CommandResult(
    ok=True, exit_code=0, cwd=str(repo_path),
    stdout="\n".join(combined_stdout), stderr="\n".join(combined_stderr),
    duration_ms=duration_ms,
    command=f"fetch + reset --hard {remote}/{branch} + clean -fdx",
    extra={"branch": branch, "remote": remote},
  )


# ---------------------------------------------------------------------------
# Audit log helpers
# ---------------------------------------------------------------------------


def insert_run_start(database, command_id: str | None, args: dict[str, Any]) -> int | None:
  """Persist a ``running`` row to ``command_runs`` and return its id.
  Returns None on any DB failure — auditing is best-effort, never blocks
  the actual command execution."""
  try:
    with database.home_connect() as conn:
      with conn.cursor() as cur:
        cur.execute(
          """INSERT INTO command_runs (command_id, args_json, status, started_at)
             VALUES (%s, %s::jsonb, 'running', NOW())
             RETURNING id""",
          (command_id, json.dumps(args or {})),
        )
        row = cur.fetchone()
        return int(row["id"]) if row else None
  except Exception:  # noqa: BLE001
    LOGGER.exception("commands: insert_run_start failed (audit only, continuing)")
    return None


def update_run_finish(database, run_id: int | None, result: CommandResult) -> None:
  """Update the ``command_runs`` row with the final status + truncated
  output. No-op when ``run_id`` is None (insert_run_start failed)."""
  if run_id is None:
    return
  status = "success" if result.ok else "failed"
  try:
    with database.home_connect() as conn:
      with conn.cursor() as cur:
        cur.execute(
          """UPDATE command_runs
             SET status = %s,
                 exit_code = %s,
                 stdout_head = %s,
                 stderr_head = %s,
                 error_message = %s,
                 finished_at = NOW()
             WHERE id = %s""",
          (status, result.exit_code,
           _trim(result.stdout or ""),
           _trim(result.stderr or ""),
           result.error,
           run_id),
        )
  except Exception:  # noqa: BLE001
    LOGGER.exception("commands: update_run_finish failed (audit only, continuing)")


def list_recent_runs(database, command_id: str | None, limit: int = 25) -> list[dict[str, Any]]:
  """Fetch the most recent run rows, optionally filtered by ``command_id``."""
  limit = max(1, min(int(limit or 25), 200))
  try:
    with database.home_connect() as conn:
      with conn.cursor() as cur:
        if command_id:
          cur.execute(
            """SELECT id, command_id, args_json, status, exit_code,
                      stdout_head, stderr_head, error_message,
                      started_at, finished_at
               FROM command_runs
               WHERE command_id = %s
               ORDER BY started_at DESC
               LIMIT %s""",
            (command_id, limit),
          )
        else:
          cur.execute(
            """SELECT id, command_id, args_json, status, exit_code,
                      stdout_head, stderr_head, error_message,
                      started_at, finished_at
               FROM command_runs
               ORDER BY started_at DESC
               LIMIT %s""",
            (limit,),
          )
        return list(cur.fetchall() or [])
  except Exception:  # noqa: BLE001
    LOGGER.exception("commands: list_recent_runs failed")
    return []


def list_catalog(database) -> list[dict[str, Any]]:
  with database.home_connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """SELECT id, title, description, category, schema, exec,
                  is_builtin, sort_order, created_at, updated_at
           FROM commands_catalog
           ORDER BY category, sort_order, id""",
      )
      return list(cur.fetchall() or [])


def get_catalog_row(database, command_id: str) -> dict[str, Any] | None:
  with database.home_connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """SELECT id, title, description, category, schema, exec,
                  is_builtin, sort_order
           FROM commands_catalog
           WHERE id = %s""",
        (command_id,),
      )
      return cur.fetchone()


# ---------------------------------------------------------------------------
# Free-form runner — exported for /api/local/run, /api/local/git/...
# ---------------------------------------------------------------------------


def run_with_audit(
  database,
  command_id: str | None,
  args: dict[str, Any],
  executor: Callable[[dict[str, Any]], CommandResult],
) -> CommandResult:
  """Wrap ``executor(args)`` with a command_runs audit row. The audit
  write never alters the result the operator sees."""
  run_id = insert_run_start(database, command_id, args)
  try:
    result = executor(args)
  except Exception as exc:  # noqa: BLE001
    LOGGER.exception("commands: executor raised")
    result = CommandResult(ok=False, exit_code=None, error=f"{type(exc).__name__}: {exc}")
  update_run_finish(database, run_id, result)
  return result
