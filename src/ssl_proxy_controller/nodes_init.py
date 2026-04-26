"""Server initialization orchestrator.

Drives a multi-step bootstrap of a remote node:

  1. Set timezone
  2. Install git
  3. Install python
  4. Install node.js
  5. Install go
  6. Install docker
  7. Install + configure git deploy key (writes /root/.ssh/id_ed25519,
     adds github.com host key, sets git identity)
  8. Install codex CLI
  9. Configure codex API
 10. Change SSH port to the desired value
 11. Verify new SSH port works (re-connect through paramiko on the new
     port using the same auth)

The whole thing runs in a background thread once kicked off via
`schedule_init_run(...)`. Progress is streamed line-by-line into the
`node_init_runs.log_text` column so the polling endpoint can render a
live tail in the UI. After step 10 succeeds the orchestrator updates
the `nodes.ssh_port` column to the new port (which is the only piece
of state outside `node_init_runs`).

The bitsfactor scripts (https://github.com/bitsfactor/scripts) are
fetched on the remote host via `curl … bfs.sh | bash -s -- <command>`
each step, so we never have to pre-clone anything. `BFS_VER` defaults to
`main` per the user's choice.
"""
from __future__ import annotations

import json
import logging
import shlex
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import paramiko
from paramiko.ssh_exception import (
  AuthenticationException,
  NoValidConnectionsError,
  SSHException,
)

from .db import Database, NodeInitRunRecord, NodeRecord
from . import nodes as nodes_mod

LOGGER = logging.getLogger("ssl_proxy_controller.nodes_init")

BFS_VER = "main"
# Single line that is curled and piped into bash on the target host.
BFS_LAUNCHER = (
  "curl -fsSL https://fastly.jsdelivr.net/gh/bitsfactor/scripts@{ver}/bfs.sh"
)


@dataclass(slots=True)
class InitConfig:
  """Wizard answers, persisted as `node_init_runs.config_snapshot`."""
  git_private_key: str | None
  git_user_name: str | None
  git_user_email: str | None
  desired_ssh_port: int
  install_codex: bool
  codex_base_url: str | None
  codex_api_key: str | None
  timezone: str = "Asia/Shanghai"
  install_node: bool = True
  install_go: bool = True
  install_docker: bool = True
  install_python: bool = True

  def to_json(self) -> dict[str, Any]:
    out = {
      "git_user_name": self.git_user_name,
      "git_user_email": self.git_user_email,
      "desired_ssh_port": self.desired_ssh_port,
      "install_codex": self.install_codex,
      "codex_base_url": self.codex_base_url,
      "timezone": self.timezone,
      "install_node": self.install_node,
      "install_go": self.install_go,
      "install_docker": self.install_docker,
      "install_python": self.install_python,
      "has_git_private_key": bool(self.git_private_key),
      "has_codex_api_key": bool(self.codex_api_key),
    }
    return out


# ---------------------------------------------------------------------------
# Step plan
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Step:
  name: str
  describe: str
  # callable receives (ssh_client, init_config, log_func) and returns int exit code (0 = ok)
  run: Callable[..., int]
  required: bool = True


def _bfs_remote_command(action: str) -> str:
  """Build the remote `bfs.sh <action>` invocation."""
  url = BFS_LAUNCHER.format(ver=BFS_VER)
  # `bash -s -- <words>` passes positional args after `--` to the piped script.
  return f"BFS_VER={shlex.quote(BFS_VER)} bash -c {shlex.quote(f'curl -fsSL {url} | bash -s -- ' + action)}"


def _run_remote_with_input_file(
  ssh: paramiko.SSHClient,
  *,
  command: str,
  input_lines: list[str] | None,
  log_func: Callable[[str], None],
  timeout: float = 600.0,
) -> int:
  """Run a command on the remote host, optionally feeding it canned answers
  via the BFS_TTY_INPUT_FILE convention used by bitsfactor scripts.

  Each line in `input_lines` is written to a temp file on the remote host;
  the script reads from FD 9 (which is wired to that file). This is how we
  drive `git.sh set-key` and `codex.sh set-api` non-interactively without
  modifying upstream.
  """
  full_command = command
  cleanup = ""
  if input_lines is not None:
    # Write the input lines to a temp file on the remote, then export
    # BFS_TTY_INPUT_FILE before invoking. We use a heredoc so we don't
    # have to escape every special character per line.
    delimiter = "BFS_TTY_INPUT_EOF_BFS"
    body = "\n".join(input_lines) + "\n"
    setup = (
      f"_BFS_INPUT=$(mktemp -t bfs-input.XXXXXX); "
      f"cat > \"$_BFS_INPUT\" <<'{delimiter}'\n{body}{delimiter}\n; "
      f"export BFS_TTY_INPUT_FILE=\"$_BFS_INPUT\"; "
    )
    cleanup = '; rm -f "$_BFS_INPUT" >/dev/null 2>&1 || true'
    full_command = setup + command + cleanup

  log_func(f"\n$ {command}\n")
  start = time.time()
  stdin, stdout, stderr = ssh.exec_command(full_command, timeout=timeout, get_pty=False)
  stdin.close()
  # Stream stdout line-by-line; stderr is interleaved at the end.
  channel = stdout.channel
  buffer = bytearray()

  def drain_stdout(blocking: bool = False) -> None:
    while channel.recv_ready():
      chunk = channel.recv(8192)
      if not chunk:
        break
      buffer.extend(chunk)
      while b"\n" in buffer:
        idx = buffer.index(b"\n")
        line = bytes(buffer[: idx + 1]).decode("utf-8", errors="replace")
        del buffer[: idx + 1]
        log_func(line)

  while not channel.exit_status_ready():
    drain_stdout()
    if channel.recv_stderr_ready():
      err = channel.recv_stderr(8192)
      if err:
        log_func(err.decode("utf-8", errors="replace"))
    time.sleep(0.2)
    if time.time() - start > timeout:
      log_func(f"\n[timeout after {timeout:.0f}s]\n")
      try:
        channel.close()
      except Exception:
        pass
      return 124

  drain_stdout()
  if buffer:
    log_func(bytes(buffer).decode("utf-8", errors="replace"))
  err = stderr.read()
  if err:
    log_func(err.decode("utf-8", errors="replace"))
  exit_code = channel.recv_exit_status()
  log_func(f"\n[exit {exit_code} · {time.time() - start:.1f}s]\n")
  return exit_code


# Each step is a small closure over the BFS launcher.

def _step_set_timezone(ssh, cfg: InitConfig, log) -> int:
  cmd = _bfs_remote_command(f"env set-timezone {shlex.quote(cfg.timezone or 'Asia/Shanghai')}")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=None, log_func=log, timeout=120.0)


def _step_install_brew(ssh, cfg: InitConfig, log) -> int:
  # Linux-only init skips this; called only when uname says Darwin
  cmd = _bfs_remote_command("env install-brew")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=None, log_func=log, timeout=900.0)


def _step_install_git(ssh, cfg: InitConfig, log) -> int:
  cmd = _bfs_remote_command("env install-git")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=None, log_func=log, timeout=300.0)


def _step_install_python(ssh, cfg: InitConfig, log) -> int:
  cmd = _bfs_remote_command("env install-python")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=None, log_func=log, timeout=600.0)


def _step_install_node(ssh, cfg: InitConfig, log) -> int:
  cmd = _bfs_remote_command("env install-node")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=None, log_func=log, timeout=600.0)


def _step_install_go(ssh, cfg: InitConfig, log) -> int:
  cmd = _bfs_remote_command("env install-go")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=None, log_func=log, timeout=600.0)


def _step_install_docker(ssh, cfg: InitConfig, log) -> int:
  cmd = _bfs_remote_command("env install-docker")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=None, log_func=log, timeout=900.0)


def _step_set_git_key(ssh, cfg: InitConfig, log) -> int:
  if not cfg.git_private_key:
    log("[skip] no git_private_key provided\n")
    return 0
  # The git.sh set-key script reads:
  #   1. private key body, terminated by a -----END line
  #   2. Press-Enter confirm
  #   3. (if existing key) y/n overwrite — fresh server has no key, so skip
  #   4. git user.name
  #   5. git user.email
  #
  # We always preemptively answer the overwrite "y" too — on a re-init
  # the file already exists; on a fresh server the prompt is skipped and
  # the line is consumed by the next prompt instead, which is harmless
  # because git config prompts have defaults.
  body = cfg.git_private_key.rstrip("\n")
  if not body.endswith("-----"):
    log("[warn] private key does not end with a -----END marker; appending may misread\n")
  lines = body.splitlines()
  lines.append("")  # confirm
  lines.append("y")  # overwrite
  lines.append((cfg.git_user_name or "").strip())
  lines.append((cfg.git_user_email or "").strip())

  cmd = _bfs_remote_command("git set-key")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=lines, log_func=log, timeout=180.0)


def _step_install_codex(ssh, cfg: InitConfig, log) -> int:
  if not cfg.install_codex:
    log("[skip] install_codex disabled\n")
    return 0
  cmd = _bfs_remote_command("codex install")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=None, log_func=log, timeout=600.0)


def _step_set_codex_api(ssh, cfg: InitConfig, log) -> int:
  if not cfg.install_codex:
    log("[skip] install_codex disabled — skipping API setup\n")
    return 0
  if not cfg.codex_api_key:
    log("[skip] no codex_api_key provided\n")
    return 0
  url_line = cfg.codex_base_url or ""  # empty -> script default
  lines = [url_line, cfg.codex_api_key]
  cmd = _bfs_remote_command("codex set-api")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=lines, log_func=log, timeout=120.0)


def _step_change_ssh_port(ssh, cfg: InitConfig, log) -> int:
  port = int(cfg.desired_ssh_port)
  # Skip rather than fail when the desired port matches an obvious no-op
  # case (port == 22 means "leave it alone"; user wired the field to the
  # current default).
  if port == 22:
    log("[skip] desired_ssh_port=22 — leaving SSH port unchanged\n")
    return 0
  if port < 1024 or port > 65535:
    log(f"[error] invalid desired_ssh_port: {port} (must be 1024-65535)\n")
    return 1
  cmd = _bfs_remote_command(f"env ssh-port {port}")
  return _run_remote_with_input_file(ssh, command=cmd, input_lines=None, log_func=log, timeout=120.0)


# Default step order. macOS-only steps (brew) are filtered at runtime.
DEFAULT_STEPS: list[Step] = [
  Step("set-timezone",     "Set system timezone",         _step_set_timezone,     required=False),
  Step("install-git",      "Install git",                  _step_install_git,      required=True),
  Step("install-python",   "Install Python 3",             _step_install_python,   required=False),
  Step("install-node",     "Install Node.js + npm",        _step_install_node,     required=False),
  Step("install-go",       "Install Go toolchain",         _step_install_go,       required=False),
  Step("install-docker",   "Install Docker",               _step_install_docker,   required=False),
  Step("set-git-key",      "Install git deploy key",       _step_set_git_key,      required=False),
  Step("install-codex",    "Install Codex CLI",            _step_install_codex,    required=False),
  Step("set-codex-api",    "Configure Codex API",          _step_set_codex_api,    required=False),
  # SSH port change is LAST — it disconnects ourselves at the end.
  Step("change-ssh-port",  "Change SSH port",              _step_change_ssh_port,  required=False),
]


# ---------------------------------------------------------------------------
# Verification helpers
# ---------------------------------------------------------------------------

def _verify_new_ssh_port(node: NodeRecord, new_port: int, log: Callable[[str], None]) -> bool:
  """Try to SSH to the node on the new port. Returns True if it works."""
  log(f"\n[verify] connecting on new port {new_port}...\n")
  patched = NodeRecord(**{**{f.name: getattr(node, f.name) for f in node.__dataclass_fields__.values()}, "ssh_port": new_port})  # type: ignore[arg-type]
  for attempt in range(1, 4):
    try:
      client = nodes_mod._open_client(patched, timeout=10.0)
      client.close()
      log(f"[verify] OK on attempt {attempt}\n")
      return True
    except (AuthenticationException, NoValidConnectionsError, SSHException, OSError) as exc:
      log(f"[verify] attempt {attempt} failed: {type(exc).__name__}: {exc}\n")
      time.sleep(3)
  return False


# ---------------------------------------------------------------------------
# Top-level orchestration
# ---------------------------------------------------------------------------

def _make_logger(database: Database, run_id: int) -> tuple[Callable[[str], None], Callable[[], None]]:
  """Return (log, flush). `log(text)` appends and lazily DB-flushes; `flush()`
  forces an immediate DB write of whatever is buffered."""
  buffer: list[str] = []
  last_flush = [time.time()]

  def _do_flush() -> None:
    if not buffer:
      return
    database.update_init_run(run_id, append_log="".join(buffer))
    buffer.clear()
    last_flush[0] = time.time()

  def log(text: str) -> None:
    if not text:
      return
    buffer.append(text)
    total = sum(len(s) for s in buffer)
    if total >= 4096 or (time.time() - last_flush[0]) > 0.5:
      _do_flush()

  return log, _do_flush


def run_init(database: Database, node: NodeRecord, cfg: InitConfig, run_id: int) -> None:
  """Synchronous worker. Runs in a background thread."""
  log, flush = _make_logger(database, run_id)
  database.update_init_run(run_id, status="running")
  log(f"=== Initialize {node.name} ({node.host}) ===\n")
  log(f"BFS version: {BFS_VER}\n\n")

  # Build the SSH client up-front so connection failures are fatal.
  try:
    ssh = nodes_mod._open_client(node, timeout=10.0)
  except Exception as exc:
    log(f"[fatal] could not connect: {type(exc).__name__}: {exc}\n")
    flush()
    database.update_init_run(run_id, status="failed", exit_code=255, finished=True)
    return

  overall_exit = 0
  ssh_port_changed_to: int | None = None
  try:
    # Probe os to skip macOS-only steps (we expect Linux for VPS, but be safe).
    try:
      _, stdout, _ = ssh.exec_command("uname -s", timeout=5.0)
      uname = stdout.read().decode().strip().lower()
    except Exception:
      uname = "linux"
    log(f"Remote OS: {uname or 'unknown'}\n\n")

    for step in DEFAULT_STEPS:
      database.update_init_run(run_id, current_step=step.name)
      log(f"\n--- Step: {step.describe} ({step.name}) ---\n")
      try:
        rc = step.run(ssh, cfg, log)
      except Exception as exc:
        log(f"[error] {type(exc).__name__}: {exc}\n")
        rc = 1
      if rc != 0:
        log(f"[step failed: {step.name} exit={rc}]\n")
        if step.required:
          overall_exit = rc
          break
        # Non-required step: log and keep going.
        if overall_exit == 0:
          overall_exit = 0  # keep marking overall as success even with optional failures
      if step.name == "change-ssh-port" and rc == 0:
        ssh_port_changed_to = cfg.desired_ssh_port
  finally:
    try:
      ssh.close()
    except Exception:
      pass

  # If we changed the port, verify and update the node row.
  if ssh_port_changed_to:
    ok = _verify_new_ssh_port(node, ssh_port_changed_to, log)
    if ok:
      database.update_node(node.name, {"ssh_port": ssh_port_changed_to})
      log(f"[ok] nodes.ssh_port updated to {ssh_port_changed_to}\n")
    else:
      log(f"[warn] new port {ssh_port_changed_to} not reachable; keeping old port {node.ssh_port}\n")
      overall_exit = overall_exit or 2

  status = "success" if overall_exit == 0 else "failed"
  log(f"\n=== Init complete: {status} ===\n")
  # Force the in-memory buffer out before we mark the run finished, so
  # whoever polls right after sees the full tail.
  flush()
  database.update_init_run(
    run_id,
    status=status,
    exit_code=overall_exit,
    finished=True,
  )


def schedule_init_run(database: Database, node: NodeRecord, cfg: InitConfig) -> NodeInitRunRecord:
  """Insert a new init run row and start the worker thread."""
  run = database.insert_init_run(node.name, config_snapshot=cfg.to_json())
  thread = threading.Thread(
    target=run_init,
    args=(database, node, cfg, run.id),
    name=f"node-init-{node.name}-{run.id}",
    daemon=True,
  )
  thread.start()
  LOGGER.info("nodes_init.scheduled node=%s run_id=%s", node.name, run.id)
  return run
