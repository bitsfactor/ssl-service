"""SSH-based node probe + remote command execution.

Used by the admin API to:
  * probe a remote node's health and the status of its ssl-service install,
  * deploy the service (run a configured shell command on the node),
  * update the service.

This module isolates all paramiko/SSH usage so tests can stub it without
touching the rest of the controller. Every public function takes a
NodeRecord and returns plain dicts/dataclasses — no network handles
escape this module.
"""
from __future__ import annotations

import io
import json
import re
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import paramiko
from paramiko.ssh_exception import (
  AuthenticationException,
  NoValidConnectionsError,
  SSHException,
)

from .db import NodeRecord, NodeStatusRecord


DEFAULT_DEPLOY_COMMAND = (
  "set -eux; "
  "if command -v curl >/dev/null 2>&1; then "
  "  curl -fsSL https://raw.githubusercontent.com/your-org/ssl-service/main/scripts/setup.sh "
  "  | sudo bash -s -- install --mode readonly; "
  "else "
  "  echo 'curl not installed; install curl first' >&2; exit 1; "
  "fi"
)

DEFAULT_UPDATE_COMMAND = (
  "set -eux; "
  "cd /opt/ssl-service 2>/dev/null || cd /root/ssl-service; "
  "git pull --ff-only && "
  "(systemctl daemon-reload || true) && "
  "(systemctl restart ssl-service || systemctl restart ssl-proxy-controller || true)"
)


@dataclass(slots=True)
class CommandResult:
  command: str
  exit_code: int
  stdout: str
  stderr: str
  duration_seconds: float


def _open_client(node: NodeRecord, timeout: float = 8.0) -> paramiko.SSHClient:
  """Open an SSHClient for the given node. Caller must .close()."""
  client = paramiko.SSHClient()
  client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  if node.auth_method == "password":
    if not node.ssh_password:
      raise ValueError("password auth selected but ssh_password is empty")
    client.connect(
      hostname=node.host,
      port=node.ssh_port,
      username=node.ssh_user,
      password=node.ssh_password,
      timeout=timeout,
      auth_timeout=timeout,
      banner_timeout=timeout,
      look_for_keys=False,
      allow_agent=False,
    )
  elif node.auth_method == "key":
    if not node.ssh_private_key:
      raise ValueError("key auth selected but ssh_private_key is empty")
    pkey = _load_private_key(node.ssh_private_key, node.ssh_key_passphrase)
    client.connect(
      hostname=node.host,
      port=node.ssh_port,
      username=node.ssh_user,
      pkey=pkey,
      timeout=timeout,
      auth_timeout=timeout,
      banner_timeout=timeout,
      look_for_keys=False,
      allow_agent=False,
    )
  else:
    raise ValueError(f"unknown auth_method: {node.auth_method}")
  return client


def _load_private_key(text: str, passphrase: str | None) -> paramiko.PKey:
  """Try the common key formats in order. Returns the first one that loads."""
  buf_factory = lambda: io.StringIO(text)
  errors: list[str] = []
  for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
    try:
      return cls.from_private_key(buf_factory(), password=passphrase or None)
    except SSHException as exc:
      errors.append(f"{cls.__name__}: {exc}")
      continue
  raise ValueError("could not parse private key; tried Ed25519/RSA/ECDSA/DSS: " + "; ".join(errors))


def _run(client: paramiko.SSHClient, command: str, timeout: float = 12.0) -> CommandResult:
  start = datetime.now(tz=UTC).timestamp()
  stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
  stdin.close()
  stdout_text = stdout.read().decode("utf-8", errors="replace")
  stderr_text = stderr.read().decode("utf-8", errors="replace")
  exit_code = stdout.channel.recv_exit_status()
  end = datetime.now(tz=UTC).timestamp()
  return CommandResult(command, exit_code, stdout_text, stderr_text, round(end - start, 3))


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------

# Single-shot script we run remotely. Each section's output is wrapped in
# `===KEY===` / `===END===` markers so we can split deterministically. We
# never trust exit codes here — every command swallows its own errors.
_PROBE_SCRIPT = r"""
emit() { echo "===$1===" ; eval "$2" 2>&1 || true ; echo "===END===" ; }
emit OS_RELEASE 'cat /etc/os-release 2>/dev/null | head -5'
emit UPTIME 'cat /proc/uptime 2>/dev/null'
emit LOAD 'uptime'
emit MEM 'free -m | awk "/Mem:/{print \$3 \"/\" \$2 \" MB\"}"'
emit DISK 'df -h / | awk "NR==2{print \$5 \" used of \" \$2}"'
emit SERVICE_ACTIVE 'systemctl is-active ssl-service 2>/dev/null || systemctl is-active ssl-proxy-controller 2>/dev/null || echo none'
emit SERVICE_VERSION 'cat /opt/ssl-service/VERSION 2>/dev/null || cat /root/ssl-service/VERSION 2>/dev/null || true'
emit SERVICE_INSTALLED 'test -d /opt/ssl-service && echo yes; test -d /root/ssl-service && echo yes; command -v ssl-service >/dev/null 2>&1 && echo yes; true'
emit SERVICE_MODE 'grep -E "^\s*mode:" /opt/ssl-service/config.yaml /root/ssl-service/config.yaml /etc/ssl-service/config.yaml 2>/dev/null | head -1 | awk -F: "{print \$3}" | tr -d " " '
emit SERVICE_GIT 'cd /opt/ssl-service 2>/dev/null && git rev-parse --short HEAD; cd /root/ssl-service 2>/dev/null && git rev-parse --short HEAD; true'
"""


def _parse_probe_output(text: str) -> dict[str, str]:
  out: dict[str, str] = {}
  current: str | None = None
  buf: list[str] = []
  for line in text.splitlines():
    if line.startswith("===") and line.endswith("==="):
      tag = line.strip("=")
      if tag == "END":
        if current is not None:
          out[current] = "\n".join(buf).strip()
        current, buf = None, []
      else:
        current = tag
        buf = []
    elif current is not None:
      buf.append(line)
  return out


def probe_node(node: NodeRecord) -> NodeStatusRecord:
  """SSH into the node and collect a status snapshot.

  Always returns a NodeStatusRecord — connection failures are captured
  in `last_probe_error` rather than raised.
  """
  now = datetime.now(tz=UTC)
  status = NodeStatusRecord(
    node_name=node.name,
    reachable=False,
    service_installed=None,
    service_running=None,
    service_mode=None,
    service_version=None,
    uptime_seconds=None,
    load_avg=None,
    memory=None,
    disk_usage=None,
    os_release=None,
    last_probed_at=now,
    last_probe_error=None,
    raw_probe=None,
  )

  client: paramiko.SSHClient | None = None
  try:
    client = _open_client(node)
    result = _run(client, _PROBE_SCRIPT, timeout=20.0)
    sections = _parse_probe_output(result.stdout)
    status.reachable = True
    status.raw_probe = {"sections": sections, "exit_code": result.exit_code}

    # OS / pretty name
    os_text = sections.get("OS_RELEASE", "")
    pretty = re.search(r'^PRETTY_NAME="?([^"\n]+)"?', os_text, flags=re.MULTILINE)
    if pretty:
      status.os_release = pretty.group(1).strip()

    # Uptime: /proc/uptime -> "12345.67 9876.54"; first field is seconds
    up_text = sections.get("UPTIME", "")
    if up_text:
      try:
        status.uptime_seconds = int(float(up_text.split()[0]))
      except (ValueError, IndexError):
        pass

    # Load avg from `uptime`
    load_text = sections.get("LOAD", "")
    m = re.search(r"load average[s]?:\s*([\d., ]+)", load_text)
    if m:
      status.load_avg = m.group(1).strip()

    # Memory and disk pre-formatted in the script
    if sections.get("MEM"):
      status.memory = sections["MEM"]
    if sections.get("DISK"):
      status.disk_usage = sections["DISK"]

    # Service active flag
    svc_active = sections.get("SERVICE_ACTIVE", "").strip().splitlines()
    if svc_active:
      first = svc_active[0].strip().lower()
      if first == "active":
        status.service_running = True
      elif first in ("inactive", "failed", "unknown", "none"):
        status.service_running = False
      else:
        status.service_running = None

    # Service installed: any "yes" line means yes
    inst_text = sections.get("SERVICE_INSTALLED", "")
    if "yes" in inst_text:
      status.service_installed = True
    elif inst_text == "":
      status.service_installed = None
    else:
      status.service_installed = False

    # Service version: prefer VERSION file, fall back to git short hash
    ver_text = sections.get("SERVICE_VERSION", "").strip()
    git_text = sections.get("SERVICE_GIT", "").strip().splitlines()
    git_text = [g for g in git_text if g and not g.startswith(("fatal", "stderr"))]
    if ver_text:
      status.service_version = ver_text.splitlines()[0]
    elif git_text:
      status.service_version = "git " + git_text[0]

    mode_text = sections.get("SERVICE_MODE", "").strip()
    if mode_text:
      status.service_mode = mode_text.splitlines()[0]

  except (AuthenticationException, NoValidConnectionsError, SSHException, OSError) as exc:
    status.last_probe_error = f"{type(exc).__name__}: {exc}"
  except Exception as exc:  # pragma: no cover — defensive
    status.last_probe_error = f"{type(exc).__name__}: {exc}"
  finally:
    if client is not None:
      try:
        client.close()
      except Exception:
        pass

  return status


# ---------------------------------------------------------------------------
# Run a single shell command (used by deploy + update)
# ---------------------------------------------------------------------------

def run_command(node: NodeRecord, command: str, timeout: float = 300.0) -> CommandResult:
  """Run an arbitrary shell command on the node via SSH."""
  if not command or not command.strip():
    raise ValueError("command must not be empty")
  client = _open_client(node)
  try:
    return _run(client, command, timeout=timeout)
  finally:
    try:
      client.close()
    except Exception:
      pass


def deploy_service(node: NodeRecord, override_command: str | None = None) -> CommandResult:
  command = (override_command or node.deploy_command or DEFAULT_DEPLOY_COMMAND).strip()
  return run_command(node, command, timeout=600.0)


def build_compose_deploy_command(
  *,
  service_name: str,
  github_repo_url: str,
  branch: str,
  install_dir: str,
  compose_file: str,
  env: dict[str, str] | None,
  pre_deploy_command: str | None = None,
  post_deploy_command: str | None = None,
  compose_template: str | None = None,
  config_files: dict[str, str] | None = None,
  rebuild: bool = True,
) -> str:
  """Generate a single shell command that:
    1. Ensures install_dir exists
    2. Clones the repo (or pulls if already cloned)
    3. Writes a .env file from `env`
    4. Optionally runs pre_deploy_command
    5. Runs `docker compose -f <file> up -d --build`
    6. Optionally runs post_deploy_command

  Robust to re-runs (idempotent for the env writeout and clone steps).
  """
  import shlex as _shlex
  import json as _json

  install_dir = install_dir.replace("{name}", service_name)
  env_lines: list[str] = []
  if env:
    for k, v in env.items():
      # Use single-quote safe encoding: replace ' with '\''.
      safe = v.replace("'", "'\\''")
      env_lines.append(f"{k}='{safe}'")
  env_blob = "\n".join(env_lines) + ("\n" if env_lines else "")

  parts = [
    "set -eu",
    f"INSTALL_DIR={_shlex.quote(install_dir)}",
    "mkdir -p \"$INSTALL_DIR\"",
    "cd \"$INSTALL_DIR\"",
    f"REPO={_shlex.quote(github_repo_url)}",
    f"BRANCH={_shlex.quote(branch)}",
    "if [ -d .git ]; then",
    "  git fetch --depth 1 origin \"$BRANCH\" || git fetch origin \"$BRANCH\"",
    "  git checkout \"$BRANCH\"",
    "  git reset --hard \"origin/$BRANCH\"",
    "else",
    "  git clone --depth 1 --branch \"$BRANCH\" \"$REPO\" .",
    "fi",
    f"COMPOSE_FILE={_shlex.quote(compose_file)}",
    "umask 077",
    "cat > .env <<'BFS_ENV_EOF'",
    env_blob.rstrip("\n"),
    "BFS_ENV_EOF",
  ]
  if compose_template:
    parts.extend([
      "echo '--- writing compose file from catalog template ---'",
      f"mkdir -p \"$(dirname \"$COMPOSE_FILE\")\"",
      f"cat > \"$COMPOSE_FILE\" <<'BFS_COMPOSE_EOF'",
      compose_template.rstrip("\n"),
      "BFS_COMPOSE_EOF",
    ])
  if config_files:
    parts.append("echo '--- writing config files from catalog ---'")
    for path, content in config_files.items():
      safe_path = path.lstrip("/")
      parts.extend([
        f"mkdir -p \"$(dirname {_shlex.quote(safe_path)})\"",
        f"cat > {_shlex.quote(safe_path)} <<'BFS_CONFIG_EOF'",
        content.rstrip("\n"),
        "BFS_CONFIG_EOF",
      ])
  if pre_deploy_command:
    parts.append(f"echo '--- pre-deploy ---'; {pre_deploy_command}")
  parts.append("echo '--- docker compose ---'")
  if rebuild:
    parts.append("docker compose -f \"$COMPOSE_FILE\" up -d --build")
  else:
    parts.append("docker compose -f \"$COMPOSE_FILE\" up -d")
  parts.append("docker compose -f \"$COMPOSE_FILE\" ps")
  if post_deploy_command:
    parts.append(f"echo '--- post-deploy ---'; {post_deploy_command}")
  return "\n".join(parts)


def update_service(node: NodeRecord, override_command: str | None = None) -> CommandResult:
  command = (override_command or node.update_command or DEFAULT_UPDATE_COMMAND).strip()
  return run_command(node, command, timeout=300.0)
