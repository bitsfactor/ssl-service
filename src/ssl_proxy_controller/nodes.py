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
import logging
import re
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import paramiko

LOGGER = logging.getLogger("ssl_proxy_controller.nodes")
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


def _open_client(
  node: NodeRecord,
  timeout: float = 8.0,
  *,
  linked_keys: list[dict] | None = None,
) -> paramiko.SSHClient:
  """Open an SSHClient for the given node. Caller must .close().

  Auth method semantics:
    * ``password`` — only try the stored password.
    * ``key``      — try every available private key (inline + linked
                     in ``linked_keys``) in order; first one that
                     authenticates wins. Raises if all fail.
    * ``auto``     — try keys first (same order as ``key``); on
                     AuthenticationException after exhausting them,
                     fall back to password if one is stored. Useful
                     for post-VPS-reinit recovery where the remote
                     authorized_keys was wiped.

  ``linked_keys`` is the platform's curated set of keys associated
  with this node (see Database.list_node_ssh_key_links). Each entry
  is a dict with at least ``private_key`` and optional ``passphrase``
  and ``name``. The legacy inline ``node.ssh_private_key`` is tried
  first when present.

  ``password`` and ``key`` no longer require the *other* field to be
  empty — the inactive credential is preserved on disk so the operator
  can flip ``auth_method`` without re-typing.
  """
  links = linked_keys or []

  def _new_client() -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return c

  def _connect_password(c: paramiko.SSHClient) -> None:
    if not node.ssh_password:
      raise ValueError("password auth requested but ssh_password is empty")
    c.connect(
      hostname=node.host, port=node.ssh_port, username=node.ssh_user,
      password=node.ssh_password,
      timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
      look_for_keys=False, allow_agent=False,
    )

  def _connect_with_pkey(c: paramiko.SSHClient, pkey) -> None:
    c.connect(
      hostname=node.host, port=node.ssh_port, username=node.ssh_user,
      pkey=pkey,
      timeout=timeout, auth_timeout=timeout, banner_timeout=timeout,
      look_for_keys=False, allow_agent=False,
    )

  # Build the ordered list of keys to try.
  candidates: list[tuple[str, str, str | None]] = []  # (label, private_key, passphrase)
  if node.ssh_private_key:
    candidates.append(("inline", node.ssh_private_key, node.ssh_key_passphrase))
  for link in links:
    pk = link.get("private_key")
    if not pk:
      continue
    label = f"linked:{link.get('name') or link.get('ssh_key_id')}"
    candidates.append((label, pk, link.get("passphrase")))

  def _try_keys() -> tuple[paramiko.SSHClient | None, list[str]]:
    """Iterate keys; return (client, errors). ``client`` is None if all keys failed."""
    errors: list[str] = []
    for label, pk_text, pp in candidates:
      try:
        pkey = _load_private_key(pk_text, pp)
      except Exception as exc:  # noqa: BLE001
        errors.append(f"{label}: load failed: {exc}")
        continue
      c = _new_client()
      try:
        _connect_with_pkey(c, pkey)
        LOGGER.info("ssh: connected to %s as %s with key %s",
                    node.name, node.ssh_user, label)
        return c, errors
      except AuthenticationException as exc:
        errors.append(f"{label}: auth rejected ({exc})")
      except Exception as exc:  # noqa: BLE001
        # Network / banner / etc — surface and stop trying further keys
        # since the issue isn't the key.
        try: c.close()
        except Exception: pass
        raise
      try: c.close()
      except Exception: pass
    return None, errors

  if node.auth_method == "password":
    c = _new_client()
    _connect_password(c)
    return c

  if node.auth_method == "key":
    if not candidates:
      raise ValueError("key auth requested but no keys are configured (inline or linked)")
    c, errors = _try_keys()
    if c is not None:
      return c
    raise AuthenticationException(
      "all configured keys were rejected: " + "; ".join(errors[-3:])
    )

  if node.auth_method == "auto":
    if candidates:
      try:
        c, errors = _try_keys()
        if c is not None:
          return c
      except Exception:
        # Network/etc — propagate; auto only handles auth failures.
        raise
      LOGGER.info("ssh: all keys rejected for %s — falling back to password (%d tried)",
                  node.name, len(candidates))
    if not node.ssh_password:
      raise ValueError(
        "auto auth: keys " +
        ("rejected" if candidates else "absent") +
        ", and no fallback password is set"
      )
    c = _new_client()
    _connect_password(c)
    return c

  raise ValueError(f"unknown auth_method: {node.auth_method}")


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
emit DOCKER_INSTALLED 'command -v docker >/dev/null 2>&1 && echo yes || echo no'
emit ALL_CONTAINERS 'command -v docker >/dev/null 2>&1 && docker ps -a --no-trunc --format "{{json .}}" 2>/dev/null || true'
"""


def _parse_containers(text: str) -> list[dict[str, str]]:
  """Parse the ALL_CONTAINERS section into a list of normalized dicts.

  Each line is one ``docker ps --format '{{json .}}'`` object, e.g.
  ``{"Names":"ssl-service","State":"running","Image":"ssl-service:local",
     "Status":"Up 5 minutes (healthy)","RunningFor":"5 minutes","CreatedAt":"..."}``

  We pick out a stable subset, lowercase the state, and skip any line
  that isn't valid JSON or is missing a name (defensive — shells can
  inject leading warnings or older docker versions can omit fields).
  """
  import json as _json
  out: list[dict[str, str]] = []
  for line in (text or "").splitlines():
    line = line.strip()
    if not line or not line.startswith("{"):
      continue
    try:
      obj = _json.loads(line)
    except Exception:  # noqa: BLE001
      continue
    name = (obj.get("Names") or obj.get("Name") or "").strip()
    if not name:
      continue
    out.append({
      "name": name,
      "state": (obj.get("State") or "").strip().lower(),
      "image": (obj.get("Image") or "").strip(),
      "status_str": (obj.get("Status") or "").strip(),
      "running_for": (obj.get("RunningFor") or "").strip(),
      "created_at": (obj.get("CreatedAt") or "").strip(),
    })
  return out


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


def probe_node(node: NodeRecord, *, linked_keys: list[dict] | None = None) -> NodeStatusRecord:
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
    client = _open_client(node, linked_keys=linked_keys)
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

    # Parse the unified ALL_CONTAINERS section (one per managed service
    # going forward). We derive the legacy `service_running` / `service_installed`
    # for "ssl-service" specifically so the existing Nodes-page badge keeps
    # working until we migrate the column.
    containers = _parse_containers(sections.get("ALL_CONTAINERS", ""))
    status.raw_probe = {
      **(status.raw_probe or {}),
      "containers": containers,
    }
    ssl = next((c for c in containers if c["name"] == "ssl-service"), None)
    container_running = bool(ssl and ssl["state"] == "running")
    container_present = ssl is not None

    # systemd active flag (legacy install path)
    systemd_running = False
    systemd_known = False
    svc_active = sections.get("SERVICE_ACTIVE", "").strip().splitlines()
    if svc_active:
      first = svc_active[0].strip().lower()
      systemd_known = first in ("active", "inactive", "failed", "unknown", "none")
      systemd_running = (first == "active")

    # Unified flag: running if EITHER systemd or docker says so.
    if container_running or systemd_running:
      status.service_running = True
    elif container_present or systemd_known:
      status.service_running = False
    else:
      status.service_running = None

    # Installed: container exists, OR /opt/ssl-service exists, OR
    # legacy ssl-service binary in PATH.
    inst_text = sections.get("SERVICE_INSTALLED", "")
    if container_present or "yes" in inst_text:
      status.service_installed = True
    elif inst_text == "" and not containers:
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

def run_command(
  node: NodeRecord,
  command: str,
  timeout: float = 300.0,
  *,
  linked_keys: list[dict] | None = None,
) -> CommandResult:
  """Run an arbitrary shell command on the node via SSH."""
  if not command or not command.strip():
    raise ValueError("command must not be empty")
  client = _open_client(node, linked_keys=linked_keys)
  try:
    return _run(client, command, timeout=timeout)
  finally:
    try:
      client.close()
    except Exception:
      pass


# ---------------------------------------------------------------------------
# Deploy an SSH key to a node
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SshKeyDeployResult:
  """Per-node, per-mode outcome of a deploy_ssh_key call."""
  node_name: str
  mode: str                   # "public" | "private" | "both"
  ok: bool
  public_added: bool          # whether public key was appended (or already present)
  public_already_present: bool
  private_path: str | None    # remote path the private key was written to
  error: str | None
  duration_seconds: float


def deploy_ssh_key(
  node: NodeRecord,
  *,
  key_name: str,
  public_key: str,
  private_key: str | None,
  mode: str,                  # "public" | "private" | "both"
  linked_keys: list[dict] | None = None,
) -> SshKeyDeployResult:
  """Deploy an SSH keypair onto a remote node.

  ``mode`` controls what gets written:
  * ``public``  — append ``public_key`` to ``~/.ssh/authorized_keys`` (so
                  *clients* holding the matching private key can SSH in
                  to this node).
  * ``private`` — write ``private_key`` to ``~/.ssh/<key_name>`` and
                  ``public_key`` to ``~/.ssh/<key_name>.pub`` (so this
                  node can use the keypair as a *client* to authenticate
                  to GitHub / other SSH servers).
  * ``both``    — both of the above.

  We connect using whatever auth_method the node already has configured
  (password or its existing key). We never trust the new key for the
  connection itself — that's the operator's job to wire up afterwards.
  """
  if mode not in ("public", "private", "both"):
    raise ValueError(f"invalid mode: {mode}")
  if mode in ("public", "both") and not (public_key or "").strip():
    raise ValueError("public_key is required for this mode")
  if mode in ("private", "both") and not (private_key or "").strip():
    raise ValueError("private_key is required for this mode")

  start = datetime.now(tz=UTC).timestamp()
  result = SshKeyDeployResult(
    node_name=node.name,
    mode=mode,
    ok=False,
    public_added=False,
    public_already_present=False,
    private_path=None,
    error=None,
    duration_seconds=0.0,
  )

  client: paramiko.SSHClient | None = None
  sftp: paramiko.SFTPClient | None = None
  try:
    client = _open_client(node, linked_keys=linked_keys)

    # Resolve $HOME on the remote so we can write ~/.ssh deterministically.
    home_res = _run(client, "echo $HOME", timeout=8.0)
    if home_res.exit_code != 0 or not home_res.stdout.strip():
      raise RuntimeError(f"could not resolve remote $HOME: {home_res.stderr or home_res.stdout}")
    home = home_res.stdout.strip()
    ssh_dir = f"{home}/.ssh"

    # Always make sure ~/.ssh exists with correct mode.
    setup = _run(
      client,
      f"mkdir -p {shlex.quote(ssh_dir)} && chmod 700 {shlex.quote(ssh_dir)}",
      timeout=8.0,
    )
    if setup.exit_code != 0:
      raise RuntimeError(f"could not prepare {ssh_dir}: {setup.stderr or setup.stdout}")

    # ---- public key: append to authorized_keys (idempotent) ------------
    if mode in ("public", "both"):
      pub_line = (public_key or "").strip()
      auth_path = f"{ssh_dir}/authorized_keys"
      # Use grep -qxF so the comparison is line-exact (no regex meta).
      check = _run(
        client,
        (
          f"touch {shlex.quote(auth_path)} && chmod 600 {shlex.quote(auth_path)} && "
          f"grep -qxF {shlex.quote(pub_line)} {shlex.quote(auth_path)}"
        ),
        timeout=8.0,
      )
      if check.exit_code == 0:
        result.public_already_present = True
        result.public_added = True  # treat as success
      else:
        # Append.
        append = _run(
          client,
          (
            f"printf '%s\\n' {shlex.quote(pub_line)} "
            f">> {shlex.quote(auth_path)} && "
            f"chmod 600 {shlex.quote(auth_path)}"
          ),
          timeout=8.0,
        )
        if append.exit_code != 0:
          raise RuntimeError(f"could not append to authorized_keys: {append.stderr or append.stdout}")
        result.public_added = True

    # ---- private key: write to ~/.ssh/<name> with strict perms --------
    if mode in ("private", "both"):
      sftp = client.open_sftp()
      # Sanitize the file name — only allow what we've already validated
      # in the admin layer, but double-check here.
      safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", key_name or "id_key")[:64] or "id_key"
      priv_path = f"{ssh_dir}/{safe_name}"
      pub_path = f"{ssh_dir}/{safe_name}.pub"
      # Write private then chmod 600 atomically.
      with sftp.open(priv_path, "w") as fh:
        fh.write(private_key)
      sftp.chmod(priv_path, 0o600)
      if (public_key or "").strip():
        with sftp.open(pub_path, "w") as fh:
          fh.write((public_key or "").strip() + "\n")
        sftp.chmod(pub_path, 0o644)
      result.private_path = priv_path

    result.ok = True
  except (
    AuthenticationException,
    NoValidConnectionsError,
    SSHException,
    OSError,
    RuntimeError,
    ValueError,
  ) as exc:
    result.error = f"{type(exc).__name__}: {exc}"[:500]
  finally:
    try:
      if sftp is not None:
        sftp.close()
    except Exception:
      pass
    try:
      if client is not None:
        client.close()
    except Exception:
      pass
    result.duration_seconds = round(datetime.now(tz=UTC).timestamp() - start, 3)
  return result


# ---------------------------------------------------------------------------
# Manifest-driven service deploy
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ManifestDeployResult:
  """Outcome of one (service, node) deploy attempt."""
  node_name: str
  service_name: str
  ok: bool
  exit_code: int | None
  deployed_sha: str | None
  healthcheck_passed: bool | None
  healthcheck_detail: str | None
  log_text: str
  error: str | None
  duration_seconds: float


def deploy_service_with_manifest(
  node: NodeRecord,
  *,
  service_name: str,
  deploy_script: str,
  healthcheck_script: str | None,
  deploy_timeout: float = 600.0,
  healthcheck_timeout: float = 120.0,
  linked_keys: list[dict] | None = None,
) -> ManifestDeployResult:
  """Run the rendered deploy script on a node, then verify healthcheck.

  Both scripts come pre-rendered from
  ``services_deploy.render_deploy_script`` /
  ``render_healthcheck_script`` — this function only does SSH plumbing.
  """
  start = datetime.now(tz=UTC).timestamp()
  result = ManifestDeployResult(
    node_name=node.name,
    service_name=service_name,
    ok=False,
    exit_code=None,
    deployed_sha=None,
    healthcheck_passed=None,
    healthcheck_detail=None,
    log_text="",
    error=None,
    duration_seconds=0.0,
  )

  client: paramiko.SSHClient | None = None
  log_chunks: list[str] = []
  try:
    client = _open_client(node, linked_keys=linked_keys)

    # 1. Run the deploy script. We pipe it via stdin to bash so we
    # don't have to fight quoting on the heredoc inside the script.
    stdin, stdout, stderr = client.exec_command(
      "bash -s -- 2>&1", timeout=deploy_timeout,
    )
    stdin.write(deploy_script)
    stdin.flush()
    stdin.channel.shutdown_write()
    deploy_out = stdout.read().decode("utf-8", errors="replace")
    deploy_err = stderr.read().decode("utf-8", errors="replace")
    exit_code = stdout.channel.recv_exit_status()
    result.exit_code = exit_code
    log_chunks.append("=== deploy ===")
    log_chunks.append(deploy_out)
    if deploy_err:
      log_chunks.append("=== deploy stderr ===")
      log_chunks.append(deploy_err)

    # Capture DEPLOYED_SHA from the script's stdout marker.
    for line in (deploy_out or "").splitlines()[::-1]:
      if line.startswith("DEPLOYED_SHA="):
        result.deployed_sha = line.split("=", 1)[1].strip() or None
        break

    if exit_code != 0:
      result.error = f"deploy script failed (exit={exit_code})"
      return result

    # 2. Healthcheck (optional).
    if healthcheck_script and healthcheck_script.strip():
      hc_stdin, hc_stdout, hc_stderr = client.exec_command(
        "bash -s -- 2>&1", timeout=healthcheck_timeout,
      )
      hc_stdin.write(healthcheck_script)
      hc_stdin.flush()
      hc_stdin.channel.shutdown_write()
      hc_out = hc_stdout.read().decode("utf-8", errors="replace")
      hc_err = hc_stderr.read().decode("utf-8", errors="replace")
      hc_exit = hc_stdout.channel.recv_exit_status()
      log_chunks.append("=== healthcheck ===")
      log_chunks.append(hc_out)
      if hc_err:
        log_chunks.append("=== healthcheck stderr ===")
        log_chunks.append(hc_err)
      result.healthcheck_passed = hc_exit == 0
      result.healthcheck_detail = (hc_out + ("\n" + hc_err if hc_err else "")).strip()[-600:]
      if hc_exit != 0:
        result.error = "healthcheck failed"
        return result
    else:
      result.healthcheck_passed = None  # not configured — neither pass nor fail

    result.ok = True
  except (
    AuthenticationException,
    NoValidConnectionsError,
    SSHException,
    OSError,
    RuntimeError,
    ValueError,
  ) as exc:
    result.error = f"{type(exc).__name__}: {exc}"[:500]
  finally:
    try:
      if client is not None:
        client.close()
    except Exception:
      pass
    result.log_text = ("\n".join(log_chunks))[:20_000]  # cap to keep DB rows sane
    result.duration_seconds = round(datetime.now(tz=UTC).timestamp() - start, 3)
  return result


def deploy_service(node: NodeRecord, override_command: str | None = None,
                   *, linked_keys: list[dict] | None = None) -> CommandResult:
  command = (override_command or node.deploy_command or DEFAULT_DEPLOY_COMMAND).strip()
  return run_command(node, command, timeout=600.0, linked_keys=linked_keys)


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


def update_service(node: NodeRecord, override_command: str | None = None,
                    *, linked_keys: list[dict] | None = None) -> CommandResult:
  command = (override_command or node.update_command or DEFAULT_UPDATE_COMMAND).strip()
  return run_command(node, command, timeout=300.0, linked_keys=linked_keys)
