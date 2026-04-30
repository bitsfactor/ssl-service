"""Service deployment logic — manifest parsing, env rendering, deploy script.

Companion to ``admin.py`` for the platform's "Deploy a service to one
or more nodes" feature. The shape of the contract is documented in
``examples/service-template/.deploy.yaml``.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import yaml

LOGGER = logging.getLogger("ssl_proxy_controller.services_deploy")

# Healthy default values that fill in when .deploy.yaml omits them.
_DEFAULT_HEALTHCHECK = {
  "url": "",
  "expect_status": 200,
  "timeout_seconds": 30,
  "retries": 6,
  "interval_seconds": 5,
}


@dataclass(slots=True)
class DeployManifest:
  """Parsed `.deploy.yaml`."""
  service: str
  runtime: str = "compose"
  compose_file: str = "docker-compose.yml"
  install_dir_template: str = "/opt/{name}"
  required_env: list[str] = field(default_factory=list)
  defaults: dict[str, str] = field(default_factory=dict)
  secrets: list[dict[str, Any]] = field(default_factory=list)
  exposed_ports: list[int] = field(default_factory=list)
  healthcheck: dict[str, Any] = field(default_factory=lambda: dict(_DEFAULT_HEALTHCHECK))
  depends_on: list[str] = field(default_factory=list)
  hooks: dict[str, str] = field(default_factory=dict)
  volumes: list[str] = field(default_factory=list)

  def install_dir(self) -> str:
    return self.install_dir_template.replace("{name}", self.service)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_deploy_yaml(text: str) -> DeployManifest:
  """Parse a ``.deploy.yaml`` blob into a typed manifest.

  Raises ``ValueError`` with a friendly message when required fields
  are missing or wrong-typed.
  """
  if not text or not text.strip():
    raise ValueError(".deploy.yaml is empty")
  try:
    data = yaml.safe_load(text)
  except yaml.YAMLError as exc:
    raise ValueError(f"could not parse YAML: {exc}") from exc
  if not isinstance(data, dict):
    raise ValueError(".deploy.yaml must be a mapping at the top level")

  service = (data.get("service") or "").strip()
  if not service:
    raise ValueError(".deploy.yaml: `service` is required")

  runtime = (data.get("runtime") or "compose").strip().lower()
  if runtime not in ("compose",):
    raise ValueError(f"runtime '{runtime}' is not supported; only 'compose' for now")

  manifest = DeployManifest(
    service=service,
    runtime=runtime,
    compose_file=(data.get("compose_file") or "docker-compose.yml").strip(),
    install_dir_template=(data.get("install_dir_template") or "/opt/{name}").strip(),
  )

  req = data.get("required_env") or []
  if isinstance(req, list):
    manifest.required_env = [str(x).strip() for x in req if str(x).strip()]

  defaults = data.get("defaults") or {}
  if isinstance(defaults, dict):
    manifest.defaults = {str(k): _stringify(v) for k, v in defaults.items() if k}

  secrets = data.get("secrets") or []
  if isinstance(secrets, list):
    cleaned: list[dict[str, Any]] = []
    for s in secrets:
      if isinstance(s, dict) and s.get("env"):
        cleaned.append({
          "env": str(s["env"]).strip(),
          "from": str(s.get("from") or "").strip() or None,
        })
    manifest.secrets = cleaned

  ports = data.get("exposed_ports") or []
  if isinstance(ports, list):
    out: list[int] = []
    for p in ports:
      try:
        n = int(p)
      except (TypeError, ValueError):
        continue
      if 0 < n < 65536:
        out.append(n)
    manifest.exposed_ports = out

  hc = data.get("healthcheck") or {}
  if isinstance(hc, dict):
    merged = dict(_DEFAULT_HEALTHCHECK)
    for k, v in hc.items():
      if k in merged:
        merged[k] = v
    manifest.healthcheck = merged

  deps = data.get("depends_on") or []
  if isinstance(deps, list):
    manifest.depends_on = [str(x).strip() for x in deps if str(x).strip()]

  hooks = data.get("hooks") or {}
  if isinstance(hooks, dict):
    manifest.hooks = {
      str(k): str(v).strip()
      for k, v in hooks.items()
      if k in ("pre_deploy", "post_deploy", "on_first_deploy") and v
    }

  vols = data.get("volumes") or []
  if isinstance(vols, list):
    manifest.volumes = [str(x).strip() for x in vols if str(x).strip()]

  return manifest


def _stringify(value: Any) -> str:
  if value is None:
    return ""
  if isinstance(value, bool):
    return "true" if value else "false"
  return str(value)


# ---------------------------------------------------------------------------
# GitHub raw fetch
# ---------------------------------------------------------------------------


_GITHUB_REPO_RE = re.compile(
  r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$",
  re.IGNORECASE,
)


def github_raw_url(repo_url: str, branch: str, path: str) -> str | None:
  """Convert https://github.com/<owner>/<repo> + branch + path to
  the raw.githubusercontent.com URL for that file. Returns None if
  ``repo_url`` doesn't look like a GitHub repo."""
  m = _GITHUB_REPO_RE.match((repo_url or "").strip())
  if not m:
    return None
  owner = m.group("owner")
  repo = m.group("repo")
  return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def fetch_deploy_yaml_from_github(
  repo_url: str, branch: str = "main", *, timeout: float = 10.0
) -> tuple[str, str]:
  """Try `branch` then `master`, looking for `.deploy.yaml` at the repo root.

  Returns ``(text, branch_used)``. Raises ``ValueError`` if neither branch
  has the file or the URL isn't a recognized GitHub URL.
  """
  for candidate in (branch, "main", "master"):
    if not candidate:
      continue
    url = github_raw_url(repo_url, candidate, ".deploy.yaml")
    if url is None:
      raise ValueError(f"not a github URL: {repo_url}")
    try:
      req = urllib.request.Request(
        url,
        headers={"User-Agent": "ssl-service-platform-deploy/1.0"},
      )
      with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
          continue
        text = resp.read().decode("utf-8", errors="replace")
        return text, candidate
    except urllib.error.HTTPError as exc:
      if exc.code == 404:
        continue
      raise ValueError(f"github fetch failed: HTTP {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
      raise ValueError(f"github fetch failed: {exc.reason}") from exc
  raise ValueError(
    f".deploy.yaml not found in {repo_url} on branch {branch} (also tried main/master)"
  )


# ---------------------------------------------------------------------------
# Effective env rendering
# ---------------------------------------------------------------------------


def build_effective_env(
  manifest: DeployManifest,
  *,
  per_deploy_env: dict[str, str] | None = None,
  service_default_env: dict[str, str] | None = None,
  secrets_resolver=None,
) -> tuple[dict[str, str], list[str]]:
  """Merge (manifest defaults) ⟵ (service.default_env) ⟵ (per-deploy
  overrides) ⟵ (resolved secrets), then check ``required_env`` is
  satisfied.

  Returns ``(env_dict, missing_required)``. Caller decides whether to
  refuse to deploy when ``missing_required`` is non-empty.
  """
  effective: dict[str, str] = {}
  effective.update({k: _stringify(v) for k, v in manifest.defaults.items()})
  if service_default_env:
    effective.update({k: _stringify(v) for k, v in service_default_env.items()})
  if per_deploy_env:
    effective.update({k: _stringify(v) for k, v in per_deploy_env.items()})
  if secrets_resolver and manifest.secrets:
    for s in manifest.secrets:
      env_name = s.get("env")
      src = s.get("from")
      if not env_name or not src:
        continue
      try:
        val = secrets_resolver(src)
      except Exception as exc:  # noqa: BLE001
        LOGGER.warning("secret resolver failed for %s: %s", src, exc)
        val = None
      if val is not None:
        effective[env_name] = _stringify(val)

  # The compose project name + container name need this if the
  # compose template references ${SERVICE_NAME}. Fill it in always.
  effective.setdefault("SERVICE_NAME", manifest.service)

  missing = [k for k in manifest.required_env if not effective.get(k)]
  return effective, missing


def render_env_file(env: dict[str, str]) -> str:
  """Render an env dict to .env-file form (KEY=value, double-quoted
  with backslash escaping for safety)."""
  lines: list[str] = []
  for k in sorted(env.keys()):
    v = env[k] if env[k] is not None else ""
    # Escape backslash, dollar (for shell expansion if anything sources
    # this), and double quotes.
    safe = v.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    lines.append(f'{k}="{safe}"')
  return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Remote deploy script generation
# ---------------------------------------------------------------------------


def render_deploy_script(
  *,
  manifest: DeployManifest,
  service_repo_url: str,
  service_branch: str,
  revision: str | None,
  env_file_content: str,
  install_dir: str | None = None,
) -> str:
  """Build the bash script the platform runs on the target node.

  The script:
    1. Clones / fetches the repo to install_dir
    2. Checks out the requested revision (sha / tag / branch)
    3. Writes `.env` from env_file_content
    4. Creates volume directories
    5. Runs `pre_deploy.sh` (if present)
    6. Runs `docker compose up -d --build`
    7. (Healthcheck is verified separately by the platform — not in
       this script — so the platform can capture detailed status.)

  No post-deploy hook / no rollback in this script: the platform calls
  another script for that AFTER the healthcheck verdict is in.
  """
  install = install_dir or manifest.install_dir()
  rev = (revision or service_branch or "main").strip() or "main"
  compose = manifest.compose_file or "docker-compose.yml"
  pre = manifest.hooks.get("pre_deploy") or ""

  vols_block = ""
  if manifest.volumes:
    paths = " ".join(shlex.quote(v.replace("{name}", manifest.service))
                     for v in manifest.volumes)
    vols_block = f"mkdir -p {paths}\n"

  pre_block = ""
  if pre:
    pre_block = (
      f"if [[ -x {shlex.quote(pre)} ]]; then\n"
      f"  echo '--- pre_deploy ---'; bash {shlex.quote(pre)};\n"
      f"fi\n"
    )

  # The env content is written via heredoc; we delimit with a marker
  # that's deliberately unlikely to collide with any value text.
  marker = "SSLSVC_ENV_E0F"

  return f"""#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR={shlex.quote(install)}
REPO_URL={shlex.quote(service_repo_url)}
REVISION={shlex.quote(rev)}
SERVICE={shlex.quote(manifest.service)}
COMPOSE_FILE={shlex.quote(compose)}

echo "==> Service: ${{SERVICE}}"
echo "==> Install dir: ${{INSTALL_DIR}}"
echo "==> Revision target: ${{REVISION}}"

mkdir -p "${{INSTALL_DIR}}"
if [[ ! -d "${{INSTALL_DIR}}/.git" ]]; then
  git clone "${{REPO_URL}}" "${{INSTALL_DIR}}"
fi
cd "${{INSTALL_DIR}}"

git fetch --all --tags --prune
# Resolve REVISION: if it's a sha, use it directly; if a branch/tag,
# checkout via origin/<branch> when applicable.
if git rev-parse --verify "${{REVISION}}" >/dev/null 2>&1; then
  git checkout --detach "${{REVISION}}"
elif git rev-parse --verify "origin/${{REVISION}}" >/dev/null 2>&1; then
  git checkout --detach "origin/${{REVISION}}"
else
  echo "ERROR: revision '${{REVISION}}' not found in repo" >&2
  exit 2
fi
DEPLOYED_SHA="$(git rev-parse HEAD)"
echo "==> Resolved SHA: ${{DEPLOYED_SHA}}"

cat > .env <<'{marker}'
{env_file_content}{marker}

{vols_block}{pre_block}
echo "--- docker compose up -d --build ---"
docker compose -f {shlex.quote(compose)} -p "${{SERVICE}}" up -d --build

echo "==> Deploy script complete"
echo "DEPLOYED_SHA=${{DEPLOYED_SHA}}"
"""


# ---------------------------------------------------------------------------
# Healthcheck helpers (executed remotely by the platform)
# ---------------------------------------------------------------------------


def render_healthcheck_script(
  manifest: DeployManifest, env: dict[str, str]
) -> str:
  """Build the bash that probes the configured healthcheck endpoint.

  Substitutes ``${VAR}`` in the URL from the effective env, then loops
  ``retries`` times waiting for the expected status. Exits 0 on
  success, non-zero with a short message on failure.
  """
  url = (manifest.healthcheck.get("url") or "").strip()
  if not url:
    return "echo 'no healthcheck configured'\nexit 0\n"
  # Substitute ${VAR} from env in the URL.
  for k, v in env.items():
    url = url.replace("${" + k + "}", v or "")
  expect = int(manifest.healthcheck.get("expect_status") or 200)
  retries = max(1, int(manifest.healthcheck.get("retries") or 6))
  interval = max(1, int(manifest.healthcheck.get("interval_seconds") or 5))
  timeout = max(1, int(manifest.healthcheck.get("timeout_seconds") or 30))
  return f"""#!/usr/bin/env bash
set -uo pipefail
URL={shlex.quote(url)}
EXPECT={expect}
RETRIES={retries}
INTERVAL={interval}
TIMEOUT={timeout}
LAST_STATUS=""
LAST_ERR=""
for i in $(seq 1 ${{RETRIES}}); do
  STATUS=$(curl -s -o /tmp/hc.body -w '%{{http_code}}' --max-time ${{TIMEOUT}} "${{URL}}" || echo "000")
  LAST_STATUS="${{STATUS}}"
  if [[ "${{STATUS}}" == "${{EXPECT}}" ]]; then
    echo "healthcheck ok: ${{URL}} -> ${{STATUS}} (after ${{i}} tries)"
    head -c 400 /tmp/hc.body 2>/dev/null || true; echo
    exit 0
  fi
  sleep ${{INTERVAL}}
done
echo "healthcheck failed: ${{URL}} -> ${{LAST_STATUS}} (expected ${{EXPECT}})" >&2
head -c 400 /tmp/hc.body 2>/dev/null || true; echo >&2
exit 1
"""


__all__ = [
  "DeployManifest",
  "parse_deploy_yaml",
  "github_raw_url",
  "fetch_deploy_yaml_from_github",
  "build_effective_env",
  "render_env_file",
  "render_deploy_script",
  "render_healthcheck_script",
]
