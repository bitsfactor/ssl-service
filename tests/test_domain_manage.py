from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path("/root/ssl-server")
SCRIPT = ROOT / "scripts" / "domain-manage.sh"


def make_config(tmp_path: Path) -> Path:
  config = tmp_path / "config.yaml"
  config.write_text(
    """
mode: readwrite
postgres:
  dsn: postgresql://example
"""
  )
  return config


def make_config_with_mode(tmp_path: Path, mode: str) -> Path:
  config = tmp_path / "config.yaml"
  config.write_text(
    f"""
mode: {mode}
postgres:
  dsn: postgresql://example
"""
  )
  return config


def run_script(args: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
  return subprocess.run(
    ["bash", str(SCRIPT), *args],
    text=True,
    capture_output=True,
    env=env,
  )


def base_env(tmp_path: Path) -> dict[str, str]:
  env = os.environ.copy()
  env["SSL_PROXY_CONFIG"] = str(make_config(tmp_path))
  return env


def env_with_mode(tmp_path: Path, mode: str) -> dict[str, str]:
  env = os.environ.copy()
  env["SSL_PROXY_CONFIG"] = str(make_config_with_mode(tmp_path, mode))
  return env


def test_status_rejects_wildcard_domain(tmp_path: Path) -> None:
  result = run_script(["status", "*.example.com"], env=base_env(tmp_path))

  assert result.returncode != 0
  assert "wildcard domains are not supported" in result.stderr


def test_issue_now_rejects_invalid_domain_before_dns_check(tmp_path: Path) -> None:
  result = run_script(["issue-now", "invalid..example"], env=base_env(tmp_path))

  assert result.returncode != 0
  assert "invalid domain label" in result.stderr


def test_help_succeeds(tmp_path: Path) -> None:
  result = run_script(["help"], env=base_env(tmp_path))

  assert result.returncode == 0
  assert "issue-now <domain> [--force]" in result.stdout
  assert "check <domain>" in result.stdout


def test_issue_now_rejects_on_readonly_node_before_dns_or_db(tmp_path: Path) -> None:
  result = run_script(["issue-now", "example.com"], env=env_with_mode(tmp_path, "readonly"))

  assert result.returncode != 0
  assert "only available on readwrite nodes" in result.stderr


def test_issue_now_accepts_mixed_case_readwrite_mode(tmp_path: Path) -> None:
  result = run_script(["issue-now", "invalid..example"], env=env_with_mode(tmp_path, "ReadWrite"))

  assert result.returncode != 0
  assert "only available on readwrite nodes" not in result.stderr
  assert "invalid domain label" in result.stderr
