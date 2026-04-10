from __future__ import annotations

import os
import shutil
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


def make_config_with_dsn(tmp_path: Path, dsn: str) -> Path:
  config = tmp_path / "config.yaml"
  config.write_text(
    f"""
mode: readwrite
postgres:
  dsn: {dsn}
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


def env_with_dsn(tmp_path: Path, dsn: str) -> dict[str, str]:
  env = os.environ.copy()
  env["SSL_PROXY_CONFIG"] = str(make_config_with_dsn(tmp_path, dsn))
  return env


def install_fake_psycopg(tmp_path: Path) -> Path:
  package_dir = tmp_path / "psycopg"
  package_dir.mkdir()
  (package_dir / "__init__.py").write_text(
    """
from __future__ import annotations

from datetime import UTC, datetime


class Error(Exception):
  pass


class FakeCursor:
  def __init__(self) -> None:
    self._row = None

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc, tb):
    return None

  def execute(self, query, params=None):
    if "FROM dns_zone_tokens" in query:
      self._row = {
        "zone_name": "example.com",
        "provider": "cloudflare",
        "zone_id": "zone-id",
        "updated_at": datetime(2026, 4, 2, tzinfo=UTC),
      }
      self._rows = [self._row]
    elif "FROM certificates c" in query and "NULL::text AS upstream_target" in query:
      self._rows = [
        {
          "domain": "api.example.com",
          "upstream_target": None,
          "enabled": True,
          "updated_at": datetime(2026, 4, 2, tzinfo=UTC),
          "certificate_status": "active",
          "certificate_not_after": datetime(2026, 7, 1, tzinfo=UTC),
          "retry_after": None,
          "last_error": None,
        }
      ]
      self._row = None
    elif "UPDATE routes" in query and "SET upstream_target = %s" in query:
      self._row = {
        "domain": params[1],
        "upstream_target": params[0],
        "enabled": True,
        "updated_at": datetime(2026, 4, 2, tzinfo=UTC),
        "certificate_status": None,
        "certificate_not_after": None,
        "retry_after": None,
        "last_error": None,
      }
    else:
      self._row = None
      self._rows = []

  def fetchone(self):
    return self._row

  def fetchall(self):
    return getattr(self, "_rows", [])


class FakeConnection:
  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc, tb):
    return None

  def cursor(self):
    return FakeCursor()

  def commit(self):
    return None


def connect(*args, **kwargs):
  return FakeConnection()
"""
  )
  (package_dir / "rows.py").write_text(
    """
dict_row = object()
"""
  )
  return tmp_path


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
  assert result.stderr == ""
  assert f"{SCRIPT.name} list" in result.stdout
  assert "list-zones" in result.stdout
  assert "issue-now <domain> [--force]" in result.stdout
  assert "check <domain>" in result.stdout
  assert "set-target <domain> <upstream_target>" in result.stdout


def test_help_uses_invoked_program_name(tmp_path: Path) -> None:
  alias_path = tmp_path / "domain-manage"
  shutil.copy2(SCRIPT, alias_path)

  env = base_env(tmp_path)
  result = subprocess.run(
    ["bash", str(alias_path), "help"],
    text=True,
    capture_output=True,
    env=env,
  )

  assert result.returncode == 0
  assert result.stderr == ""
  assert "domain-manage list" in result.stdout
  assert "domain-manage.sh list" not in result.stdout


def test_ssl_proxy_domain_help_proxies_to_domain_script(tmp_path: Path) -> None:
  setup_script = ROOT / "scripts" / "setup.sh"
  env = base_env(tmp_path)

  result = subprocess.run(
    ["bash", str(setup_script), "domain", "help"],
    text=True,
    capture_output=True,
    env=env,
  )

  assert result.returncode == 0
  assert result.stderr == ""
  assert "ssl-proxy domain list" in result.stdout
  assert "domain-manage.sh list" not in result.stdout
  assert "issue-now <domain> [--force]" in result.stdout


def test_no_args_without_tty_shows_usage_and_exits_nonzero(tmp_path: Path) -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT)],
    text=True,
    capture_output=True,
    env=base_env(tmp_path),
    stdin=subprocess.DEVNULL,
  )

  assert result.returncode != 0
  assert "Usage:" in result.stdout
  assert f"{SCRIPT.name} list" in result.stdout


def test_issue_now_rejects_on_readonly_node_before_dns_or_db(tmp_path: Path) -> None:
  result = run_script(["issue-now", "example.com"], env=env_with_mode(tmp_path, "readonly"))

  assert result.returncode != 0
  assert "only available on readwrite nodes" in result.stderr


def test_issue_now_accepts_mixed_case_readwrite_mode(tmp_path: Path) -> None:
  result = run_script(["issue-now", "invalid..example"], env=env_with_mode(tmp_path, "ReadWrite"))

  assert result.returncode != 0
  assert "only available on readwrite nodes" not in result.stderr
  assert "invalid domain label" in result.stderr


def test_get_reports_clean_database_error_without_traceback(tmp_path: Path) -> None:
  result = run_script(["get", "example.com"], env=env_with_dsn(tmp_path, "postgresql://invalid.invalid/postgres"))

  assert result.returncode != 0
  assert "database connection failed:" in result.stderr
  assert "Traceback" not in result.stderr


def test_check_reports_db_failure_without_traceback(tmp_path: Path) -> None:
  result = run_script(["check", "example.com"], env=env_with_dsn(tmp_path, "postgresql://invalid.invalid/postgres"))

  assert result.returncode != 0
  assert "check_db_lookup: fail database connection failed:" in result.stdout
  assert "Traceback" not in result.stderr


def test_status_reports_db_failure_without_traceback(tmp_path: Path) -> None:
  result = run_script(["status", "example.com"], env=env_with_dsn(tmp_path, "postgresql://invalid.invalid/postgres"))

  assert result.returncode != 0
  assert "database_lookup_ok: no" in result.stdout
  assert "database_error: database connection failed:" in result.stdout
  assert "Traceback" not in result.stderr


def test_list_certs_lists_certificate_rows_without_routes(tmp_path: Path) -> None:
  fake_site = install_fake_psycopg(tmp_path)
  env = base_env(tmp_path)
  env["PYTHONPATH"] = f"{fake_site}:{env.get('PYTHONPATH', '')}".rstrip(":")

  result = run_script(["list-certs"], env=env)

  assert result.returncode == 0
  assert result.stderr == ""
  assert "domain=api.example.com" in result.stdout
  assert "certificate_status=active" in result.stdout
  assert "upstream_target=" in result.stdout


def test_set_target_accepts_remote_ip_upstream(tmp_path: Path) -> None:
  fake_site = install_fake_psycopg(tmp_path)
  env = base_env(tmp_path)
  env["PYTHONPATH"] = f"{fake_site}:{env.get('PYTHONPATH', '')}".rstrip(":")

  result = run_script(["set-target", "api.example.com", "154.17.0.51:50101"], env=env)

  assert result.returncode == 0
  assert result.stderr == ""
  assert "domain=api.example.com" in result.stdout
  assert "upstream_target=154.17.0.51:50101" in result.stdout
