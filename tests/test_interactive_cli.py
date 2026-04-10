from __future__ import annotations

import os
from pathlib import Path

import pexpect


ROOT = Path(__file__).resolve().parents[1]
SETUP_SCRIPT = ROOT / "scripts" / "setup.sh"
DOMAIN_SCRIPT = ROOT / "scripts" / "domain-manage.sh"
TEST_VENV_BIN = Path("/tmp/ssl-proxy-test-venv/bin")


def base_env(tmp_path: Path) -> dict[str, str]:
  env = os.environ.copy()
  env["SSL_SERVICE_INSTALL_ROOT"] = str(tmp_path / ".ssl-service")
  env["SSL_SERVICE_BASHRC_PATH"] = str(tmp_path / ".bashrc")
  if TEST_VENV_BIN.exists():
    env["PATH"] = f"{TEST_VENV_BIN}:{env['PATH']}"
  return env


def write_config(tmp_path: Path) -> Path:
  config = tmp_path / "config.yaml"
  config.write_text(
    """
mode: readonly
postgres:
  dsn: postgresql://example
"""
  )
  return config


def install_fake_psycopg(tmp_path: Path) -> Path:
  package_dir = tmp_path / "psycopg"
  package_dir.mkdir()
  (package_dir / "__init__.py").write_text(
    """
from __future__ import annotations


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
    self._row = {
      "domain": (params or [""])[0],
      "upstream_target": "127.0.0.1:9901",
      "enabled": True,
      "updated_at": "2026-04-10T00:00:00+00:00",
      "certificate_status": "active",
      "certificate_not_after": "2026-07-01T00:00:00+00:00",
      "retry_after": None,
      "last_error": None,
    }

  def fetchone(self):
    return self._row

  def fetchall(self):
    return []


class FakeConnection:
  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc, tb):
    return None

  def cursor(self):
    return FakeCursor()


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


def setup_domain_env(tmp_path: Path) -> dict[str, str]:
  env = base_env(tmp_path)
  env["SSL_PROXY_CONFIG"] = str(write_config(tmp_path))
  fake_pythonpath = install_fake_psycopg(tmp_path)
  env["PYTHONPATH"] = f"{fake_pythonpath}:{env.get('PYTHONPATH', '')}".rstrip(":")
  return env


def move_to_exit(child: pexpect.spawn, count: int) -> None:
  for _ in range(count):
    child.send("\x1b[B")
  child.send("\r")


def test_setup_menu_renders_and_exit_can_be_selected_in_tty(tmp_path: Path) -> None:
  child = pexpect.spawn(
    "/bin/bash",
    [str(SETUP_SCRIPT)],
    env=base_env(tmp_path),
    encoding="utf-8",
    timeout=10,
  )
  try:
    child.expect("ssl-service control")
    child.expect("Install or overwrite runtime")
    child.expect("Exit")
    for _ in range(8):
      child.send("\x1b[B")
    child.send("\r")
    child.expect(pexpect.EOF)
  finally:
    child.close()
  assert child.exitstatus == 0


def test_setup_status_screen_returns_to_menu_then_exit(tmp_path: Path) -> None:
  child = pexpect.spawn(
    "/bin/bash",
    [str(SETUP_SCRIPT)],
    env=base_env(tmp_path),
    encoding="utf-8",
    timeout=10,
  )
  try:
    child.expect("ssl-service control")
    child.expect("Show service status")
    child.send("\x1b[B")
    child.send("\x1b[B")
    child.send("\r")
    child.expect("docker_version:")
    child.expect("Press Enter to return to the menu")
    child.send("\r")
    child.expect("ssl-service control")
    child.send("\r")
    child.expect(pexpect.EOF)
  finally:
    child.close()
  assert child.exitstatus == 0


def test_setup_uninstall_confirmation_can_cancel_and_return_to_menu(tmp_path: Path) -> None:
  child = pexpect.spawn(
    "/bin/bash",
    [str(SETUP_SCRIPT)],
    env=base_env(tmp_path),
    encoding="utf-8",
    timeout=10,
  )
  try:
    child.expect("ssl-service control")
    child.expect("Uninstall runtime")
    for _ in range(7):
      child.send("\x1b[B")
    child.send("\r")
    child.expect("Proceed with uninstall\\?")
    child.expect("Yes")
    child.expect("No")
    child.send("\r")
    child.expect("Press Enter to return to the menu")
    child.send("\r")
    child.expect("ssl-service control")
    child.send("\r")
    child.expect(pexpect.EOF)
  finally:
    child.close()
  assert child.exitstatus == 0


def test_domain_menu_renders_and_exit_can_be_selected_in_tty(tmp_path: Path) -> None:
  env = setup_domain_env(tmp_path)
  child = pexpect.spawn(
    "/bin/bash",
    [str(DOMAIN_SCRIPT)],
    env=env,
    encoding="utf-8",
    timeout=10,
  )
  try:
    child.expect("ssl-service domain manager")
    child.expect("Node overview")
    child.expect("Exit")
    for _ in range(20):
      child.send("\x1b[B")
    child.send("\r")
    child.expect(pexpect.EOF)
  finally:
    child.close()
  assert child.exitstatus == 0


def test_domain_overview_returns_to_menu_then_exit(tmp_path: Path) -> None:
  child = pexpect.spawn(
    "/bin/bash",
    [str(DOMAIN_SCRIPT)],
    env=setup_domain_env(tmp_path),
    encoding="utf-8",
    timeout=10,
  )
  try:
    child.expect("ssl-service domain manager")
    child.expect("Node overview")
    child.send("\r")
    child.expect("container_status:")
    child.expect("Press Enter to continue")
    child.send("\r")
    child.expect("ssl-service domain manager")
    move_to_exit(child, count=20)
    child.expect(pexpect.EOF)
  finally:
    child.close()
  assert child.exitstatus == 0


def test_domain_add_prompt_can_cancel_and_return_to_menu(tmp_path: Path) -> None:
  child = pexpect.spawn(
    "/bin/bash",
    [str(DOMAIN_SCRIPT)],
    env=setup_domain_env(tmp_path),
    encoding="utf-8",
    timeout=10,
  )
  try:
    child.expect("ssl-service domain manager")
    child.expect("Add a domain")
    for _ in range(8):
      child.send("\x1b[B")
    child.send("\r")
    child.expect("New domain:")
    child.send("\r")
    child.expect("cancelled")
    child.expect("Press Enter to continue")
    child.send("\r")
    child.expect("ssl-service domain manager")
    move_to_exit(child, count=20)
    child.expect(pexpect.EOF)
  finally:
    child.close()
  assert child.exitstatus == 0


def test_domain_clear_target_confirmation_can_cancel_and_return_to_menu(tmp_path: Path) -> None:
  child = pexpect.spawn(
    "/bin/bash",
    [str(DOMAIN_SCRIPT)],
    env=setup_domain_env(tmp_path),
    encoding="utf-8",
    timeout=10,
  )
  try:
    child.expect("ssl-service domain manager")
    child.expect("Clear upstream target")
    for _ in range(10):
      child.send("\x1b[B")
    child.send("\r")
    child.expect("Domain:")
    child.send("example.com\r")
    child.expect("Clear upstream target for example.com\\?")
    child.expect("Yes")
    child.expect("No")
    child.send("\r")
    child.expect("cancelled")
    child.expect("Press Enter to continue")
    child.send("\r")
    child.expect("ssl-service domain manager")
    move_to_exit(child, count=20)
    child.expect(pexpect.EOF)
  finally:
    child.close()
  assert child.exitstatus == 0


def test_domain_delete_exact_confirmation_can_cancel_and_return_to_menu(tmp_path: Path) -> None:
  child = pexpect.spawn(
    "/bin/bash",
    [str(DOMAIN_SCRIPT)],
    env=setup_domain_env(tmp_path),
    encoding="utf-8",
    timeout=10,
  )
  try:
    child.expect("ssl-service domain manager")
    child.expect("Delete route")
    for _ in range(13):
      child.send("\x1b[B")
    child.send("\r")
    child.expect("Domain:")
    child.send("example.com\r")
    child.expect("Confirm destructive action for example.com")
    child.send("\r")
    child.expect("cancelled")
    child.expect("Press Enter to continue")
    child.send("\r")
    child.expect("ssl-service domain manager")
    move_to_exit(child, count=20)
    child.expect(pexpect.EOF)
  finally:
    child.close()
  assert child.exitstatus == 0


def test_domain_set_zone_token_blank_input_returns_to_menu(tmp_path: Path) -> None:
  child = pexpect.spawn(
    "/bin/bash",
    [str(DOMAIN_SCRIPT)],
    env=setup_domain_env(tmp_path),
    encoding="utf-8",
    timeout=10,
  )
  try:
    child.expect("ssl-service domain manager")
    child.expect("Set Cloudflare zone token")
    for _ in range(16):
      child.send("\x1b[B")
    child.send("\r")
    child.expect("Domain or zone:")
    child.send("example.com\r")
    child.expect("Cloudflare API token for zone managing example.com:")
    child.send("\r")
    child.expect("token is required")
    child.expect("Press Enter to continue")
    child.send("\r")
    child.expect("ssl-service domain manager")
    move_to_exit(child, count=20)
    child.expect(pexpect.EOF)
  finally:
    child.close()
  assert child.exitstatus == 0
