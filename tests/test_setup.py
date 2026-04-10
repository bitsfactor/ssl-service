from __future__ import annotations

import subprocess
from pathlib import Path
import os


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup.sh"
INSTALL_SCRIPT = ROOT / "scripts" / "install.sh"
DEV_SCRIPT = ROOT / "scripts" / "setup-dev.sh"


def base_env(tmp_path: Path) -> dict[str, str]:
  env = os.environ.copy()
  env["SSL_SERVICE_INSTALL_ROOT"] = str(tmp_path / ".ssl-service")
  env["SSL_SERVICE_BASHRC_PATH"] = str(tmp_path / ".bashrc")
  return env


def test_no_args_without_tty_shows_usage_and_exits_nonzero(tmp_path: Path) -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT)],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
    env=base_env(tmp_path),
  )

  assert result.returncode != 0
  assert "Usage:" in result.stdout
  assert "setup.sh install" in result.stdout


def test_help_lists_domain_and_reconfigure_subcommands(tmp_path: Path) -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT), "help"],
    text=True,
    capture_output=True,
    check=False,
    env=base_env(tmp_path),
  )

  assert result.returncode == 0
  assert "setup.sh reconfigure" in result.stdout
  assert "setup.sh domain <domain-command> [args...]" in result.stdout
  assert ".ssl-service" in result.stdout


def test_install_sh_requires_tty_when_no_flags(tmp_path: Path) -> None:
  result = subprocess.run(
    ["bash", str(INSTALL_SCRIPT)],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
    env=base_env(tmp_path),
  )

  assert result.returncode != 0
  assert "interactive bootstrap requires a TTY" in result.stderr


def test_install_sh_uses_github_download_url() -> None:
  content = INSTALL_SCRIPT.read_text()

  assert "https://github.com/bitsfactor/ssl-service/raw/" in content
  assert "raw.githubusercontent.com" not in content


def test_install_requires_mode_without_tty_when_config_missing(tmp_path: Path) -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT), "install", "--force-reconfigure", "--dsn", "postgresql://example"],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
    env=base_env(tmp_path),
  )

  assert result.returncode != 0
  assert "--mode is required when install runs without a TTY" in result.stderr


def test_install_requires_acme_email_for_readwrite_without_tty(tmp_path: Path) -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT), "install", "--force-reconfigure", "--mode", "readwrite", "--dsn", "postgresql://example"],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
    env=base_env(tmp_path),
  )

  assert result.returncode != 0
  assert "--acme-email is required for readwrite install without a TTY" in result.stderr


def test_setup_dev_help_mentions_bootstrap(tmp_path: Path) -> None:
  result = subprocess.run(
    ["bash", str(DEV_SCRIPT), "help"],
    text=True,
    capture_output=True,
    check=False,
    env=base_env(tmp_path),
  )

  assert result.returncode == 0
  assert "setup-dev.sh bootstrap" in result.stdout
  assert "source tree" in result.stdout


def test_update_stops_and_cleans_legacy_runtime() -> None:
  content = SCRIPT.read_text()

  update_block = content.split("update_command() {", 1)[1].split("\n}\n\nuninstall_command()", 1)[0]
  assert "stop_legacy_runtime" in update_block
  assert "remove_legacy_runtime" in update_block


def test_runtime_control_commands_require_root() -> None:
  content = SCRIPT.read_text()

  for function_name in ("stop_runtime", "start_runtime", "restart_runtime"):
    block = content.split(f"{function_name}() {{", 1)[1].split("\n}\n\n", 1)[0]
    assert "require_root" in block
