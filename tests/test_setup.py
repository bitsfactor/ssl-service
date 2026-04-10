from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path("/root/ssl-server")
SCRIPT = ROOT / "scripts" / "setup.sh"
INSTALL_SCRIPT = ROOT / "scripts" / "install.sh"


def test_no_args_without_tty_shows_usage_and_exits_nonzero() -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT)],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
  )

  assert result.returncode != 0
  assert "Usage:" in result.stdout
  assert "setup.sh install" in result.stdout


def test_help_lists_domain_subcommand() -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT), "help"],
    text=True,
    capture_output=True,
    check=False,
  )

  assert result.returncode == 0
  assert "setup.sh domain <domain-command> [args...]" in result.stdout


def test_install_sh_requires_tty_when_no_flags() -> None:
  result = subprocess.run(
    ["bash", str(INSTALL_SCRIPT)],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
  )

  assert result.returncode != 0
  assert "interactive bootstrap requires a TTY" in result.stderr


def test_install_requires_mode_without_tty_when_config_missing() -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT), "install", "--force-reconfigure", "--dsn", "postgresql://example"],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
  )

  assert result.returncode != 0
  assert "--mode is required when install runs without a TTY" in result.stderr


def test_install_requires_acme_email_for_readwrite_without_tty() -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT), "install", "--force-reconfigure", "--mode", "readwrite", "--dsn", "postgresql://example"],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
  )

  assert result.returncode != 0
  assert "--acme-email is required for readwrite install without a TTY" in result.stderr


def test_install_rejects_new_parameters_without_force_when_config_exists() -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT), "install", "--mode", "readonly", "--dsn", "postgresql://example"],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
  )

  assert result.returncode != 0
  assert "existing config detected; use --force-reconfigure" in result.stderr
