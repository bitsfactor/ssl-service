from __future__ import annotations

import json
import subprocess
from pathlib import Path
import os


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup.sh"
INSTALL_SCRIPT = ROOT / "scripts" / "install.sh"
DEV_SCRIPT = ROOT / "scripts" / "setup-dev.sh"
PYPROJECT = ROOT / "pyproject.toml"


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
  assert "setup.sh build-status" in result.stdout
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


def test_uninstall_requires_tty_or_yes_without_tty(tmp_path: Path) -> None:
  result = subprocess.run(
    ["bash", str(SCRIPT), "uninstall"],
    text=True,
    capture_output=True,
    stdin=subprocess.DEVNULL,
    env=base_env(tmp_path),
  )

  assert result.returncode != 0
  assert "uninstall requires a TTY or --yes" in result.stderr


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


def test_setup_dev_bootstrap_installs_test_extras() -> None:
  content = DEV_SCRIPT.read_text()

  assert 'install -e "${REPO_DIR}[test]"' in content


def test_project_metadata_uses_ssl_service_name() -> None:
  content = PYPROJECT.read_text()

  assert 'name = "ssl-service"' in content


def test_build_status_command_reads_latest_workflow_run_from_api(tmp_path: Path) -> None:
  payload = {
    "workflow_runs": [
      {
        "name": "Publish Image",
        "run_number": 42,
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": "abc123",
        "created_at": "2026-04-10T12:00:00Z",
        "updated_at": "2026-04-10T12:05:00Z",
        "html_url": "https://github.com/test/ssl-service/actions/runs/42",
      }
    ]
  }
  payload_path = tmp_path / "workflow-runs.json"
  payload_path.write_text(json.dumps(payload))

  env = base_env(tmp_path)
  env["SSL_SERVICE_GITHUB_WORKFLOW_RUNS_URL"] = payload_path.resolve().as_uri()
  result = subprocess.run(
    ["bash", str(SCRIPT), "build-status"],
    text=True,
    capture_output=True,
    check=False,
    env=env,
  )

  assert result.returncode == 0
  assert "workflow: Publish Image" in result.stdout
  assert "run_number: 42" in result.stdout
  assert "status: completed" in result.stdout
  assert "conclusion: success" in result.stdout
  assert "branch: main" in result.stdout
  assert "sha: abc123" in result.stdout
  assert "actions/runs/42" in result.stdout


def test_update_stops_and_cleans_legacy_runtime() -> None:
  content = SCRIPT.read_text()

  update_block = content.split("update_command() {", 1)[1].split("\n}\n\nuninstall_command()", 1)[0]
  assert "stop_legacy_runtime" in update_block
  assert "remove_legacy_runtime" in update_block
  assert 'rm -f /etc/profile.d/ssl-proxy-shell.sh' in content
  assert 'for legacy_unit in caddy.service ssl-proxy-controller.service ssl-proxy-update.timer; do' in content
  assert 'for legacy_unit in caddy.service ssl-proxy-controller.service ssl-proxy-update.service ssl-proxy-update.timer; do' in content


def test_runtime_control_commands_require_root() -> None:
  content = SCRIPT.read_text()

  for function_name in ("stop_runtime", "start_runtime", "restart_runtime"):
    block = content.split(f"{function_name}() {{", 1)[1].split("\n}\n\n", 1)[0]
    assert "require_root" in block


def test_interactive_menu_resets_default_selection_to_exit_after_actions() -> None:
  content = SCRIPT.read_text()

  menu_block = content.split("interactive_menu() {", 1)[1].split("\n}\n\nmain()", 1)[0]
  assert 'default_index="${exit_index}"' in menu_block
  assert 'Press Enter to return to the menu' in content
  assert '"Show image build status"' in content


def test_external_setup_without_source_tree_can_auto_update_existing_runtime() -> None:
  content = SCRIPT.read_text()

  assert 'should_auto_update_from_external_setup' in content
  assert 'Existing installation detected. Updating runtime from this setup.sh.' in content


def test_interactive_input_uses_dev_tty_and_safe_clear() -> None:
  content = SCRIPT.read_text()

  assert "[[ -t 2 ]] || return 1" in content
  assert "[[ -t 2 && -r /dev/tty ]]" in content
  assert "read -rsn1 key < /dev/tty" in content
  assert "printf '\\033[H\\033[2J' > /dev/tty" in content


def test_uninstall_requires_tty_or_yes_without_prompting_on_dev_tty() -> None:
  content = SCRIPT.read_text()

  uninstall_block = content.split("uninstall_command() {", 1)[1].split("\n}\n\ndomain_command()", 1)[0]
  assert 'ui_has_tty || fail "uninstall requires a TTY or --yes"' in uninstall_block
