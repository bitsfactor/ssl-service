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
  env["SSL_SERVICE_GLOBAL_COMMAND_PATH"] = str(tmp_path / "ssl-service")
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
  assert str(tmp_path / "ssl-service") in result.stdout
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

  assert 'REPO_URL="${SSL_SERVICE_REPO_URL:-https://github.com/bitsfactor/ssl-service.git}"' in content
  assert 'normalize_repo_url() {' in content
  assert 'git clone --depth 1 --branch "${INSTALL_REF}" "${REPO_URL}" "${SOURCE_ROOT}"' in content
  assert 'git -C "${SOURCE_ROOT}" fetch --depth 1 origin "${INSTALL_REF}"' in content
  assert 'Existing checkout at ${SOURCE_ROOT} has local changes; skipping git update and using current checkout' in content
  assert 'git@github.com:' in content


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
  assert 'cryptography>=42.0.0,<47.0.0' in content


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
  assert '"Manage domains and routes"' in content
  assert '"Show image build status"' in content


def test_install_symlinks_global_ssl_service_to_source_tree_and_cleans_old_aliases() -> None:
  content = SCRIPT.read_text()

  assert 'GLOBAL_COMMAND_PATH="${SSL_SERVICE_GLOBAL_COMMAND_PATH:-/usr/local/bin/ssl-service}"' in content
  assert 'ln -sfn "${SOURCE_SETUP_PATH}" "${GLOBAL_COMMAND_PATH}"' in content
  assert 'rm -f "${INSTALL_ROOT}/bin/ssl-service" "${INSTALL_ROOT}/bin/setup.sh" "${INSTALL_ROOT}/bin/domain-manage.sh"' in content
  assert 'remove_shell_alias' in content
  assert 'log "command: ${GLOBAL_COMMAND_PATH}"' in content


def test_external_setup_without_source_tree_can_auto_update_existing_runtime() -> None:
  content = SCRIPT.read_text()

  assert 'should_auto_update_from_external_setup' in content
  assert 'Existing installation detected. Updating runtime from this setup.sh.' in content
  assert 'handoff_to_source_setup_for_update() {' in content
  assert 'exec bash "${source_setup}" update' in content


def test_interactive_input_uses_dev_tty_and_safe_clear() -> None:
  content = SCRIPT.read_text()

  assert "[[ -t 2 ]] || return 1" in content
  assert "[[ -t 2 && -r /dev/tty ]]" in content
  assert "read -rsn1 key < /dev/tty" in content
  assert "printf '\\033[H\\033[2J' > /dev/tty" in content
  assert "ui_cursor_save() {" in content
  assert "ui_cursor_restore() {" in content
  assert "ui_clear_to_end() {" in content


def test_apt_install_writes_package_manager_output_to_stderr() -> None:
  content = SCRIPT.read_text()

  apt_block = content.split("apt_install() {", 1)[1].split("\n}\n\nensure_curl()", 1)[0]
  assert "apt-get update >&2" in apt_block
  assert 'apt-get install -y "$@" >&2' in apt_block


def test_publish_workflow_only_triggers_for_image_inputs() -> None:
  content = (ROOT / ".github" / "workflows" / "publish-image.yml").read_text()

  assert '"Dockerfile"' in content
  assert '".dockerignore"' in content
  assert '"pyproject.toml"' in content
  assert '"src/**"' in content
  assert '"scripts/container-entrypoint.sh"' in content
  assert '"scripts/domain-manage.sh"' in content


def test_compose_maps_host_docker_internal_for_host_backends() -> None:
  content = SCRIPT.read_text()

  render_compose_block = content.split("render_compose() {", 1)[1].split("\n}\n\nwrite_install_meta()", 1)[0]
  assert 'extra_hosts:' in render_compose_block
  assert '"host.docker.internal:host-gateway"' in render_compose_block
  assert 'logging:' in render_compose_block
  assert 'driver: json-file' in render_compose_block
  assert 'max-size: "5m"' in render_compose_block
  assert 'max-file: "2"' in render_compose_block


def test_render_config_sets_default_app_log_rotation_limits() -> None:
  content = SCRIPT.read_text()

  render_config_block = content.split("render_config() {", 1)[1].split("\n}\n\nrender_compose()", 1)[0]
  assert "controller_log_path: /app/logs/controller.log" in render_config_block
  assert "controller_log_max_bytes: 5242880" in render_config_block
  assert "controller_log_backup_count: 8" in render_config_block
  assert "caddy_log_path: /app/logs/caddy.log" in render_config_block
  assert "caddy_log_roll_size_mb: 5" in render_config_block
  assert "caddy_log_roll_keep: 8" in render_config_block


def test_uninstall_requires_tty_or_yes_without_prompting_on_dev_tty() -> None:
  content = SCRIPT.read_text()

  uninstall_block = content.split("uninstall_command() {", 1)[1].split("\n}\n\ndomain_command()", 1)[0]
  assert 'ui_has_tty || fail "uninstall requires a TTY or --yes"' in uninstall_block
