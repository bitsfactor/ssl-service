from __future__ import annotations

from pathlib import Path

import pytest

from ssl_proxy_controller.config import as_dict, load_config


def test_load_config_reads_retry_backoff_and_paths(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readwrite
postgres:
  dsn: postgresql://example
sync:
  poll_interval_seconds: 5
  renew_before_days: 10
  retry_backoff_seconds: 7200
  loop_error_backoff_seconds: 3
paths:
  state_dir: /tmp/state
  log_dir: /tmp/log
caddy:
  admin_url: http://127.0.0.1:2019
  reload_command: ["/usr/bin/caddy", "reload"]
acme:
  email: ops@example.com
  staging: true
  challenge_type: dns-01
  dns_provider: cloudflare
  dns_propagation_seconds: 45
logging:
  level: DEBUG
"""
  )

  config = load_config(config_path)

  assert config.mode == "readwrite"
  assert config.postgres.dsn == "postgresql://example"
  assert config.sync.poll_interval_seconds == 5
  assert config.sync.renew_before_days == 10
  assert config.sync.retry_backoff_seconds == 7200
  assert config.sync.loop_error_backoff_seconds == 3
  assert config.paths.state_dir == Path("/tmp/state")
  assert config.paths.log_dir == Path("/tmp/log")
  assert config.caddy.reload_command == ["/usr/bin/caddy", "reload"]
  assert config.acme.email == "ops@example.com"
  assert config.acme.staging is True
  assert config.acme.challenge_type == "dns-01"
  assert config.acme.dns_provider == "cloudflare"
  assert config.acme.dns_propagation_seconds == 45
  assert config.logging.level == "DEBUG"
  assert config.logging.controller_log_path == "/app/logs/controller.log"
  assert config.logging.controller_log_max_bytes == 5 * 1024 * 1024
  assert config.logging.controller_log_backup_count == 8
  assert config.logging.caddy_log_path == "/app/logs/caddy.log"
  assert config.logging.caddy_log_roll_size_mb == 5
  assert config.logging.caddy_log_roll_keep == 8


def test_load_config_uses_defaults_for_sync_values(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readonly
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
"""
  )

  config = load_config(config_path)

  assert config.mode == "readonly"
  assert config.sync.poll_interval_seconds == 30
  assert config.sync.renew_before_days == 30
  assert config.sync.retry_backoff_seconds == 3600
  assert config.sync.loop_error_backoff_seconds == 10


def test_load_config_rejects_invalid_mode(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: invalid
postgres:
  dsn: postgresql://example
"""
  )

  with pytest.raises(ValueError, match="unsupported mode"):
    load_config(config_path)


def test_as_dict_serializes_paths(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readwrite
postgres:
  dsn: postgresql://example
paths:
  state_dir: /tmp/state
  log_dir: /tmp/log
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
acme:
  email: ops@example.com
  dns_propagation_seconds: 30
"""
  )

  config = load_config(config_path)
  payload = as_dict(config)

  assert payload["mode"] == "readwrite"
  assert payload["postgres"]["dsn"] == "postgresql://example"
  assert payload["paths"]["state_dir"] == "/tmp/state"
  assert payload["acme"]["challenge_type"] == "dns-01"
  assert payload["acme"]["dns_provider"] == "cloudflare"
  assert payload["acme"]["dns_propagation_seconds"] == 30
  assert payload["logging"]["controller_log_path"] == "/app/logs/controller.log"
  assert payload["logging"]["controller_log_max_bytes"] == 5 * 1024 * 1024
  assert payload["logging"]["controller_log_backup_count"] == 8
  assert payload["logging"]["caddy_log_path"] == "/app/logs/caddy.log"
  assert payload["logging"]["caddy_log_roll_size_mb"] == 5
  assert payload["logging"]["caddy_log_roll_keep"] == 8


def test_load_config_parses_string_boolean_for_staging(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readwrite
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
acme:
  email: ops@example.com
  staging: "false"
"""
  )

  config = load_config(config_path)

  assert config.acme.staging is False


@pytest.mark.parametrize(
  ("sync_block", "message"),
  [
    ("poll_interval_seconds: 0", r"sync\.poll_interval_seconds must be >= 1"),
    ("renew_before_days: -1", r"sync\.renew_before_days must be >= 0"),
    ("retry_backoff_seconds: -1", r"sync\.retry_backoff_seconds must be >= 0"),
    ("loop_error_backoff_seconds: 0", r"sync\.loop_error_backoff_seconds must be >= 1"),
  ],
)
def test_load_config_rejects_invalid_sync_intervals(tmp_path: Path, sync_block: str, message: str) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    f"""
mode: readwrite
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
acme:
  email: ops@example.com
sync:
  {sync_block}
"""
  )

  with pytest.raises(ValueError, match=message):
    load_config(config_path)


def test_load_config_rejects_invalid_acme_dns_config(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readwrite
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
acme:
  email: ops@example.com
  challenge_type: http-01
"""
  )

  with pytest.raises(ValueError, match=r"acme\.challenge_type must be dns-01"):
    load_config(config_path)


def test_load_config_rejects_non_integer_sync_values(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readwrite
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
acme:
  email: ops@example.com
sync:
  poll_interval_seconds: "30"
"""
  )

  with pytest.raises(ValueError, match=r"sync\.poll_interval_seconds must be an integer"):
    load_config(config_path)


@pytest.mark.parametrize(
  ("logging_block", "message"),
  [
    ('controller_log_max_bytes: "5"', r"logging\.controller_log_max_bytes must be an integer"),
    ("controller_log_backup_count: -1", r"logging\.controller_log_backup_count must be >= 0"),
    ("caddy_log_roll_size_mb: 0", r"logging\.caddy_log_roll_size_mb must be >= 1"),
    ("caddy_log_roll_keep: -1", r"logging\.caddy_log_roll_keep must be >= 0"),
  ],
)
def test_load_config_rejects_invalid_logging_rotation_values(tmp_path: Path, logging_block: str, message: str) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    f"""
mode: readwrite
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
acme:
  email: ops@example.com
logging:
  {logging_block}
"""
  )

  with pytest.raises(ValueError, match=message):
    load_config(config_path)


def test_load_config_requires_reload_command(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readonly
postgres:
  dsn: postgresql://example
"""
  )

  with pytest.raises(ValueError, match=r"caddy\.reload_command must not be empty"):
    load_config(config_path)


def test_load_config_requires_acme_email_in_readwrite_mode(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readwrite
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
"""
  )

  with pytest.raises(ValueError, match=r"acme\.email is required in readwrite mode"):
    load_config(config_path)


def test_load_config_parses_admin_section(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readonly
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
admin:
  enabled: true
  bind: 0.0.0.0
  port: 8080
  token: secret-token
"""
  )

  config = load_config(config_path)

  assert config.admin.enabled is True
  assert config.admin.bind == "0.0.0.0"
  assert config.admin.port == 8080
  assert config.admin.token == "secret-token"


def test_load_config_admin_defaults_off(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readonly
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
"""
  )

  config = load_config(config_path)

  assert config.admin.enabled is False
  assert config.admin.bind == "127.0.0.1"
  assert config.admin.port == 8088
  assert config.admin.token == ""


def test_load_config_admin_requires_token_when_enabled(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readonly
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
admin:
  enabled: true
  port: 8088
"""
  )

  with pytest.raises(ValueError, match=r"admin\.token is required"):
    load_config(config_path)


def test_load_config_admin_rejects_invalid_port(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readonly
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
admin:
  enabled: true
  port: 70000
  token: t
"""
  )

  with pytest.raises(ValueError, match=r"admin\.port must be <= 65535"):
    load_config(config_path)


def test_as_dict_masks_admin_token(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readonly
postgres:
  dsn: postgresql://example
caddy:
  reload_command: ["/usr/bin/caddy", "reload"]
admin:
  enabled: true
  token: super-secret
"""
  )

  payload = as_dict(load_config(config_path))

  assert payload["admin"]["enabled"] is True
  assert payload["admin"]["token"] == "***"
