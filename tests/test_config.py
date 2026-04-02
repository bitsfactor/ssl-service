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
  webroot: /tmp/acme
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
  assert config.acme.webroot == Path("/tmp/acme")
  assert config.logging.level == "DEBUG"


def test_load_config_uses_defaults_for_sync_values(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readonly
postgres:
  dsn: postgresql://example
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
acme:
  email: ops@example.com
  webroot: /tmp/acme
"""
  )

  config = load_config(config_path)
  payload = as_dict(config)

  assert payload["mode"] == "readwrite"
  assert payload["postgres"]["dsn"] == "postgresql://example"
  assert payload["paths"]["state_dir"] == "/tmp/state"
  assert payload["acme"]["webroot"] == "/tmp/acme"


def test_load_config_parses_string_boolean_for_staging(tmp_path: Path) -> None:
  config_path = tmp_path / "config.yaml"
  config_path.write_text(
    """
mode: readwrite
postgres:
  dsn: postgresql://example
acme:
  staging: "false"
"""
  )

  config = load_config(config_path)

  assert config.acme.staging is False
