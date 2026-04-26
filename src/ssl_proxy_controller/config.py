from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class PostgresConfig:
  dsn: str


@dataclass(slots=True)
class SyncConfig:
  poll_interval_seconds: int = 30
  renew_before_days: int = 30
  retry_backoff_seconds: int = 3600
  loop_error_backoff_seconds: int = 10


@dataclass(slots=True)
class PathsConfig:
  state_dir: Path
  log_dir: Path
  caddy_binary: str = "/usr/bin/caddy"
  certbot_binary: str = "/usr/bin/certbot"


@dataclass(slots=True)
class CaddyConfig:
  admin_url: str = "http://127.0.0.1:2019"
  reload_command: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AcmeConfig:
  email: str = ""
  staging: bool = False
  challenge_type: str = "dns-01"
  dns_provider: str = "cloudflare"
  dns_propagation_seconds: int = 30
  certbot_args: list[str] = field(default_factory=list)


@dataclass(slots=True)
class LoggingConfig:
  level: str = "INFO"
  controller_log_path: str = "/app/logs/controller.log"
  controller_log_max_bytes: int = 5 * 1024 * 1024
  controller_log_backup_count: int = 8
  caddy_log_path: str = "/app/logs/caddy.log"
  caddy_log_roll_size_mb: int = 5
  caddy_log_roll_keep: int = 8


@dataclass(slots=True)
class AdminConfig:
  enabled: bool = False
  bind: str = "127.0.0.1"
  port: int = 8088
  token: str = ""


@dataclass(slots=True)
class AppConfig:
  mode: str
  postgres: PostgresConfig
  sync: SyncConfig
  paths: PathsConfig
  caddy: CaddyConfig
  acme: AcmeConfig
  logging: LoggingConfig
  admin: AdminConfig = field(default_factory=AdminConfig)


def _normalize_mode(mode: str) -> str:
  normalized = mode.strip().lower()
  if normalized not in {"readonly", "readwrite"}:
    raise ValueError(f"unsupported mode: {mode}")
  return normalized


def _normalize_bool(value: object) -> bool:
  if isinstance(value, bool):
    return value
  if isinstance(value, str):
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes", "on"}:
      return True
    if normalized in {"false", "0", "no", "off", ""}:
      return False
  return bool(value)


def _require_int(name: str, value: int, *, minimum: int) -> int:
  if isinstance(value, bool) or not isinstance(value, int):
    raise ValueError(f"{name} must be an integer")
  if value < minimum:
    raise ValueError(f"{name} must be >= {minimum}")
  return value


def _normalize_challenge_type(value: object) -> str:
  normalized = str(value or "dns-01").strip().lower()
  if normalized != "dns-01":
    raise ValueError("acme.challenge_type must be dns-01")
  return normalized


def _normalize_dns_provider(value: object) -> str:
  normalized = str(value or "cloudflare").strip().lower()
  if normalized != "cloudflare":
    raise ValueError("acme.dns_provider must be cloudflare")
  return normalized


def load_config(path: str | Path) -> AppConfig:
  config_path = Path(path)
  data = yaml.safe_load(config_path.read_text()) or {}

  paths = data.get("paths", {})
  caddy = data.get("caddy", {})
  acme = data.get("acme", {})

  config = AppConfig(
    mode=_normalize_mode(data["mode"]),
    postgres=PostgresConfig(**data["postgres"]),
    sync=SyncConfig(**data.get("sync", {})),
    paths=PathsConfig(
      state_dir=Path(paths.get("state_dir", "/app/state")),
      log_dir=Path(paths.get("log_dir", "/app/logs")),
      caddy_binary=paths.get("caddy_binary", "/usr/bin/caddy"),
      certbot_binary=paths.get("certbot_binary", "/usr/local/bin/certbot"),
    ),
    caddy=CaddyConfig(
      admin_url=caddy.get("admin_url", "http://127.0.0.1:2019"),
      reload_command=list(caddy.get("reload_command", [])),
    ),
    acme=AcmeConfig(
      email=acme.get("email", ""),
      staging=_normalize_bool(acme.get("staging", False)),
      challenge_type=_normalize_challenge_type(acme.get("challenge_type", "dns-01")),
      dns_provider=_normalize_dns_provider(acme.get("dns_provider", "cloudflare")),
      dns_propagation_seconds=acme.get("dns_propagation_seconds", 30),
      certbot_args=list(acme.get("certbot_args", [])),
    ),
    logging=LoggingConfig(**data.get("logging", {})),
    admin=AdminConfig(**{
      "enabled": _normalize_bool(data.get("admin", {}).get("enabled", False)),
      "bind": str(data.get("admin", {}).get("bind", "127.0.0.1")),
      "port": int(data.get("admin", {}).get("port", 8088)),
      "token": str(data.get("admin", {}).get("token", "") or ""),
    }),
  )
  config.sync.poll_interval_seconds = _require_int("sync.poll_interval_seconds", config.sync.poll_interval_seconds, minimum=1)
  config.sync.renew_before_days = _require_int("sync.renew_before_days", config.sync.renew_before_days, minimum=0)
  config.sync.retry_backoff_seconds = _require_int("sync.retry_backoff_seconds", config.sync.retry_backoff_seconds, minimum=0)
  config.sync.loop_error_backoff_seconds = _require_int("sync.loop_error_backoff_seconds", config.sync.loop_error_backoff_seconds, minimum=1)
  config.acme.dns_propagation_seconds = _require_int(
    "acme.dns_propagation_seconds",
    config.acme.dns_propagation_seconds,
    minimum=0,
  )
  config.logging.controller_log_max_bytes = _require_int(
    "logging.controller_log_max_bytes",
    config.logging.controller_log_max_bytes,
    minimum=1,
  )
  config.logging.controller_log_backup_count = _require_int(
    "logging.controller_log_backup_count",
    config.logging.controller_log_backup_count,
    minimum=0,
  )
  config.logging.caddy_log_roll_size_mb = _require_int(
    "logging.caddy_log_roll_size_mb",
    config.logging.caddy_log_roll_size_mb,
    minimum=1,
  )
  config.logging.caddy_log_roll_keep = _require_int(
    "logging.caddy_log_roll_keep",
    config.logging.caddy_log_roll_keep,
    minimum=0,
  )
  if not config.caddy.reload_command:
    raise ValueError("caddy.reload_command must not be empty")
  if config.mode == "readwrite" and not config.acme.email.strip():
    raise ValueError("acme.email is required in readwrite mode")
  config.admin.port = _require_int("admin.port", config.admin.port, minimum=1)
  if config.admin.port > 65535:
    raise ValueError("admin.port must be <= 65535")
  if config.admin.enabled and not config.admin.token.strip():
    raise ValueError("admin.token is required when admin.enabled is true")
  return config


def as_dict(config: AppConfig) -> dict[str, Any]:
  return {
    "mode": config.mode,
    "postgres": {"dsn": config.postgres.dsn},
    "sync": {
      "poll_interval_seconds": config.sync.poll_interval_seconds,
      "renew_before_days": config.sync.renew_before_days,
      "retry_backoff_seconds": config.sync.retry_backoff_seconds,
      "loop_error_backoff_seconds": config.sync.loop_error_backoff_seconds,
    },
    "paths": {
      "state_dir": str(config.paths.state_dir),
      "log_dir": str(config.paths.log_dir),
      "caddy_binary": config.paths.caddy_binary,
      "certbot_binary": config.paths.certbot_binary,
    },
    "caddy": {
      "admin_url": config.caddy.admin_url,
      "reload_command": config.caddy.reload_command,
    },
    "acme": {
      "email": config.acme.email,
      "staging": config.acme.staging,
      "challenge_type": config.acme.challenge_type,
      "dns_provider": config.acme.dns_provider,
      "dns_propagation_seconds": config.acme.dns_propagation_seconds,
      "certbot_args": config.acme.certbot_args,
    },
    "logging": {
      "level": config.logging.level,
      "controller_log_path": config.logging.controller_log_path,
      "controller_log_max_bytes": config.logging.controller_log_max_bytes,
      "controller_log_backup_count": config.logging.controller_log_backup_count,
      "caddy_log_path": config.logging.caddy_log_path,
      "caddy_log_roll_size_mb": config.logging.caddy_log_roll_size_mb,
      "caddy_log_roll_keep": config.logging.caddy_log_roll_keep,
    },
    "admin": {
      "enabled": config.admin.enabled,
      "bind": config.admin.bind,
      "port": config.admin.port,
      "token": "***" if config.admin.token else "",
    },
  }
