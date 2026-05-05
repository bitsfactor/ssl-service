"""Platform contract — user identity + billing event hook.

Every service in the BitsFactor micro-product platform uses this module
so user/billing concerns stay outside the service code itself. Today both
hooks degrade to noops; when the platform turns them on, the service
starts honouring them with no code change.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class User:
  """User identity as injected by the platform's edge gateway.

  Fields are populated from request headers. `id == "anonymous"` means
  the gateway didn't authenticate the caller (or the header didn't
  arrive) — services should still serve, gated by their own logic.
  """
  id: str
  plan: str


def get_user(request: Any) -> User:
  """Read user identity off the request headers.

  Works with FastAPI / Starlette `Request` objects (anything that
  exposes `.headers` as a mapping with case-insensitive lookup).
  """
  headers = getattr(request, "headers", {})
  user_id = headers.get("X-User-Id") or headers.get("x-user-id") or "anonymous"
  plan = headers.get("X-Plan") or headers.get("x-plan") or "free"
  return User(id=str(user_id), plan=str(plan))


# Module-level client so we don't pay TLS handshake on every report.
_CLIENT: httpx.Client | None = None


def _get_client() -> httpx.Client | None:
  global _CLIENT
  sink = os.getenv("BILLING_SINK_URL")
  if not sink:
    return None
  if _CLIENT is None:
    _CLIENT = httpx.Client(timeout=2.0)
  return _CLIENT


def report_usage(event: str, qty: float = 1.0, *, user_id: str | None = None,
                 metadata: dict[str, Any] | None = None) -> None:
  """Record a billable / metered event.

  Noop when `BILLING_SINK_URL` is unset (the default). When set, posts
  a JSON envelope and swallows transport errors — this call is on the
  hot path and must never fail a request.
  """
  sink = os.getenv("BILLING_SINK_URL")
  if not sink:
    return
  client = _get_client()
  if client is None:
    return
  payload = {
    "event": event,
    "qty": qty,
    "user_id": user_id or "anonymous",
    "metadata": metadata or {},
  }
  try:
    client.post(sink, json=payload)
  except Exception:  # noqa: BLE001 — billing must not break the request
    LOGGER.exception("report_usage POST failed event=%s", event)
