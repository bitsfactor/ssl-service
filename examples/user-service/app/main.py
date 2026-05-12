"""HTTP surface for the user-service.

Endpoints (v1, P1 scope):

  POST /api/auth/signup-start      email + password → emails OTP
  POST /api/auth/signup-confirm    email + code     → creates account + cookie
  POST /api/auth/signup-resend     email            → re-issues OTP
  POST /api/auth/login             email + password → cookie
  POST /api/auth/logout            clears cookie + revokes session row
  GET  /api/me                     current user + active subscriptions
  PATCH /api/me                    update locale / display_name

  GET  /api/products               public product catalog (active only)

  POST /api/usage                  service-to-service ingest, X-Service-Token

  GET  /api/admin/users            list users (admin only)
  POST /api/admin/users            create user (admin only, manual provisioning)
  GET  /api/admin/users/{id}       user detail
  POST /api/admin/users/{id}/grant grant a product subscription
  POST /api/admin/users/{id}/admin toggle is_admin
  GET  /api/admin/products         all products (incl. inactive)
  POST /api/admin/products         create product
  PATCH /api/admin/products/{id}   update product

  GET  /health                     simple liveness

Auth model:
  Browser session is a Cookie ``user_sid=<random>``. Server stores
  ``sha256(<random>)`` keyed in auth_sessions. ``request.user`` is
  populated by :func:`get_current_user` for any endpoint that needs it.

Admin gating:
  ``auth_users.is_admin = TRUE`` is the only switch. The first user
  to ever sign up becomes admin automatically (so the operator can
  bootstrap without SQL); subsequent users are non-admin by default.
"""
from __future__ import annotations

import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psycopg
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, field_validator

from .auth import (
  SESSION_COOKIE_NAME,
  hash_password,
  issue_session,
  lookup_session,
  needs_rehash,
  revoke_session,
  verify_password,
)
from .db import connect, init_pool
from .i18n import DEFAULT_LOCALE, SUPPORTED_LOCALES, negotiate_locale, t


LOGGER = logging.getLogger("user_service")
# Make sure our logger actually emits — uvicorn doesn't auto-configure
# arbitrary named loggers. Without this, LOGGER.info() in dev silently
# drops messages and the "[email-fallback]" verify/reset links never
# show up in `docker logs`.
if not LOGGER.handlers:
  _h = logging.StreamHandler()
  _h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s user_service %(message)s"))
  LOGGER.addHandler(_h)
  LOGGER.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
  LOGGER.propagate = False
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PASSWORD_MIN_LEN = 8


# ---------------------------------------------------------------------------
# App init / shutdown — we eagerly open the connection pool so the first
# request doesn't pay the latency.
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI):
  import asyncio
  from . import billing
  init_pool()
  # Background flush task that drains the in-memory billing buffers
  # to the DB every few seconds. Without this, all charges live in
  # memory only — survives the request lifecycle but lost on restart.
  flush_task = asyncio.create_task(billing.flush_loop())
  try:
    yield
  finally:
    flush_task.cancel()
    try:
      await flush_task
    except asyncio.CancelledError:
      pass


app = FastAPI(title="user-service", lifespan=_lifespan)

# Browser cookie auth needs CORS allow-credentials when the SPA lives on
# a different origin. v1: same-origin only (user.develop.cc serves both
# the SPA and the API), so we leave CORS permissive but restricted to
# our own develop.cc subdomains.
app.add_middleware(
  CORSMiddleware,
  allow_origin_regex=r"^https://[a-z0-9-]+\.develop\.cc$",
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------


class SignupRequest(BaseModel):
  email: EmailStr
  password: str = Field(min_length=PASSWORD_MIN_LEN, max_length=200)
  locale: str | None = None


class LoginRequest(BaseModel):
  email: EmailStr
  password: str


class MePatchRequest(BaseModel):
  locale: str | None = None
  display_name: str | None = Field(default=None, max_length=120)


class UsageEvent(BaseModel):
  user_id: str
  event: str = Field(min_length=1, max_length=120)
  # qty is a float so callers can record fractional units (e.g. tokens
  # in thousands), but it has to be non-negative — letting a caller
  # decrement a counter through this surface would make audit a
  # nightmare.
  qty: float = Field(default=1, ge=0)
  product_code: str | None = None
  source: str | None = Field(default=None, max_length=64)
  metadata: dict[str, Any] = Field(default_factory=dict)


class GrantRequest(BaseModel):
  product_code: str
  expires_at: datetime | None = None
  # Must match the CHECK constraint on subscriptions.source — DB will
  # 500 otherwise. Pydantic constrains it to the allowed set so the
  # caller gets 422 with a useful message rather than a stack trace.
  source: str = Field(default="manual", pattern=r"^(manual|stripe|grant)$")


class QuotaUpsertRequest(BaseModel):
  product_code: str
  # Use 0 to mean "no limit" — same convention as the existing tables.
  limit_qty: float = Field(ge=0)
  # Must match usage_quotas.reset_kind CHECK.
  reset_kind: str = Field(default="monthly_first",
                          pattern=r"^(never|monthly_first|monthly_anchor)$")
  # 1..28 — anything > 28 risks Feb-overflow so we clamp early.
  reset_anchor_day: int | None = Field(default=None, ge=1, le=28)
  # Optional knob: when True, also zero current_period_consumed and
  # restart current_period_start. Without it, an admin lowering the
  # limit on a quota that already used 80% of the *old* limit can leave
  # the user immediately over-quota with no path to reset short of
  # DELETE+INSERT.
  reset_consumption: bool = False

  # Reject NaN / +inf / -inf — Pydantic's ge=0 alone passes Infinity
  # because float('inf') >= 0 is True. NaN / Infinity in the DB make
  # the quota arithmetic misbehave silently.
  @field_validator("limit_qty")
  @classmethod
  def _validate_finite(cls, v: float) -> float:
    import math
    if math.isnan(v) or math.isinf(v):
      raise ValueError("limit_qty must be a finite number")
    return v


class AdminCreateUserRequest(BaseModel):
  email: EmailStr
  password: str | None = Field(default=None, min_length=PASSWORD_MIN_LEN, max_length=200)
  display_name: str | None = None
  username: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
  locale: str | None = None
  is_admin: bool = False


_VALID_SERVICE_CODES = frozenset(("chat", "xout", "platform"))


def _infer_service_code(code: str) -> str:
  """Best-effort service inference when caller omits service_code.

  Used only for backward-compat create paths that don't supply a
  service_code. Prefer explicit caller-supplied values.
  """
  if code.startswith("tier_"):
    return "chat"
  if code.startswith("xout-"):
    return "xout"
  return "platform"


class ProductCreateRequest(BaseModel):
  code: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,40}$")
  kind: str = Field(pattern=r"^(one_time|recurring|period)$")
  price_cents: int = Field(ge=0, le=100_000_000)  # $1,000,000 sanity cap
  # ISO-4217 codes are 3 letters. Reject anything else early to keep
  # bad data out of the DB without relying on Postgres' loose typing.
  currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
  period_days: int | None = Field(default=None, ge=1, le=3650)
  stripe_price_id: str | None = Field(default=None, max_length=120)
  name: dict[str, str] = Field(default_factory=dict)
  description: dict[str, str] = Field(default_factory=dict)
  metadata: dict[str, Any] = Field(default_factory=dict)
  active: bool = True
  # service_code groups the product by which platform service owns it.
  # Defaults to code-prefix inference so old callers that omit the
  # field continue to work correctly.
  service_code: str = Field(default="", min_length=0, max_length=32)

  @field_validator("period_days")
  @classmethod
  def _period_required_for_period_kind(cls, v, info):
    # period_days is the cycle length for kind=period; without it the
    # /sub expiry calc has no way to compute expires_at and the grant
    # path silently produces an unbounded sub.
    if info.data.get("kind") == "period" and v is None:
      raise ValueError("period_days is required when kind is 'period'")
    return v

  @field_validator("service_code")
  @classmethod
  def _validate_service_code(cls, v: str, info) -> str:
    if not v:
      # Infer from code when omitted for backward compat.
      return _infer_service_code(info.data.get("code", ""))
    if v not in _VALID_SERVICE_CODES:
      raise ValueError(f"service_code must be one of {sorted(_VALID_SERVICE_CODES)}")
    return v


class ProductPatchRequest(BaseModel):
  kind: str | None = Field(default=None, pattern=r"^(one_time|recurring|period)$")
  price_cents: int | None = Field(default=None, ge=0, le=100_000_000)
  currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
  period_days: int | None = Field(default=None, ge=1, le=3650)
  stripe_price_id: str | None = Field(default=None, max_length=120)
  name: dict[str, str] | None = None
  description: dict[str, str] | None = None
  metadata: dict[str, Any] | None = None
  active: bool | None = None
  service_code: str | None = Field(default=None, min_length=0, max_length=32)

  @field_validator("service_code")
  @classmethod
  def _validate_service_code(cls, v: str | None) -> str | None:
    if v is None:
      return None
    if v not in _VALID_SERVICE_CODES:
      raise ValueError(f"service_code must be one of {sorted(_VALID_SERVICE_CODES)}")
    return v


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------


def _request_locale(request: Request, user: dict | None = None) -> str:
  return negotiate_locale(
    request.headers.get("accept-language"),
    (user or {}).get("locale"),
  )


def _set_session_cookie(response: Response, token: str) -> None:
  domain = os.getenv("SESSION_COOKIE_DOMAIN", "") or None
  secure = (os.getenv("SESSION_COOKIE_SECURE", "true").lower() in ("1","true","yes"))
  response.set_cookie(
    key=SESSION_COOKIE_NAME,
    value=token,
    max_age=int(timedelta(days=30).total_seconds()),
    secure=secure,
    httponly=True,
    samesite="lax",
    domain=domain,
    path="/",
  )


def _clear_session_cookie(response: Response) -> None:
  domain = os.getenv("SESSION_COOKIE_DOMAIN", "") or None
  response.delete_cookie(
    key=SESSION_COOKIE_NAME,
    domain=domain,
    path="/",
  )


def get_current_user(
  request: Request,
  user_sid: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict:
  user = lookup_session(user_sid or "")
  if user is None:
    locale = _request_locale(request)
    raise HTTPException(status_code=401,
                        detail=t(locale, "auth.session.required"))
  return user


def get_current_user_optional(
  user_sid: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict | None:
  return lookup_session(user_sid or "")


def require_admin(
  request: Request,
  user_sid: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
  x_admin_service_token: str | None = Header(default=None, alias="X-Admin-Service-Token"),
) -> dict:
  """Admin gate.

  Two ways in:
   1. Cookie session whose user has is_admin=true (interactive operators).
   2. Service-to-service header ``X-Admin-Service-Token`` matching the
      ADMIN_SERVICE_TOKEN env var (used by the ssl-service admin proxy
      so the operator manages users/products from one console without
      a separate login). Only enabled when the env var is non-empty.
  """
  service_token = (os.getenv("ADMIN_SERVICE_TOKEN") or "").strip()
  if service_token and x_admin_service_token and \
     _consteq(x_admin_service_token, service_token):
    return {"id": None, "primary_email": None, "is_admin": True,
            "status": "active", "locale": DEFAULT_LOCALE,
            "_via": "service_token"}
  user = lookup_session(user_sid or "")
  if user is None:
    locale = _request_locale(request)
    raise HTTPException(status_code=401,
                        detail=t(locale, "auth.session.required"))
  if not user.get("is_admin"):
    locale = _request_locale(request, user)
    raise HTTPException(status_code=403,
                        detail=t(locale, "auth.admin_required"))
  return user


def _consteq(a: str, b: str) -> bool:
  """Constant-time string compare — avoids timing oracle on the token."""
  import hmac
  return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def require_service_token(
  request: Request,
  x_service_token: str | None = Header(default=None, alias="X-Service-Token"),
) -> None:
  expected = os.getenv("USAGE_INGEST_TOKEN", "")
  if not expected:
    # If the operator hasn't set the token at all, fail closed — refusing
    # writes is safer than accepting unauthenticated ones.
    raise HTTPException(status_code=503, detail="usage ingest not configured")
  # Constant-time compare — same defence as require_admin's service token.
  if not x_service_token or not _consteq(x_service_token, expected):
    raise HTTPException(status_code=401, detail="invalid X-Service-Token")


# ---------------------------------------------------------------------------
# Health / product info (required by platform)
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict:
  return {"status": "ok"}


# ``/`` serves the SPA — sign-up / login / account view. Everything
# under /api/* is JSON; everything under /static/* is a static asset.
# We keep the SPA single-file so there's nothing to bundle.
_STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
_INDEX_HTML = _STATIC_DIR / "index.html"
if _STATIC_DIR.exists():
  app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/")
def root() -> Response:
  """Serve the SPA shell. JSON probes can still hit /health for liveness."""
  if _INDEX_HTML.exists():
    return FileResponse(str(_INDEX_HTML), media_type="text/html; charset=utf-8")
  # Fallback so old smoke tests that expect JSON don't choke if the
  # static dir wasn't shipped with the image.
  return Response(content='{"service":"user","status":"ok"}',
                  media_type="application/json")


def _load_product_manifest() -> dict:
  here = Path(__file__).resolve().parent.parent
  candidate = here / ".product.yaml"
  if not candidate.exists():
    return {}
  try:
    import yaml
    return yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
  except Exception:  # noqa: BLE001
    return {}


_PRODUCT_MANIFEST = _load_product_manifest()


@app.get("/product/info")
def product_info() -> dict:
  return _PRODUCT_MANIFEST.get("product", {}) or {}


# ---------------------------------------------------------------------------
# Helpers for Auth ingestion / DB CRUD
# ---------------------------------------------------------------------------


def _normalize_email(email: str) -> str:
  return email.strip().lower()


def _require_uuid(user_id: str) -> str:
  """Reject malformed path params before they hit Postgres -- otherwise
  ``SELECT ... WHERE id = 'abc'`` returns InvalidTextRepresentation
  which surfaces as a 500 instead of a clean 400."""
  import uuid as _uuid
  try:
    return str(_uuid.UUID(str(user_id)))
  except (ValueError, AttributeError, TypeError):
    raise HTTPException(status_code=400, detail="invalid user id")


def _user_row_to_public(row: dict) -> dict:
  """Project an auth_users row to the shape we send back to clients."""
  return {
    "id": row["id"],
    "username": row.get("username"),
    "email": row.get("primary_email"),
    "display_name": row.get("display_name"),
    "locale": row.get("locale") or DEFAULT_LOCALE,
    "is_admin": bool(row.get("is_admin", False)),
    "status": row.get("status"),
    "email_verified": row.get("email_verified_at") is not None,
  }


# ---------------------------------------------------------------------------
# Quota period reset — pure-Python helper, doesn't touch DB.
# ---------------------------------------------------------------------------


def _next_period_start(reset_kind: str, anchor_day: int | None,
                        from_dt: datetime,
                        current_start: datetime) -> datetime:
  """Return the period-start ``from_dt`` belongs to under the given
  reset rule. All times are UTC.

  - ``never``         → never roll. Returns the row's existing
                        ``current_start`` so the caller's comparison
                        always evaluates to "no roll".
  - ``monthly_first`` → 1st of ``from_dt``'s month, 00:00 UTC.
  - ``monthly_anchor``→ anchor_day of the *most recent* anchor that
                        is ≤ ``from_dt``. If anchor_day is missing or
                        > 28 we clamp to 28 to dodge Feb edge cases.
  """
  if reset_kind == "never":
    return current_start
  if reset_kind == "daily":
    # Reset to UTC midnight of from_dt's day. The billing engine
    # mirrors this in-memory logic (see app/billing.py); keep them
    # in sync.
    return from_dt.replace(hour=0, minute=0, second=0,
                           microsecond=0, tzinfo=timezone.utc)
  if reset_kind == "monthly_first":
    return from_dt.replace(day=1, hour=0, minute=0, second=0,
                           microsecond=0, tzinfo=timezone.utc)
  if reset_kind == "monthly_anchor":
    day = max(1, min(28, anchor_day or 1))
    candidate = from_dt.replace(day=day, hour=0, minute=0, second=0,
                                microsecond=0, tzinfo=timezone.utc)
    if candidate > from_dt:
      # Anchor day this month is in the future → we're still in last
      # month's period.
      year = candidate.year
      month = candidate.month - 1
      if month == 0:
        month = 12
        year -= 1
      candidate = candidate.replace(year=year, month=month)
    return candidate
  # Unknown kind — fail safe: don't reset.
  return current_start


def _ensure_quota_period(cur, user_id: str, product_id: int,
                          *, lock: bool = False) -> dict | None:
  """Roll the quota row's current period if we're past its boundary.

  Returns the (possibly updated) quota row or None if no quota exists
  for ``(user_id, product_id)``. Cheap to call on every read/write
  because the boundary check is in-process.

  Pass ``lock=True`` from the write path (``/api/usage``) to grab a
  row-level lock — without it, two concurrent ingest calls can both
  pass the limit check and each commit a delta that collectively
  overshoots the quota. ``FOR UPDATE`` serialises the read+update.
  """
  cur.execute(
    f"""
    SELECT user_id::text, product_id, limit_qty, reset_kind, reset_anchor_day,
           current_period_start, current_period_consumed, updated_at
    FROM usage_quotas
    WHERE user_id = %s AND product_id = %s
    {"FOR UPDATE" if lock else ""}
    """,
    (user_id, product_id),
  )
  row = cur.fetchone()
  if row is None:
    return None
  current_start = row["current_period_start"]
  # Always normalise to UTC for comparison — TIMESTAMPTZ is stored in
  # UTC by Postgres but psycopg returns it in the session TZ. Without
  # the explicit conversion the comparison can mistakenly conclude
  # "current_start < expected_start" purely because of TZ shifts.
  current_start_utc = current_start.astimezone(timezone.utc)
  expected_start = _next_period_start(row["reset_kind"],
                                       row["reset_anchor_day"],
                                       datetime.now(timezone.utc),
                                       current_start_utc)
  if current_start_utc < expected_start:
    cur.execute(
      """
      UPDATE usage_quotas
      SET current_period_start = %s,
          current_period_consumed = 0,
          updated_at = NOW()
      WHERE user_id = %s AND product_id = %s
      RETURNING current_period_start, current_period_consumed
      """,
      (expected_start, user_id, product_id),
    )
    new = cur.fetchone()
    row["current_period_start"] = new["current_period_start"]
    row["current_period_consumed"] = new["current_period_consumed"]
  return row


def _list_user_quotas(user_id: str) -> list[dict]:
  """Return per-product quota state for a user, after rolling periods."""
  with connect() as conn:
    with conn.cursor() as cur:
      # Fetch all (user, product) pairs first, then call _ensure_quota_period
      # for each so the period roll happens transactionally.
      cur.execute(
        """
        SELECT q.product_id, p.code AS product_code,
               p.name AS product_name, p.kind AS product_kind
        FROM usage_quotas q JOIN products p ON p.id = q.product_id
        WHERE q.user_id = %s
        """,
        (user_id,),
      )
      pairs = cur.fetchall()
      out: list[dict] = []
      for pair in pairs:
        q = _ensure_quota_period(cur, user_id, pair["product_id"])
        if q is None:
          continue
        out.append({
          "product_id": pair["product_id"],
          "product_code": pair["product_code"],
          "product_name": pair["product_name"],
          "product_kind": pair["product_kind"],
          "limit_qty": q["limit_qty"],
          "reset_kind": q["reset_kind"],
          "reset_anchor_day": q["reset_anchor_day"],
          "current_period_start": q["current_period_start"],
          "current_period_consumed": q["current_period_consumed"],
          "remaining": (None if q["limit_qty"] in (None, 0)
                        else max(0.0, float(q["limit_qty"]) - float(q["current_period_consumed"]))),
        })
    conn.commit()
  return out


# ---------------------------------------------------------------------------
# xout-specific config — exposed inside /api/me when the user has an
# active xout subscription. Keeps the SPA stateless about subscription
# kind: it just renders whatever blocks are present.
# ---------------------------------------------------------------------------


# ===========================================================================
# SERVICE PLUGINS
# ---------------------------------------------------------------------------
# Each business service that lives on the user system (today: xout) declares
# its own:
#   - Pydantic models for product create / patch
#   - DB-side helpers (selector evaluation, subscription URI builder, …)
#   - Public + admin + internal endpoints
#
# When adding a new service (e.g. ai_credits, vault, …), follow xout as a
# template:
#   1. Schema: a sidecar table `<svc>_products` keyed off products(id),
#      containing the service's product-specific config.
#   2. Define the request/response models near the top of its block.
#   3. Add `_<svc>_config_for_user(user_id)` that produces what /api/me
#      should return for users with this service.
#   4. Register endpoints on the FastAPI app. Group all of them under a
#      banner comment so future plugin extraction is mechanical.
#   5. Wire `_<svc>_config_for_user` into the /api/me handler.
#
# When the second service appears, this whole block becomes a real
# `app/<svc>.py` module with its own APIRouter. Until then keeping it
# inline avoids the import-cycle plumbing for one plugin.
# ===========================================================================
# Plugin: xout — subscription URL + node-inbound resolution.
#
# Mental model (post-2026-05-06 user-system unification):
#   - A "xout product" is a row in `xout_products` joined to `products`.
#     It carries an `inbound_selector` JSONB describing which (node,
#     inbound_tag) pairs the product offers.
#   - Every user has ONE public subscription URL, built from
#     ``auth_users.subscription_token``. Granting an xout product to
#     a user is just an INSERT into `subscriptions`. The /sub/{token}
#     endpoint aggregates VLESS URIs from EVERY active xout sub the
#     user holds, rendered live -- adding / removing nodes / products
#     flows through immediately, and the URL itself never rotates.
#   - The xout container on each node periodically pulls "active xout
#     users for products that include this node" from the DB and
#     renders xray config with all of them. Per-user uplink/downlink
#     stats from xray's stats API are POSTed back to /api/usage so
#     quotas count down.
# ---------------------------------------------------------------------------


def _resolve_xout_inbounds_for_node(node_name: str) -> list[dict]:
  """Return the list of inbounds defined for a node, with resolved
  reality keys when the agent has reported them back. Returns shape:

  [{"tag": "美国", "port": 12001, "protocol": "vless", "reality": {sni, public_key, short_id}, ...}, ...]

  The DB-side preset stores ``"auto"`` for reality keys — actual
  values only exist after first xray boot on the node. xout itself
  upserts them into ``xout_node_inbounds`` on boot, so /sub/<token>
  and the SPA see resolved reality info instead of the placeholder
  ``auto``.
  """
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT p.inbounds FROM xout_node_assignments a
        JOIN xout_presets p ON p.id = a.preset_id
        WHERE a.node_name = %s
        """,
        (node_name,),
      )
      row = cur.fetchone()
      preset_inbounds = (row["inbounds"] or []) if row is not None else []
      cur.execute(
        """
        SELECT tag, port, protocol, sni, public_key, short_id
        FROM xout_node_inbounds WHERE node_name = %s
        """,
        (node_name,),
      )
      reported = {r["tag"]: r for r in cur.fetchall()}
  out: list[dict] = []
  for ib in preset_inbounds:
    tag = (ib.get("tag") or "").replace("{node_name}", node_name)
    merged = {**ib, "tag": tag}
    rep = reported.get(tag)
    if rep is not None:
      reality = dict(merged.get("reality") or {})
      if rep.get("sni"):        reality["sni"] = rep["sni"]
      if rep.get("public_key"): reality["public_key"] = rep["public_key"]
      if rep.get("short_id"):   reality["short_id"] = rep["short_id"]
      merged["reality"] = reality
    out.append(merged)
  return out


def _selector_includes(selector: dict, node_name: str, tag: str) -> bool:
  """Does this xout product's selector include the given (node, tag)?

  Selector schema v1:
    {"version": 1, "nodes": [{"name": "us01", "tags": ["美国","*"]}]}

  ``"*"`` in tags means all inbounds on that node. Missing/empty
  ``tags`` means the entry is malformed and matches nothing -- we
  want explicit opt-in to dodge surprises (an empty admin form
  should not silently grant blanket access to every inbound on
  every node).
  """
  if not isinstance(selector, dict):
    LOGGER.warning("xout product selector is not a dict: %r", type(selector))
    return False
  nodes = selector.get("nodes")
  if nodes is None:
    return False
  if not isinstance(nodes, list):
    LOGGER.warning("xout product selector 'nodes' is not a list: %r", type(nodes))
    return False
  for n in nodes:
    if not isinstance(n, dict):
      continue
    if n.get("name") != node_name:
      continue
    tags = n.get("tags") or []
    if "*" in tags:
      return True
    if tag in tags:
      return True
  return False


def _validate_xout_selector(selector: Any) -> None:
  """Reject empty or malformed inbound_selectors before they reach the
  DB. Empty selector = "no inbounds" — would silently produce empty
  /sub/{token}, which is confusing UX.
  """
  if not isinstance(selector, dict):
    raise HTTPException(status_code=400,
                        detail="inbound_selector must be an object")
  nodes = selector.get("nodes")
  if not isinstance(nodes, list) or len(nodes) == 0:
    raise HTTPException(status_code=400,
                        detail="inbound_selector.nodes must be a non-empty list")
  for n in nodes:
    if not isinstance(n, dict) or not (n.get("name") or "").strip():
      raise HTTPException(status_code=400,
                          detail="each selector node must have a non-empty 'name'")
    tags = n.get("tags")
    if tags is None or not isinstance(tags, list) or len(tags) == 0:
      raise HTTPException(status_code=400,
                          detail=(f"selector node {n.get('name')} 'tags' "
                                  f"must be a non-empty list "
                                  f"(use [\"*\"] for all inbounds)"))


def _user_xout_subscriptions(user_id: str) -> list[dict]:
  """Return one row per active xout subscription for the user.

  Each row carries product info plus a resolved list of (node,
  inbound) entries the user can connect to. /api/me uses this to
  render the SPA cards; /sub/<token> aggregates inbounds across
  every row to build the unified subscription bundle.

  The user's VLESS UUID is read from auth_users (one global UUID per
  user, not per (user, node)) -- post-2026-05-06 user-system
  unification. ``subscription_token`` is no longer stored on the
  subscriptions row, so the public URL is built from the user's
  ``auth_users.subscription_token`` instead.
  """
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT vless_uuid::text AS vless_uuid FROM auth_users WHERE id = %s",
        (user_id,),
      )
      ur = cur.fetchone()
      vless_uuid = (ur or {}).get("vless_uuid")
      cur.execute(
        """
        SELECT s.id AS sub_id, s.expires_at, s.starts_at, s.status,
               p.id AS product_id, p.code AS product_code,
               p.name AS product_name, p.kind, p.period_days,
               xp.inbound_selector, xp.metadata AS xout_metadata
        FROM subscriptions s
        JOIN products p ON p.id = s.product_id
        JOIN xout_products xp ON xp.product_id = p.id
        WHERE s.user_id = %s AND s.status = 'active'
          AND (s.expires_at IS NULL OR s.expires_at > NOW())
        ORDER BY p.id
        """,
        (user_id,),
      )
      subs = cur.fetchall()
      if not subs:
        return []
      # Pre-fetch host info for all nodes mentioned in any selector.
      node_names: set[str] = set()
      for s in subs:
        for n in (s["inbound_selector"] or {}).get("nodes") or []:
          if n.get("name"):
            node_names.add(n["name"])
      cur.execute(
        "SELECT name, host FROM nodes WHERE name = ANY(%s)",
        (list(node_names) or [""],),
      )
      node_hosts = {r["name"]: r["host"] for r in cur.fetchall()}

  out = []
  for s in subs:
    selector = s["inbound_selector"] or {"nodes": []}
    matched = []
    for node_name in node_names:
      inbounds = _resolve_xout_inbounds_for_node(node_name)
      for ib in inbounds:
        if not _selector_includes(selector, node_name, ib.get("tag", "")):
          continue
        matched.append({
          "node_name": node_name,
          "node_host": node_hosts.get(node_name),
          "tag": ib.get("tag"),
          "port": ib.get("port"),
          "protocol": ib.get("protocol"),
          "vless_uuid": vless_uuid,
          # Include reality for the URI builder. /api/me also returns
          # this so the SPA can display the SNI per-line if it wants.
          "reality": ib.get("reality"),
        })
    out.append({
      "subscription_id": s["sub_id"],
      "expires_at": s["expires_at"],
      "product_id": s["product_id"],
      "product_code": s["product_code"],
      "product_name": s["product_name"],
      "kind": s["kind"],
      "period_days": s["period_days"],
      "inbounds": matched,
    })
  return out


def _build_subscription_uris(user_id: str, sub_id: int,
                              inbounds: list[dict]) -> list[str]:
  """Build vless:// URIs for one subscription's inbounds. Inbounds
  without a ``vless_uuid`` (= user not yet provisioned on that node) are
  skipped. Reality params come from the inbound's ``reality`` block in
  the preset; if any of sni / public_key / short_id are missing or
  ``auto`` we omit the URI rather than emit broken config — the xout
  container fills these on first boot, so the URI becomes valid as soon
  as the secrets resolve.
  """
  from urllib.parse import quote
  uris: list[str] = []
  for ib in inbounds:
    proto = (ib.get("protocol") or "").lower()
    host  = ib.get("node_host")
    port  = ib.get("port")
    tag   = ib.get("tag") or ""
    uuid  = ib.get("vless_uuid")
    if proto != "vless" or not (host and port and uuid):
      continue
    reality = ib.get("reality") or {}
    sni = reality.get("sni") or ""
    pub = reality.get("public_key") or reality.get("pubkey") or ""
    sid = reality.get("short_id") or ""
    if not (sni and pub and sid) or pub == "auto" or sid == "auto":
      # Reality keys not yet resolved (xout will fill on container boot).
      continue
    qs = (
      f"encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp"
      f"&fp=chrome&sni={quote(sni)}&pbk={quote(pub)}&sid={quote(sid)}"
    )
    uri = f"vless://{uuid}@{host}:{port}?{qs}#{quote(tag)}"
    uris.append(uri)
  return uris


def _build_clash_yaml(inbounds: list[dict]) -> str:
  """Render the same set of inbounds as a minimal Clash config (proxies
  + a single Select group + a MATCH rule). Mirrors the filtering rules
  of ``_build_subscription_uris``: only fully-resolved VLESS+Reality
  inbounds make it in; anything else is silently skipped so a partial
  preset never produces a broken config that crashes Clash.
  """
  # Top-level fields signal "this is a complete clash config, don't
  # overlay your default template". Some Clash GUIs (clash-party in
  # particular) merge subscription rules with their own template rules
  # by default, which causes errors when the template's rules
  # reference proxy-groups our YAML doesn't define. Setting `mode: rule`
  # explicitly is the conventional signal that the sub author already
  # provided everything.
  lines: list[str] = ["mode: rule", "log-level: info", "", "proxies:"]
  proxy_names: list[str] = []
  for ib in inbounds:
    proto = (ib.get("protocol") or "").lower()
    host  = ib.get("node_host")
    port  = ib.get("port")
    tag   = (ib.get("tag") or "").strip() or f"{host}-{port}"
    uuid  = ib.get("vless_uuid")
    if proto != "vless" or not (host and port and uuid):
      continue
    reality = ib.get("reality") or {}
    sni = reality.get("sni") or ""
    pub = reality.get("public_key") or reality.get("pubkey") or ""
    sid = reality.get("short_id") or ""
    if not (sni and pub and sid) or pub == "auto" or sid == "auto":
      continue
    # Clash YAML — names must be unique. Tag uniqueness is enforced
    # upstream (xout boot validation rejects dupes), so we trust it.
    name = tag
    proxy_names.append(name)
    # Inline yaml — no external dep. Quote string values to keep
    # special chars (colons in IPv6, dashes in tags) safe.
    def q(v): return '"' + str(v).replace('"', '\\"') + '"'
    lines.append(f"  - name: {q(name)}")
    lines.append(f"    type: vless")
    lines.append(f"    server: {q(host)}")
    lines.append(f"    port: {int(port)}")
    lines.append(f"    uuid: {q(uuid)}")
    lines.append(f"    network: tcp")
    lines.append(f"    udp: true")
    lines.append(f"    tls: true")
    lines.append(f"    flow: xtls-rprx-vision")
    lines.append(f"    servername: {q(sni)}")
    lines.append(f"    client-fingerprint: chrome")
    lines.append(f"    reality-opts:")
    lines.append(f"      public-key: {q(pub)}")
    lines.append(f"      short-id: {q(sid)}")
  if not proxy_names:
    # Don't return an empty config — a Clash subscription with zero
    # proxies will silently route everything through DIRECT and confuse
    # the user. Surface the empty state explicitly.
    return ("# No usable proxies in this subscription.\n"
            "# Either no nodes are deployed yet, or their reality keys\n"
            "# haven't been resolved by xout. Try again in a minute.\n"
            "proxies: []\nproxy-groups: []\nrules: []\n")
  lines.append("")
  lines.append("proxy-groups:")
  # The select group MUST be named ``PROXY`` (uppercase). Almost every
  # Clash GUI client (clash-party, clash-verge, mihomo-party, …) layers
  # its own default rule-set list on top of the imported subscription
  # — and those rules conventionally target a group named ``PROXY``.
  # Naming it anything else (e.g. "🚀 Proxy") causes the GUI's bundled
  # rules to fail validation with errors like
  # ``RULE-SET,google,PROXY: proxy [PROXY] not found``.
  #
  # No url-test "Auto" group — operators want users to pick a node by
  # hand, not have the client silently switch under them.
  lines.append("  - name: PROXY")
  lines.append("    type: select")
  lines.append("    proxies:")
  for n in proxy_names:
    lines.append(f"      - \"{n}\"")
  lines.append("      - DIRECT")
  lines.append("")
  lines.append("rules:")
  lines.append("  - MATCH,PROXY")
  lines.append("")
  return "\n".join(lines)


def _xout_config_for_user(user_id: str) -> dict | None:
  """Compose the ``xout`` block returned by /api/me.

  Returns None when the user has no xout subscriptions. Otherwise
  returns one entry per subscription with subscription URL, product
  name, expiry, and per-node connection info.

  All entries share the SAME subscription_url -- it's per-user, not
  per-subscription, sourced from auth_users.subscription_token.
  """
  subs = _user_xout_subscriptions(user_id)
  if not subs:
    return None
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT subscription_token FROM auth_users WHERE id = %s",
        (user_id,),
      )
      ur = cur.fetchone()
      user_sub_token = (ur or {}).get("subscription_token")
  user_sub_url = f"{base}/sub/{user_sub_token}" if user_sub_token else None
  out_subs = []
  for s in subs:
    uris = _build_subscription_uris(user_id, s["subscription_id"], s["inbounds"])
    out_subs.append({
      "subscription_id": s["subscription_id"],
      "product_code": s["product_code"],
      "product_name": s["product_name"],
      "expires_at": s["expires_at"],
      "subscription_url": user_sub_url,
      "inbounds": s["inbounds"],
      "uri_count": len(uris),
    })
  return {"subscriptions": out_subs, "subscription_url": user_sub_url}


def _list_user_subscriptions(user_id: str) -> list[dict]:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT s.id, s.product_id, p.code AS product_code, p.kind,
               s.status, s.starts_at, s.expires_at, s.source,
               p.name AS product_name, p.description AS product_description,
               p.service_code
        FROM subscriptions s
        JOIN products p ON p.id = s.product_id
        WHERE s.user_id = %s
        ORDER BY s.starts_at DESC
        """,
        (user_id,),
      )
      return cur.fetchall()


def _no_users_yet(cur=None) -> bool:
  """Returns True when the auth_users table has no rows.

  When ``cur`` is provided, the check runs on the caller's cursor so it
  joins their transaction. The signup path does this *under* an
  advisory lock so two concurrent first-time signups can't both win the
  bootstrap-admin promotion.
  """
  if cur is not None:
    cur.execute("SELECT 1 FROM auth_users LIMIT 1")
    return cur.fetchone() is None
  with connect() as conn:
    with conn.cursor() as c:
      c.execute("SELECT 1 FROM auth_users LIMIT 1")
      return c.fetchone() is None


# Fixed key for the first-user bootstrap advisory lock. Any value works
# as long as it never collides with another lock in the DB; we picked an
# arbitrary 64-bit constant. Held only inside the signup transaction so
# the lock vanishes on commit/rollback.
_FIRST_USER_LOCK_KEY = 0x7553_4552_5F31_5354  # b"USER_1ST" mnemonic


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Signup is a two-step OTP flow:
#   POST /api/auth/signup-start    → email + password staged in
#                                    `pending_signups`, 6-digit OTP emailed.
#                                    No `auth_users` row yet, no session.
#   POST /api/auth/signup-confirm  → email + code → on match, the staged
#                                    row is promoted into a real account
#                                    (auth_users + auth_passwords + tier
#                                    grants + accounts row), session cookie
#                                    set, pending row deleted.
#   POST /api/auth/signup-resend   → re-issue the OTP for an in-flight
#                                    signup (rate-limited).
#
# Why two steps: blocks signups with bogus emails — the account isn't
# created until the user proves they can read mail at that address. The
# old single-shot /api/auth/signup is gone.
#
# OTP details:
#   - 6 random digits, zero-padded
#   - argon2-hashed at rest (same hasher we use for passwords)
#   - 10-minute TTL from issuance
#   - 5 wrong attempts on the same staged row → user must resend
#   - resend is rate-limited to once per 60 seconds
# ---------------------------------------------------------------------------

_OTP_TTL_MINUTES = 10
_OTP_MAX_ATTEMPTS = 5
_OTP_RESEND_MIN_SECONDS = 60


def _generate_otp() -> str:
  import secrets as _secrets
  return f"{_secrets.randbelow(1_000_000):06d}"


def _verify_otp_hash(raw_code: str, stored_hash: str) -> bool:
  try:
    return verify_password(raw_code, stored_hash)
  except Exception:  # noqa: BLE001
    return False


def _send_signup_otp_email(email: str, code: str, locale: str) -> None:
  _send_email(
    email,
    t(locale, "auth.signup.otp_email_subject"),
    t(locale, "auth.signup.otp_email_body",
      code=code, ttl=_OTP_TTL_MINUTES),
  )


class SignupConfirmRequest(BaseModel):
  email: EmailStr
  code: str = Field(min_length=6, max_length=6)


class SignupResendRequest(BaseModel):
  email: EmailStr


@app.post("/api/auth/signup-start")
def auth_signup_start(req: SignupRequest, request: Request) -> dict:
  """Stage a signup and send an OTP. No account is created here."""
  locale_hint = req.locale or request.headers.get("accept-language")
  locale = negotiate_locale(locale_hint)
  email = _normalize_email(req.email)
  if not EMAIL_RE.match(email):
    raise HTTPException(status_code=400, detail=t(locale, "auth.signup.invalid_email"))
  if len(req.password) < PASSWORD_MIN_LEN:
    raise HTTPException(status_code=400,
                        detail=t(locale, "auth.signup.password_too_short"))

  # Refuse re-signup for an address that's already a full account.
  # (The pending_signups row will be overwritten below — re-entering the
  # form for an unfinished signup is the supported "lost the code" path.)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT 1 FROM auth_users WHERE LOWER(primary_email) = %s",
        (email,),
      )
      if cur.fetchone() is not None:
        raise HTTPException(status_code=409,
                            detail=t(locale, "auth.signup.email_taken"))

  code = _generate_otp()
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        INSERT INTO pending_signups
          (email, password_hash, locale, display_name, otp_hash,
           otp_created_at, attempts, resend_count, last_resend_at)
        VALUES (%s, %s, %s, NULL, %s, NOW(), 0, 0, NOW())
        ON CONFLICT (email) DO UPDATE SET
          password_hash = EXCLUDED.password_hash,
          locale = EXCLUDED.locale,
          otp_hash = EXCLUDED.otp_hash,
          otp_created_at = NOW(),
          attempts = 0,
          resend_count = 0,
          last_resend_at = NOW()
        """,
        (email, hash_password(req.password), locale, hash_password(code)),
      )
    conn.commit()

  try:
    _send_signup_otp_email(email, code, locale)
  except Exception:  # noqa: BLE001
    LOGGER.exception("could not send signup OTP email")

  LOGGER.info("auth.signup-start email=%s", email)
  return {"pending": True, "email": email}


@app.post("/api/auth/signup-resend")
def auth_signup_resend(req: SignupResendRequest, request: Request) -> dict:
  """Re-issue the OTP for an in-flight signup. Throttled."""
  locale = negotiate_locale(request.headers.get("accept-language"))
  email = _normalize_email(req.email)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT email, last_resend_at, resend_count
        FROM pending_signups WHERE email = %s
        """,
        (email,),
      )
      row = cur.fetchone()
      if row is None:
        # Don't reveal whether the email is staged or not — same 200
        # path either way to avoid email-enumeration.
        return {"pending": True}
      since = (datetime.now(timezone.utc) -
               row["last_resend_at"]).total_seconds() if row["last_resend_at"] else 1e9
      if since < _OTP_RESEND_MIN_SECONDS:
        raise HTTPException(
          status_code=429,
          detail=t(locale, "auth.signup.resend_too_soon"),
        )
      code = _generate_otp()
      cur.execute(
        """
        UPDATE pending_signups
        SET otp_hash = %s, otp_created_at = NOW(), attempts = 0,
            resend_count = resend_count + 1, last_resend_at = NOW()
        WHERE email = %s
        """,
        (hash_password(code), email),
      )
    conn.commit()
  try:
    _send_signup_otp_email(email, code, locale)
  except Exception:  # noqa: BLE001
    LOGGER.exception("could not resend signup OTP email")
  return {"pending": True}


@app.post("/api/auth/signup-confirm")
def auth_signup_confirm(req: SignupConfirmRequest, request: Request,
                       response: Response) -> dict:
  """Verify the OTP and finalize the account."""
  locale_hint = request.headers.get("accept-language")
  locale = negotiate_locale(locale_hint)
  email = _normalize_email(req.email)

  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT email, password_hash, locale, otp_hash, otp_created_at,
               attempts
        FROM pending_signups WHERE email = %s
        FOR UPDATE
        """,
        (email,),
      )
      pending = cur.fetchone()
      if pending is None:
        raise HTTPException(status_code=400,
                            detail=t(locale, "auth.signup.no_pending"))
      age = (datetime.now(timezone.utc) -
             pending["otp_created_at"]).total_seconds() / 60
      if age > _OTP_TTL_MINUTES:
        cur.execute("DELETE FROM pending_signups WHERE email = %s", (email,))
        conn.commit()
        raise HTTPException(status_code=400,
                            detail=t(locale, "auth.signup.code_expired"))
      if pending["attempts"] >= _OTP_MAX_ATTEMPTS:
        raise HTTPException(status_code=429,
                            detail=t(locale, "auth.signup.too_many_attempts"))
      if not _verify_otp_hash(req.code, pending["otp_hash"]):
        cur.execute(
          "UPDATE pending_signups SET attempts = attempts + 1 WHERE email = %s",
          (email,),
        )
        conn.commit()
        raise HTTPException(status_code=400,
                            detail=t(locale, "auth.signup.code_wrong"))
      # OTP matches — promote the staged row into a real account.
      conn.commit()

  user_locale = pending["locale"] or locale
  password_hash = pending["password_hash"]

  # Username derivation + first-user bootstrap, same as the old single-shot
  # signup. Held under the same advisory lock so concurrent "first-ever
  # signup confirmations" can't both win.
  local = re.sub(r"[^a-z0-9_.-]", "", email.split("@", 1)[0].lower())
  base_username = local or f"user_{int(datetime.now(timezone.utc).timestamp())}"
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT pg_advisory_xact_lock(%s)", (_FIRST_USER_LOCK_KEY,))
      is_first = _no_users_yet(cur)
      # Re-check email uniqueness inside the lock — a race between two
      # confirms with the same address could otherwise produce two rows.
      cur.execute(
        "SELECT id::text FROM auth_users WHERE LOWER(primary_email) = %s",
        (email,),
      )
      if cur.fetchone() is not None:
        cur.execute("DELETE FROM pending_signups WHERE email = %s", (email,))
        conn.commit()
        raise HTTPException(status_code=409,
                            detail=t(user_locale, "auth.signup.email_taken"))
      candidate = base_username
      attempt = 0
      while True:
        cur.execute(
          "SELECT 1 FROM auth_users WHERE LOWER(username) = LOWER(%s)",
          (candidate,),
        )
        if cur.fetchone() is None:
          break
        attempt += 1
        candidate = f"{base_username}_{attempt}"
        if attempt > 99:
          raise HTTPException(status_code=409,
                              detail=t(user_locale, "auth.signup.email_taken"))
      cur.execute(
        """
        INSERT INTO auth_users (username, primary_email, locale, is_admin, status,
                                email_verified_at)
        VALUES (%s, %s, %s, %s, 'active', NOW())
        RETURNING id::text, username, primary_email, locale, is_admin, display_name, status
        """,
        (candidate, email, user_locale, is_first),
      )
      user_row = cur.fetchone()
      cur.execute(
        "INSERT INTO auth_passwords (user_id, argon2_hash) VALUES (%s, %s)",
        (user_row["id"], password_hash),
      )

      # Grant tier_free (fallback, 0/day) + 7-day tier_basic + accounts
      # row — identical to the pre-OTP flow.
      cur.execute(
        "SELECT id FROM products WHERE code = 'tier_free' AND active = TRUE LIMIT 1"
      )
      _free = cur.fetchone()
      if _free is not None:
        cur.execute(
          """
          INSERT INTO subscriptions (user_id, product_id, status, starts_at, source)
          VALUES (%s, %s, 'active', NOW(), 'grant')
          """,
          (user_row["id"], _free["id"]),
        )
        cur.execute(
          """
          INSERT INTO usage_quotas (user_id, product_id, limit_qty,
                                     reset_kind, current_period_start,
                                     current_period_consumed, updated_at)
          VALUES (%s, %s, 0, 'never', NOW(), 0, NOW())
          ON CONFLICT (user_id, product_id) DO NOTHING
          """,
          (user_row["id"], _free["id"]),
        )
      cur.execute(
        """
        SELECT id,
               COALESCE((metadata->>'daily_allowance_cents')::int, 200)
                 AS daily_allowance
        FROM products WHERE code = 'tier_basic' AND active = TRUE LIMIT 1
        """
      )
      _basic = cur.fetchone()
      if _basic is not None:
        cur.execute(
          """
          INSERT INTO subscriptions (user_id, product_id, status, starts_at,
                                       expires_at, source, metadata)
          VALUES (%s, %s, 'active', NOW(), NOW() + INTERVAL '7 days',
                  'grant', jsonb_build_object('reason', 'signup_7day_basic'))
          """,
          (user_row["id"], _basic["id"]),
        )
        cur.execute(
          """
          INSERT INTO usage_quotas (user_id, product_id, limit_qty,
                                     reset_kind, current_period_start,
                                     current_period_consumed, updated_at)
          VALUES (%s, %s, %s, 'daily',
                  date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
                  0, NOW())
          ON CONFLICT (user_id, product_id) DO NOTHING
          """,
          (user_row["id"], _basic["id"], _basic["daily_allowance"]),
        )
      cur.execute(
        """
        INSERT INTO accounts (user_id, trial_credit_cents)
        VALUES (%s, 0)
        ON CONFLICT (user_id) DO NOTHING
        """,
        (user_row["id"],),
      )
      cur.execute("DELETE FROM pending_signups WHERE email = %s", (email,))
    conn.commit()

  token = issue_session(user_row["id"],
                        ip=request.client.host if request.client else None,
                        ua=request.headers.get("user-agent"))
  _set_session_cookie(response, token)
  LOGGER.info("auth.signup-confirm id=%s admin=%s email=%s",
              user_row["id"], is_first, email)
  return {"user": _user_row_to_public(user_row)}


@app.post("/api/auth/login")
def auth_login(req: LoginRequest, request: Request, response: Response) -> dict:
  email = _normalize_email(req.email)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT u.id::text AS id, u.primary_email, u.locale, u.display_name,
               u.is_admin, u.status, p.argon2_hash
        FROM auth_users u
        LEFT JOIN auth_passwords p ON p.user_id = u.id
        WHERE LOWER(u.primary_email) = %s
        """,
        (email,),
      )
      row = cur.fetchone()

  locale = _request_locale(request, row)
  if row is None or not row.get("argon2_hash"):
    # Same response shape for "no such user" and "wrong password" so we
    # don't leak which emails are registered.
    raise HTTPException(status_code=401, detail=t(locale, "auth.login.invalid"))
  if row["status"] != "active":
    raise HTTPException(status_code=403, detail=t(locale, "auth.login.disabled"))
  if not verify_password(req.password, row["argon2_hash"]):
    raise HTTPException(status_code=401, detail=t(locale, "auth.login.invalid"))

  if needs_rehash(row["argon2_hash"]):
    new_hash = hash_password(req.password)
    with connect() as conn:
      with conn.cursor() as cur:
        cur.execute(
          "UPDATE auth_passwords SET argon2_hash = %s WHERE user_id = %s",
          (new_hash, row["id"]),
        )
      conn.commit()

  token = issue_session(row["id"],
                        ip=request.client.host if request.client else None,
                        ua=request.headers.get("user-agent"))
  _set_session_cookie(response, token)
  LOGGER.info("auth.login id=%s", row["id"])
  return {"user": _user_row_to_public(row)}


@app.post("/api/auth/logout")
def auth_logout(
  response: Response,
  user_sid: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> dict:
  if user_sid:
    revoke_session(user_sid)
  _clear_session_cookie(response)
  return {"ok": True}


# ---------------------------------------------------------------------------
# Email-delivery helper. Real SMTP when system_config['smtp.config'] is set;
# otherwise we just LOG the message so an operator can copy the verify /
# reset link from `docker logs` during dev.
# ---------------------------------------------------------------------------


def _send_email(to_email: str, subject: str, body: str) -> bool:
  cfg = _get_system_config("smtp.config")
  host = (cfg.get("host") or "").strip()
  if not host:
    LOGGER.info("[email-fallback] to=%s subject=%s\n%s",
                 to_email, subject, body)
    return False
  port = int(cfg.get("port") or 587)
  user = cfg.get("user") or ""
  password = cfg.get("password") or ""
  from_email = (cfg.get("from_email") or user or "no-reply@user.develop.cc").strip()
  from_name = (cfg.get("from_name") or "User Service").strip()
  # `starttls: false` in the system_config JSON parses to Python `False`,
  # which `or "true"` then silently *replaced* with True — making the code
  # use STARTTLS even when the operator had said "no, this is implicit SSL".
  # Treat missing/None as the default (True), but respect a real False.
  starttls_raw = cfg.get("starttls")
  use_starttls = (
    True
    if starttls_raw is None
    else str(starttls_raw).lower() in ("1", "true", "yes")
  )
  try:
    import smtplib
    from email.mime.text import MIMEText
    from email.utils import formataddr
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = formataddr((from_name, from_email))
    msg["To"] = to_email
    if use_starttls:
      with smtplib.SMTP(host, port, timeout=15) as smtp:
        smtp.starttls()
        if user and password:
          smtp.login(user, password)
        smtp.sendmail(from_email, [to_email], msg.as_string())
    else:
      with smtplib.SMTP_SSL(host, port, timeout=15) as smtp:
        if user and password:
          smtp.login(user, password)
        smtp.sendmail(from_email, [to_email], msg.as_string())
    return True
  except Exception:  # noqa: BLE001
    LOGGER.exception("smtp send failed; falling back to log")
    LOGGER.info("[email-fallback] to=%s subject=%s\n%s",
                 to_email, subject, body)
    return False


# ---------------------------------------------------------------------------
# Email verification — generated at signup, redeemed by clicking the link.
# ---------------------------------------------------------------------------


def _make_verification_token(user_id: str, email: str, kind: str,
                                ttl_hours: int) -> str:
  """Insert an auth_email_verifications row. Returns the plaintext token
  the caller embeds in a link; only sha256(token) is stored."""
  import secrets as _secrets, hashlib as _hashlib
  token = _secrets.token_urlsafe(24)
  token_hash = _hashlib.sha256(token.encode("utf-8")).hexdigest()
  expires = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        INSERT INTO auth_email_verifications
          (token_hash, user_id, kind, email, expires_at, created_at)
        VALUES (%s, %s, %s, %s, %s, NOW())
        """,
        (token_hash, user_id, kind, email.lower(), expires),
      )
    conn.commit()
  return token


def _redeem_token(token: str, kind: str) -> dict | None:
  """Validate + mark used. Returns the verification row or None if
  the token is bad / expired / already used."""
  import hashlib as _hashlib
  th = _hashlib.sha256(token.encode("utf-8")).hexdigest()
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT user_id::text AS user_id, email, expires_at, used_at
        FROM auth_email_verifications
        WHERE token_hash = %s AND kind = %s
        FOR UPDATE
        """,
        (th, kind),
      )
      row = cur.fetchone()
      if row is None or row["used_at"] is not None:
        return None
      if row["expires_at"] < datetime.now(timezone.utc):
        return None
      cur.execute(
        "UPDATE auth_email_verifications SET used_at = NOW() WHERE token_hash = %s",
        (th,),
      )
    conn.commit()
  return row


@app.post("/api/auth/verify-email/send")
def verify_email_send(user: dict = Depends(get_current_user)) -> dict:
  """User clicked 'resend verification' on the SPA banner. Always 200
  even if email is already verified — keeps timing observable equal."""
  email = user.get("primary_email")
  if not email:
    raise HTTPException(status_code=400, detail="no email on this account")
  if user.get("email_verified_at"):
    return {"ok": True, "already_verified": True}
  token = _make_verification_token(user["id"], email, "verify_email", 24)
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  link = f"{base}/auth/verify-email?token={token}"
  _send_email(email, "Verify your email",
              f"Click the link to verify your email:\n\n{link}\n\n"
              f"This link expires in 24 hours.")
  return {"ok": True}


@app.post("/api/auth/verify-email")
def verify_email(payload: dict) -> dict:
  """Public endpoint. Body: {token}. Marks the email verified."""
  token = (payload or {}).get("token") or ""
  if not _looks_like_token(token):
    raise HTTPException(status_code=400, detail="invalid token")
  row = _redeem_token(token, "verify_email")
  if row is None:
    raise HTTPException(status_code=400, detail="token invalid or expired")
  with connect() as conn:
    with conn.cursor() as cur:
      # Refuse to verify the email of a disabled / deleted account —
      # otherwise an attacker holding a still-valid token could
      # quietly re-arm the email on a deactivated user.
      cur.execute(
        """
        UPDATE auth_users
        SET email_verified_at = NOW(), updated_at = NOW()
        WHERE id = %s AND LOWER(primary_email) = %s AND status = 'active'
        """,
        (row["user_id"], row["email"]),
      )
      if cur.rowcount == 0:
        raise HTTPException(status_code=400,
                            detail="account is not active")
    conn.commit()
  return {"ok": True}


# ---------------------------------------------------------------------------
# Password reset — operator-friendly: works whether SMTP is configured
# or not; without SMTP the link is in container logs.
# ---------------------------------------------------------------------------


class ForgotPasswordRequest(BaseModel):
  email: EmailStr


class ResetPasswordRequest(BaseModel):
  token: str
  new_password: str = Field(min_length=PASSWORD_MIN_LEN, max_length=200)


@app.post("/api/auth/forgot-password")
def forgot_password(req: ForgotPasswordRequest) -> dict:
  """Always 200. Never reveals whether email is registered — that's
  a privacy guarantee. Real work happens only if a user actually exists.

  Best-effort to keep the response time near-constant: we run the
  DB lookup either way, and on no-match we run a dummy SHA256 hash
  that's similar in cost to inserting a token. Not a perfect cover
  — the email send still adds a few hundred ms — but takes the
  obvious cliff out of the timing oracle.
  """
  import time as _time
  start = _time.perf_counter()
  email = _normalize_email(req.email)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT id::text FROM auth_users WHERE LOWER(primary_email) = %s AND status='active'",
        (email,),
      )
      row = cur.fetchone()
  if row is not None:
    token = _make_verification_token(row["id"], email, "reset_password", ttl_hours=1)
    base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
    link = f"{base}/?reset={token}"
    _send_email(email, "Reset your password",
                f"Click the link to reset your password:\n\n{link}\n\n"
                f"This link expires in 1 hour. If you didn't request this, ignore the message.")
  else:
    # Cover work — same shape but not persisted. Cheap, just enough
    # to make the no-match path not finish noticeably faster.
    import secrets as _sec, hashlib as _h
    _h.sha256(_sec.token_bytes(48)).hexdigest()
  # Floor the response time so the network-RTT delta is the only
  # observable channel, not server work.
  elapsed = _time.perf_counter() - start
  if elapsed < 0.15:
    _time.sleep(0.15 - elapsed)
  return {"ok": True}


@app.post("/api/admin/auth/cleanup-tokens", dependencies=[Depends(require_admin)])
def admin_cleanup_tokens() -> dict:
  """Operator-triggered: prune expired email verification tokens.
  Safe to call periodically (cron / scheduled task)."""
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "DELETE FROM auth_email_verifications WHERE expires_at < NOW() - INTERVAL '7 days'"
      )
      n = cur.rowcount
    conn.commit()
  return {"deleted": n}


@app.post("/api/auth/reset-password")
def reset_password(req: ResetPasswordRequest) -> dict:
  if not _looks_like_token(req.token):
    raise HTTPException(status_code=400, detail="invalid token")
  row = _redeem_token(req.token, "reset_password")
  if row is None:
    raise HTTPException(status_code=400, detail="token invalid or expired")
  user_id = row["user_id"]
  new_hash = hash_password(req.new_password)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "UPDATE auth_passwords SET argon2_hash = %s, updated_at = NOW() WHERE user_id = %s",
        (new_hash, user_id),
      )
      if cur.rowcount == 0:
        # User had no password row — they signed up via OAuth. Insert one.
        cur.execute(
          "INSERT INTO auth_passwords (user_id, argon2_hash) VALUES (%s, %s)",
          (user_id, new_hash),
        )
      # Revoke all existing sessions — assume the password leak is the
      # reason for reset.
      cur.execute("DELETE FROM auth_sessions WHERE user_id = %s", (user_id,))
    conn.commit()
  return {"ok": True}


# ---------------------------------------------------------------------------
# Active sessions for the current user — list + revoke individuals.
# ---------------------------------------------------------------------------


@app.get("/api/me/sessions")
def me_sessions(user: dict = Depends(get_current_user),
                  user_sid: str | None = Cookie(default=None,
                                                  alias=SESSION_COOKIE_NAME)) -> dict:
  import hashlib as _hashlib
  current_hash = _hashlib.sha256((user_sid or "").encode("utf-8")).hexdigest()
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT token_hash, created_at, expires_at, last_used_at, ip, user_agent
        FROM auth_sessions
        WHERE user_id = %s AND expires_at > NOW()
        ORDER BY last_used_at DESC
        """,
        (user["id"],),
      )
      rows = cur.fetchall()
  out = []
  for r in rows:
    out.append({
      # 24-hex-char prefix = 96 bits — collision probability over the
      # entire user base is < 10^-9 even at millions of sessions, so
      # `LIKE id || '%'` in revoke can't accidentally match someone
      # else's session.
      "id": r["token_hash"][:24],
      "current": r["token_hash"] == current_hash,
      "created_at": r["created_at"],
      "expires_at": r["expires_at"],
      "last_used_at": r["last_used_at"],
      "ip": r["ip"],
      "user_agent": r["user_agent"],
    })
  return {"sessions": out}


@app.delete("/api/me/sessions/{session_id}")
def me_revoke_session(session_id: str,
                        user: dict = Depends(get_current_user)) -> dict:
  # Match the prefix length emitted by /api/me/sessions exactly.
  # Anything shorter could collide; anything longer is fine but we
  # reject for predictability.
  if not session_id or len(session_id) < 16 or len(session_id) > 64:
    raise HTTPException(status_code=400, detail="invalid session id")
  import re as _re
  if not _re.match(r"^[0-9a-f]+$", session_id):
    raise HTTPException(status_code=400, detail="invalid session id")
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "DELETE FROM auth_sessions WHERE user_id = %s AND token_hash LIKE %s",
        (user["id"], session_id + "%"),
      )
      n = cur.rowcount
    conn.commit()
  return {"deleted": n}


@app.delete("/api/me/sessions")
def me_revoke_all_sessions(user: dict = Depends(get_current_user),
                              user_sid: str | None = Cookie(default=None,
                                                              alias=SESSION_COOKIE_NAME)) -> dict:
  """Revoke every session EXCEPT the caller's current one — otherwise
  the user logs themselves out, which is rarely what they wanted."""
  import hashlib as _hashlib
  keep_hash = _hashlib.sha256((user_sid or "").encode("utf-8")).hexdigest()
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "DELETE FROM auth_sessions WHERE user_id = %s AND token_hash != %s",
        (user["id"], keep_hash),
      )
      n = cur.rowcount
    conn.commit()
  return {"deleted": n}


# ---------------------------------------------------------------------------
# /api/me
# ---------------------------------------------------------------------------


@app.get("/api/me")
def me(user: dict = Depends(get_current_user)) -> dict:
  subs = _list_user_subscriptions(user["id"])
  quotas = _list_user_quotas(user["id"])
  xout = _xout_config_for_user(user["id"])
  return {
    "user": _user_row_to_public(user),
    "subscriptions": [
      {
        "id": s["id"],
        "product_code": s["product_code"],
        "product_name": s.get("product_name"),
        "product_description": s.get("product_description"),
        "service_code": s.get("service_code", "platform"),
        "kind": s["kind"],
        "status": s["status"],
        "starts_at": s["starts_at"],
        "expires_at": s["expires_at"],
      }
      for s in subs
    ],
    "quotas": quotas,
    "xout": xout,
  }


@app.get("/api/me/usage")
def me_usage(user: dict = Depends(get_current_user)) -> dict:
  """Per-product quota state + AI billing summary for the logged-in
  user. ``billing`` reflects the in-memory accumulator so the
  response is fresh-to-the-second; ``quotas`` is a DB snapshot of
  every product the user has a quota row for."""
  from . import billing as _billing
  usage_summary = _billing.get_usage_summary(user["id"])
  # Attach trial_credit_cents from accounts table (Job 2 — account-level credit).
  trial_credit = _get_trial_credit(user["id"])
  if trial_credit is not None:
    usage_summary["trial_credit_cents"] = trial_credit
  # Per-model token breakdown for the current billing period — same
  # numbers used by the chatbot sidebar footer. Period start matches
  # the billing engine's quota period or UTC midnight as fallback.
  period_start_iso = usage_summary.get("current_period_start")
  if period_start_iso:
    try:
      period_start = datetime.fromisoformat(period_start_iso)
      if period_start.tzinfo is None:
        period_start = period_start.replace(tzinfo=timezone.utc)
    except Exception:
      period_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
      )
  else:
    period_start = datetime.now(timezone.utc).replace(
      hour=0, minute=0, second=0, microsecond=0
    )
  usage_summary["tokens_today"] = _build_token_usage_period(
    user["id"], period_start
  )
  return {
    "quotas": _list_user_quotas(user["id"]),
    "billing": usage_summary,
  }


def _get_trial_credit(user_id: str) -> int | None:
  """Return the remaining trial_credit_cents for the user, or None if the
  accounts table / column doesn't exist yet (migration hasn't run)."""
  try:
    with connect() as conn:
      with conn.cursor() as cur:
        cur.execute(
          "SELECT trial_credit_cents FROM accounts WHERE user_id = %s",
          (user_id,),
        )
        row = cur.fetchone()
    if row is None:
      return None
    return int(row["trial_credit_cents"] or 0)
  except Exception:
    return None


def _build_token_usage_period(
  user_id: str,
  period_start: "datetime",
) -> dict:
  """Aggregate usage_events rows for user_id since period_start.

  Returns a dict with:
    by_model: list of per-model breakdowns
    total_input_tokens, total_cached_input_tokens, total_output_tokens, total_cents
  """
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT
          event AS model_id,
          COALESCE(SUM((metadata->>'input_tokens')::bigint), 0) AS input_tokens,
          COALESCE(SUM((metadata->>'cached_input_tokens')::bigint), 0) AS cached_input_tokens,
          COALESCE(SUM((metadata->>'output_tokens')::bigint), 0) AS output_tokens,
          COALESCE(SUM(qty), 0) AS cents
        FROM usage_events
        WHERE user_id = %s AND ts >= %s
        GROUP BY event
        ORDER BY cents DESC
        """,
        (user_id, period_start),
      )
      rows = cur.fetchall()

  by_model = []
  total_input = 0
  total_cached = 0
  total_output = 0
  total_cents = 0.0
  for r in rows:
    inp = int(r["input_tokens"] or 0)
    cached = int(r["cached_input_tokens"] or 0)
    out = int(r["output_tokens"] or 0)
    cents = float(r["cents"] or 0)
    total_input += inp
    total_cached += cached
    total_output += out
    total_cents += cents
    by_model.append({
      "model_id": r["model_id"],
      "input_tokens": inp,
      "cached_input_tokens": cached,
      "output_tokens": out,
      "cents": round(cents, 6),
    })

  return {
    "by_model": by_model,
    "total_input_tokens": total_input,
    "total_cached_input_tokens": total_cached,
    "total_output_tokens": total_output,
    "total_cents": round(total_cents, 6),
  }


@app.get("/api/me/usage-tokens")
def me_usage_tokens(user: dict = Depends(get_current_user)) -> dict:
  """Return per-model token consumption totals for the current user.

  ``today`` covers the current billing period (UTC midnight or the
  active quota's current_period_start, whichever is later).
  ``all_time`` covers since account creation.
  """
  uid = user["id"]

  # "today" period start: use UTC midnight, same as the billing engine.
  now_utc = datetime.now(timezone.utc)
  today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)

  # "all_time" period start: user's account creation timestamp.
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT created_at FROM auth_users WHERE id = %s",
        (uid,),
      )
      row = cur.fetchone()
  if row and row["created_at"]:
    all_time_start = row["created_at"]
    if all_time_start.tzinfo is None:
      all_time_start = all_time_start.replace(tzinfo=timezone.utc)
  else:
    # fallback: 2024-01-01
    all_time_start = datetime(2024, 1, 1, tzinfo=timezone.utc)

  today_data = _build_token_usage_period(uid, today_start)
  all_time_data = _build_token_usage_period(uid, all_time_start)

  return {
    "today": today_data,
    "all_time": all_time_data,
  }


# ---------------------------------------------------------------------------
# AI billing: charge endpoint + public pricing
# ---------------------------------------------------------------------------


class ChargeRequest(BaseModel):
  user_id: str
  model: str
  input_tokens: int = 0
  cached_input_tokens: int = 0
  output_tokens: int = 0
  duration_seconds: float = 0
  resource_id: str | None = None
  metadata: dict | None = None
  # Scope the tier lookup to this service (e.g. "chat", "xout"). Without
  # it the resolver picks the user's globally-highest tier_rank, which
  # cross-contaminates as soon as more than one service has rank-bearing
  # products. Optional for now to keep older callers working.
  service_code: str | None = None


@app.post("/api/usage/charge", dependencies=[Depends(require_service_token)])
def usage_charge(req: ChargeRequest) -> dict:
  """Service-to-service: deduct an AI op's cost from the user's
  active-tier quota. Cost is computed from token counts × the
  model's row in ``model_pricing`` × the global ``discount_factor``.

  Returns 200 on success, 429 on quota exhaustion. The hot path is
  in-memory; the DB write happens later on the flush schedule.
  """
  from . import billing as _billing
  result = _billing.charge_usage(
    req.user_id,
    model=req.model,
    input_tokens=req.input_tokens,
    cached_input_tokens=req.cached_input_tokens,
    output_tokens=req.output_tokens,
    duration_seconds=req.duration_seconds,
    resource_id=req.resource_id,
    metadata=req.metadata,
    service_code=req.service_code,
  )
  if not result.ok:
    if result.error == "quota_exhausted":
      raise HTTPException(status_code=429, detail={
        "code": "quota_exhausted",
        "tier_code": result.tier_code,
        "remaining_cents": result.remaining_cents,
        "limit_cents": result.limit_cents,
      })
    raise HTTPException(status_code=400, detail={
      "code": result.error or "charge_failed",
    })
  return {
    "ok": True,
    "charged_cents": result.charged_cents,
    "openai_cents": result.openai_cents,
    "remaining_cents": result.remaining_cents,
    "limit_cents": result.limit_cents,
    "tier_code": result.tier_code,
    "tier_rank": result.tier_rank,
  }


def _resolve_user_id(ident: str) -> str | None:
  """Accept either a UUID (user_id) or an email and return the
  user-service auth_users.id. Return None if not found."""
  if "@" in ident:
    with connect() as conn:
      with conn.cursor() as cur:
        cur.execute(
          "SELECT id::text FROM auth_users WHERE LOWER(primary_email) = LOWER(%s)",
          (ident,),
        )
        row = cur.fetchone()
    return row["id"] if row else None
  return ident


@app.get("/api/internal/users/{ident}/usage-summary",
         dependencies=[Depends(require_service_token)])
def internal_usage_summary(ident: str, service_code: str = "chat") -> dict:
  """Service-to-service: return billing summary for a user without
  needing a session cookie. ``ident`` may be either the
  ``auth_users.id`` UUID or the user's primary email — chatbot has
  its own user table with a different id space, so it passes the
  email.

  ``service_code`` scopes which subscription to resolve. Defaults to
  ``chat`` since chatbot is the dominant caller; other services pass
  their own (e.g. ``service_code=xout``) via query string.

  Also includes a ``tokens_today`` block (per-model input / cached /
  output breakdown) so the chatbot sidebar can show the user how many
  tokens they've burned in the current billing period without making
  a second round-trip."""
  from . import billing as _billing
  uid = _resolve_user_id(ident)
  if not uid:
    raise HTTPException(status_code=404, detail="user not found")
  summary = _billing.get_usage_summary(uid, service_code=service_code)
  # Bolt token-breakdown onto the same response. Period start matches
  # the billing engine's: prefer the active quota's current_period_start
  # (so a mid-day quota reset is reflected here too), else UTC midnight.
  period_start_iso = summary.get("current_period_start")
  if period_start_iso:
    try:
      period_start = datetime.fromisoformat(period_start_iso)
      if period_start.tzinfo is None:
        period_start = period_start.replace(tzinfo=timezone.utc)
    except Exception:
      period_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
      )
  else:
    period_start = datetime.now(timezone.utc).replace(
      hour=0, minute=0, second=0, microsecond=0
    )
  summary["tokens_today"] = _build_token_usage_period(uid, period_start)
  # account_balance_cents — the lifetime credit pool on accounts.
  # Previously labelled "trial credit" / "体验金"; renamed to
  # "account balance" / "账号余额" since it's a permanent balance the
  # user accumulates (no longer a sign-up bonus on new accounts).
  bal = _get_trial_credit(uid)
  if bal is not None:
    summary["account_balance_cents"] = bal
  return summary


class InternalChargeRequest(BaseModel):
  user_ident: str
  model: str
  input_tokens: int = 0
  cached_input_tokens: int = 0
  output_tokens: int = 0
  duration_seconds: float = 0
  resource_id: str | None = None
  metadata: dict | None = None
  service_code: str | None = None


@app.post("/api/internal/usage/charge",
          dependencies=[Depends(require_service_token)])
def internal_usage_charge(req: InternalChargeRequest) -> dict:
  """Service-to-service charge — same as /api/usage/charge but
  accepts email-or-uuid in ``user_ident`` so chatbot doesn't need
  to resolve the user-service uuid client-side."""
  from . import billing as _billing
  uid = _resolve_user_id(req.user_ident)
  if not uid:
    raise HTTPException(status_code=404, detail="user not found")
  result = _billing.charge_usage(
    uid,
    model=req.model,
    input_tokens=req.input_tokens,
    cached_input_tokens=req.cached_input_tokens,
    output_tokens=req.output_tokens,
    duration_seconds=req.duration_seconds,
    resource_id=req.resource_id,
    metadata=req.metadata,
    service_code=req.service_code,
  )
  if not result.ok:
    if result.error == "quota_exhausted":
      raise HTTPException(status_code=429, detail={
        "code": "quota_exhausted",
        "tier_code": result.tier_code,
        "remaining_cents": result.remaining_cents,
        "limit_cents": result.limit_cents,
      })
    raise HTTPException(status_code=400, detail={
      "code": result.error or "charge_failed",
    })
  return {
    "ok": True,
    "charged_cents": result.charged_cents,
    "openai_cents": result.openai_cents,
    "remaining_cents": result.remaining_cents,
    "limit_cents": result.limit_cents,
    "tier_code": result.tier_code,
    "tier_rank": result.tier_rank,
  }


@app.get("/api/pricing")
def public_pricing() -> dict:
  """Public — list all active model_pricing rows + the current
  discount factor. Frontend renders this on /center/billing and
  in chatbot's model picker tooltip.

  Rates are returned as both raw micro-USD ints AND human-friendly
  USD-per-1M floats so consumers don't redo the conversion.
  """
  from . import billing as _billing
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT model_id, display_name, pricing_kind, modality,
               input_rate_micros, cached_input_rate_micros, output_rate_micros,
               per_unit_micros, per_unit_label, notes, source_url, updated_at
        FROM model_pricing WHERE active = TRUE ORDER BY modality, model_id
        """
      )
      rows = cur.fetchall()
  discount = _billing.get_discount_factor()
  models = []
  for r in rows:
    def _usd_per_1m(micros: int | None) -> float | None:
      return None if micros is None else round(micros / 1_000_000, 6)
    models.append({
      "model_id": r["model_id"],
      "display_name": r["display_name"],
      "pricing_kind": r["pricing_kind"],
      "modality": r["modality"],
      "input_rate_per_1m_usd": _usd_per_1m(r["input_rate_micros"]),
      "cached_input_rate_per_1m_usd": _usd_per_1m(r["cached_input_rate_micros"]),
      "output_rate_per_1m_usd": _usd_per_1m(r["output_rate_micros"]),
      "per_unit_usd": _usd_per_1m(r["per_unit_micros"]),
      "per_unit_label": r["per_unit_label"],
      "notes": r["notes"],
      "source_url": r["source_url"],
      "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
    })
  return {
    "discount_factor": discount,
    "models": models,
  }


@app.patch("/api/me")
def me_patch(req: MePatchRequest, user: dict = Depends(get_current_user)) -> dict:
  fields: list[str] = []
  params: list[Any] = []
  if req.locale is not None:
    if req.locale not in SUPPORTED_LOCALES:
      raise HTTPException(status_code=400, detail="unsupported locale")
    fields.append("locale = %s")
    params.append(req.locale)
  if req.display_name is not None:
    fields.append("display_name = %s")
    params.append(req.display_name.strip() or None)
  if not fields:
    return {"user": _user_row_to_public(user)}
  fields.append("updated_at = NOW()")
  params.append(user["id"])
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        f"UPDATE auth_users SET {', '.join(fields)} WHERE id = %s "
        f"RETURNING id::text, primary_email, locale, display_name, is_admin, status",
        params,
      )
      row = cur.fetchone()
    conn.commit()
  return {"user": _user_row_to_public(row)}


# ---------------------------------------------------------------------------
# Public product catalog
# ---------------------------------------------------------------------------


@app.get("/api/products")
def list_products(
  request: Request,
  user: dict | None = Depends(get_current_user_optional),
  service: str | None = None,
) -> dict:
  """Public product catalog.

  Query params:
    ?service=chat   — filter to products belonging to one service
                      (used by billing pages that only care about one context)

  Response shape (backward-compatible):
    {
      "locale": "en",
      "products": [...],          # flat list — old clients read this
      "products_by_service": {    # grouped — new consumers read this
        "chat": [...],
        "xout": [...],
        ...
      }
    }

  Each product object includes ``service_code`` so consumers can
  decide per-item without inspecting the code prefix.
  """
  # Logged-in users get content in their stored locale; anonymous
  # users fall back to Accept-Language → DEFAULT_LOCALE.
  locale = _request_locale(request, user)
  # Validate ?service= value early so a typo returns 400, not an empty
  # list that silently confuses the caller.
  if service and service not in _VALID_SERVICE_CODES:
    raise HTTPException(
      status_code=400,
      detail=f"unknown service '{service}'; valid values: {sorted(_VALID_SERVICE_CODES)}"
    )
  with connect() as conn:
    with conn.cursor() as cur:
      if service:
        cur.execute(
          """
          SELECT id, code, kind, price_cents, currency, period_days,
                 name, description, metadata, active, service_code
          FROM products WHERE active = TRUE AND service_code = %s ORDER BY id ASC
          """,
          (service,),
        )
      else:
        cur.execute(
          """
          SELECT id, code, kind, price_cents, currency, period_days,
                 name, description, metadata, active, service_code
          FROM products WHERE active = TRUE ORDER BY id ASC
          """
        )
      rows = cur.fetchall()
  out = []
  by_service: dict[str, list[dict]] = {}
  for r in rows:
    name = (r["name"] or {})
    desc = (r["description"] or {})
    entry = {
      "id": r["id"],
      "code": r["code"],
      "service_code": r["service_code"],
      "kind": r["kind"],
      "price_cents": r["price_cents"],
      "currency": r["currency"],
      "period_days": r["period_days"],
      "name": name.get(locale) or name.get(DEFAULT_LOCALE) or r["code"],
      "description": desc.get(locale) or desc.get(DEFAULT_LOCALE) or "",
      "metadata": r["metadata"] or {},
    }
    out.append(entry)
    svc = r["service_code"] or "platform"
    by_service.setdefault(svc, []).append(entry)
  return {"products": out, "products_by_service": by_service, "locale": locale}


# ---------------------------------------------------------------------------
# Service-to-service usage ingest
# ---------------------------------------------------------------------------


@app.post("/api/usage", dependencies=[Depends(require_service_token)])
def usage_ingest(event: UsageEvent) -> dict:
  with connect() as conn:
    with conn.cursor() as cur:
      product_id = None
      if event.product_code:
        cur.execute("SELECT id FROM products WHERE code = %s", (event.product_code,))
        row = cur.fetchone()
        if row is None:
          raise HTTPException(status_code=400,
                              detail=f"unknown product_code: {event.product_code}")
        product_id = row["id"]

      # Quota check — must happen BEFORE the event is recorded, so a
      # rejection doesn't bloat usage_events with charges that won't
      # actually be honored. Period reset rolls automatically here too.
      # ``lock=True`` so two concurrent ingests for the same user can't
      # each pass the check and overshoot the quota.
      if product_id is not None:
        q = _ensure_quota_period(cur, event.user_id, product_id, lock=True)
        if q is not None and q["limit_qty"]:
          # limit_qty=0 means "no limit"; only enforce when > 0.
          if float(q["current_period_consumed"]) + float(event.qty) > float(q["limit_qty"]):
            raise HTTPException(
              status_code=429,
              detail={
                "code": "quota_exceeded",
                "message": "user exceeded the period quota for this product",
                "product_id": product_id,
                "limit_qty": q["limit_qty"],
                "current_period_consumed": q["current_period_consumed"],
                "current_period_start": q["current_period_start"].isoformat(),
              },
            )

      cur.execute(
        """
        INSERT INTO usage_events (user_id, product_id, event, qty, source, metadata)
        VALUES (%s, %s, %s, %s, %s, %s::jsonb)
        RETURNING id, ts
        """,
        (event.user_id, product_id, event.event, event.qty, event.source,
         _to_jsonb(event.metadata)),
      )
      result = cur.fetchone()
      # Update the running counter. UPDATE-only — usage_quotas has a
      # NOT-NULL limit_qty so we can't safely auto-insert; 0 rows = no
      # quota tracked, which is fine for events that don't bill.
      if product_id is not None:
        cur.execute(
          """
          UPDATE usage_quotas
          SET current_period_consumed = current_period_consumed + %s,
              updated_at = NOW()
          WHERE user_id = %s AND product_id = %s
          """,
          (event.qty, event.user_id, product_id),
        )
        if cur.rowcount == 0:
          LOGGER.debug("usage event has no quota row to update: user=%s product_id=%s",
                       event.user_id, product_id)
    conn.commit()
  return {"ok": True, "event_id": result["id"], "ts": result["ts"]}


_JSONB_MAX_BYTES = 64 * 1024  # 64 KiB hard cap per JSONB value


def _to_jsonb(value: Any) -> str:
  """Serialize a Python value for psycopg's ``%s::jsonb`` casting.

  Distinguishes ``None`` (becomes JSON null) from an empty dict (``{}``)
  so callers can pass ``metadata=None`` to mean "delete" — earlier code
  silently coerced both to ``{}`` and the round-trip was lossy.

  Also caps the serialized size at ``_JSONB_MAX_BYTES`` so a misbehaving
  caller can't bloat the DB with a 10MB metadata blob.
  """
  import json
  if value is None:
    return "null"
  out = json.dumps(value)
  if len(out.encode("utf-8")) > _JSONB_MAX_BYTES:
    raise HTTPException(status_code=413,
                        detail=f"metadata too large ({_JSONB_MAX_BYTES} bytes max)")
  return out


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------


@app.get("/api/admin/users", dependencies=[Depends(require_admin)])
def admin_list_users(q: str | None = None, limit: int = 50, offset: int = 0) -> dict:
  limit = max(1, min(200, limit))
  offset = max(0, offset)
  where = ""
  params: list[Any] = []
  if q:
    # Escape LIKE metacharacters so a search for "100%" matches the literal
    # string and not "anything-with-100-prefix". Postgres uses backslash by
    # default; we still pass ESCAPE explicitly to make the contract obvious.
    escaped = q.strip().lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    where = ("WHERE LOWER(primary_email) LIKE %s ESCAPE '\\' "
             "OR LOWER(username) LIKE %s ESCAPE '\\' "
             "OR LOWER(display_name) LIKE %s ESCAPE '\\'")
    needle = f"%{escaped}%"
    params.extend([needle, needle, needle])
  list_params = list(params) + [limit, offset]
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        f"""
        SELECT id::text AS id, username, primary_email,
               primary_email AS email,
               display_name, locale, is_admin, status, created_at,
               (SELECT COUNT(*) FROM subscriptions s
                WHERE s.user_id = u.id AND s.status = 'active') AS active_subs
        FROM auth_users u
        {where}
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
        """,
        list_params,
      )
      rows = cur.fetchall()
      cur.execute(f"SELECT COUNT(*) AS n FROM auth_users u {where}", params)
      total = cur.fetchone()["n"]
  return {"users": rows, "total": total, "limit": limit, "offset": offset}


@app.post("/api/admin/users", dependencies=[Depends(require_admin)])
def admin_create_user(req: AdminCreateUserRequest) -> dict:
  email = _normalize_email(req.email)
  locale = req.locale if req.locale in SUPPORTED_LOCALES else DEFAULT_LOCALE
  # username is NOT NULL on auth_users post user-system unification.
  # If the operator didn't supply one, derive from the email's local
  # part (matches the migration backfill rule). Append a numeric
  # suffix on collision so we never 500 on the INSERT.
  base_username = (req.username or "").strip().lower()
  if not base_username:
    local = re.sub(r"[^a-z0-9_.-]", "", email.split("@", 1)[0].lower())
    base_username = local or f"user_{int(datetime.now(timezone.utc).timestamp())}"
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT id FROM auth_users WHERE LOWER(primary_email) = %s",
        (email,),
      )
      if cur.fetchone() is not None:
        raise HTTPException(status_code=409, detail="email already registered")
      # Resolve username collision.
      candidate = base_username
      attempt = 0
      while True:
        cur.execute(
          "SELECT 1 FROM auth_users WHERE LOWER(username) = LOWER(%s)",
          (candidate,),
        )
        if cur.fetchone() is None:
          break
        attempt += 1
        candidate = f"{base_username}_{attempt}"
        if attempt > 99:
          raise HTTPException(status_code=409, detail="username unavailable")
      # Auto-mint a placeholder argon2 hash if no password was passed
      # (auth_passwords is 1:1 with auth_users post-migration; without
      # a row the user has no path to log in, but that's fine for
      # admin-provisioned accounts).
      cur.execute(
        """
        INSERT INTO auth_users (username, primary_email, display_name, locale,
                                 is_admin, status)
        VALUES (%s, %s, %s, %s, %s, 'active')
        RETURNING id::text, username, primary_email, display_name, locale,
                  is_admin, status
        """,
        (candidate, email, req.display_name, locale, req.is_admin),
      )
      row = cur.fetchone()
      if req.password:
        cur.execute(
          "INSERT INTO auth_passwords (user_id, argon2_hash) VALUES (%s, %s)",
          (row["id"], hash_password(req.password)),
        )
    conn.commit()
  return {"user": _user_row_to_public(row)}


@app.get("/api/admin/users/{user_id}", dependencies=[Depends(require_admin)])
def admin_user_detail(user_id: str) -> dict:
  user_id = _require_uuid(user_id)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT id::text, username, primary_email, display_name, locale,
               is_admin, status, metadata, created_at,
               subscription_token, vless_uuid::text AS vless_uuid
        FROM auth_users WHERE id = %s
        """,
        (user_id,),
      )
      row = cur.fetchone()
      if row is None:
        raise HTTPException(status_code=404, detail="user not found")
  subs = _list_user_subscriptions(user_id)
  # Build the per-user subscription URL once and propagate it down to
  # each subscription entry too, so the operator UI can keep its
  # row-level "Open" / "Copy URL" buttons working without a separate
  # round-trip to /api/me. After the user-system unification one user
  # has one /sub URL aggregating all their active xout subs.
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  sub_url = (f"{base}/sub/{row['subscription_token']}"
             if row.get("subscription_token") else None)
  for s in subs:
    s["subscription_url"] = sub_url
  return {"user": row, "subscription_url": sub_url, "subscriptions": subs}


@app.post("/api/admin/users/{user_id}/grant", dependencies=[Depends(require_admin)])
def admin_grant_product(user_id: str, req: GrantRequest) -> dict:
  """Grant a product to a user.

  Post-2026-05-06 user-system unification: subscriptions no longer
  carry their own ``subscription_token`` -- the public /sub URL is
  per-user (built from auth_users.subscription_token), and one user
  has one URL aggregating every active xout sub. xout_node_users is
  also gone; the user's VLESS UUID is on auth_users and is used
  globally across nodes.
  """
  user_id = _require_uuid(user_id)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT id::text, subscription_token FROM auth_users WHERE id = %s",
        (user_id,),
      )
      user = cur.fetchone()
      if user is None:
        raise HTTPException(status_code=404, detail="user not found")
      cur.execute("SELECT id, kind, period_days FROM products WHERE code = %s",
                  (req.product_code,))
      product = cur.fetchone()
      if product is None:
        raise HTTPException(status_code=404,
                            detail=f"product not found: {req.product_code}")
      expires_at = req.expires_at
      if expires_at is None and product["kind"] == "period" and product["period_days"]:
        expires_at = datetime.now(timezone.utc) + timedelta(days=product["period_days"])
      try:
        cur.execute(
          """
          INSERT INTO subscriptions
            (user_id, product_id, status, starts_at, expires_at, source)
          VALUES (%s, %s, 'active', NOW(), %s, %s)
          RETURNING id, starts_at, expires_at
          """,
          (user_id, product["id"], expires_at, req.source),
        )
      except psycopg.errors.UniqueViolation as exc:
        # idx_subscriptions_one_active_per_user_product blocks duplicate
        # non-terminal subs for the same (user, product). Tell the
        # operator clearly so they don't refresh the form and try again.
        raise HTTPException(
          status_code=409,
          detail=(f"user already has an active or pending subscription to "
                  f"{req.product_code}; revoke it first to re-grant"),
        ) from exc
      sub = cur.fetchone()
    conn.commit()
  return {"subscription_id": sub["id"], "starts_at": sub["starts_at"],
          "expires_at": sub["expires_at"],
          # The user's per-user subscription token. Operator can paste
          # the resulting /sub/<token> URL into the SPA without a
          # separate round-trip.
          "subscription_token": user["subscription_token"]}


@app.post("/api/admin/users/{user_id}/revoke", dependencies=[Depends(require_admin)])
def admin_revoke_subscription(user_id: str, body: dict) -> dict:
  """Cancel an active subscription. Body: {product_code}.

  Marks the subscriptions row as 'canceled' (matching the DB CHECK
  constraint). xout's next active-users sync (≤30s) will pick up the
  state change and remove the user from xray. /sub/{token} starts
  returning 404 immediately.
  """
  user_id = _require_uuid(user_id)
  product_code = (body or {}).get("product_code") or ""
  if not product_code:
    raise HTTPException(status_code=400, detail="product_code is required")
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT id FROM products WHERE code = %s", (product_code,))
      product = cur.fetchone()
      if product is None:
        raise HTTPException(status_code=404,
                            detail=f"product not found: {product_code}")
      cur.execute(
        """
        UPDATE subscriptions
        SET status='canceled', updated_at=NOW()
        WHERE user_id=%s AND product_id=%s AND status='active'
        RETURNING id
        """,
        (user_id, product["id"]),
      )
      row = cur.fetchone()
    conn.commit()
  if row is None:
    raise HTTPException(status_code=404,
                        detail="no active subscription to revoke")
  return {"ok": True, "subscription_id": row["id"]}


@app.get("/api/admin/users/{user_id}/quotas", dependencies=[Depends(require_admin)])
def admin_user_quotas(user_id: str) -> dict:
  """Per-product quota state for one user, after lazy period reset."""
  user_id = _require_uuid(user_id)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT id::text FROM auth_users WHERE id = %s", (user_id,))
      if cur.fetchone() is None:
        raise HTTPException(status_code=404, detail="user not found")
  return {"quotas": _list_user_quotas(user_id)}


@app.post("/api/admin/users/{user_id}/quota", dependencies=[Depends(require_admin)])
def admin_upsert_quota(user_id: str, req: QuotaUpsertRequest) -> dict:
  """Set or update one quota row for (user, product). Reset_anchor_day
  is mandatory when reset_kind=monthly_anchor; for monthly_first we
  default it to 1; for never we store NULL.

  ``reset_consumption=True`` also zeroes the running counter — useful
  when an admin is lowering a limit and wants the user to have a clean
  period instead of being instantly over-quota.
  """
  user_id = _require_uuid(user_id)
  if req.reset_kind == "monthly_anchor" and req.reset_anchor_day is None:
    raise HTTPException(status_code=400,
                        detail="reset_anchor_day is required when reset_kind=monthly_anchor")
  # If the caller passed reset_anchor_day with a kind that doesn't use
  # it, drop it rather than store stale data.
  anchor = req.reset_anchor_day if req.reset_kind == "monthly_anchor" else (
    1 if req.reset_kind == "monthly_first" else None
  )
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT id::text FROM auth_users WHERE id = %s", (user_id,))
      if cur.fetchone() is None:
        raise HTTPException(status_code=404, detail="user not found")
      cur.execute("SELECT id FROM products WHERE code = %s", (req.product_code,))
      product = cur.fetchone()
      if product is None:
        raise HTTPException(status_code=404,
                            detail=f"product not found: {req.product_code}")
      # Initial / reset period start = the most recent period boundary,
      # not "right now". Otherwise a quota created on the 4th of a
      # monthly_first row reports "Period from 5/4" until the next 1st,
      # which doesn't match the user's mental model of a monthly cycle.
      now_utc = datetime.now(timezone.utc)
      initial_period_start = _next_period_start(req.reset_kind, anchor,
                                                  now_utc, now_utc)
      # Two SQL paths — with or without consumption reset. Branching is
      # clearer than building one mega-statement with conditional SET.
      if req.reset_consumption:
        cur.execute(
          """
          INSERT INTO usage_quotas
            (user_id, product_id, limit_qty, reset_kind, reset_anchor_day,
             current_period_start, current_period_consumed, updated_at)
          VALUES (%s, %s, %s, %s, %s, %s, 0, NOW())
          ON CONFLICT (user_id, product_id) DO UPDATE SET
            limit_qty = EXCLUDED.limit_qty,
            reset_kind = EXCLUDED.reset_kind,
            reset_anchor_day = EXCLUDED.reset_anchor_day,
            current_period_start = EXCLUDED.current_period_start,
            current_period_consumed = 0,
            updated_at = NOW()
          RETURNING user_id::text, product_id, limit_qty, reset_kind,
                    reset_anchor_day, current_period_start,
                    current_period_consumed
          """,
          (user_id, product["id"], req.limit_qty, req.reset_kind, anchor,
           initial_period_start),
        )
      else:
        cur.execute(
          """
          INSERT INTO usage_quotas
            (user_id, product_id, limit_qty, reset_kind, reset_anchor_day,
             current_period_start, current_period_consumed, updated_at)
          VALUES (%s, %s, %s, %s, %s, %s, 0, NOW())
          ON CONFLICT (user_id, product_id) DO UPDATE SET
            limit_qty = EXCLUDED.limit_qty,
            reset_kind = EXCLUDED.reset_kind,
            reset_anchor_day = EXCLUDED.reset_anchor_day,
            updated_at = NOW()
          RETURNING user_id::text, product_id, limit_qty, reset_kind,
                    reset_anchor_day, current_period_start,
                    current_period_consumed
          """,
          (user_id, product["id"], req.limit_qty, req.reset_kind, anchor,
           initial_period_start),
        )
      row = cur.fetchone()
    conn.commit()
  return {"quota": row}


@app.delete("/api/admin/users/{user_id}/quota/{product_code}",
             dependencies=[Depends(require_admin)])
def admin_delete_quota(user_id: str, product_code: str) -> dict:
  user_id = _require_uuid(user_id)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT id FROM products WHERE code = %s", (product_code,))
      product = cur.fetchone()
      if product is None:
        raise HTTPException(status_code=404,
                            detail=f"product not found: {product_code}")
      cur.execute(
        "DELETE FROM usage_quotas WHERE user_id = %s AND product_id = %s",
        (user_id, product["id"]),
      )
      n = cur.rowcount
    conn.commit()
  return {"deleted": n}


@app.post("/api/admin/users/{user_id}/admin")
def admin_toggle_admin(user_id: str, body: dict, caller: dict = Depends(require_admin)) -> dict:
  user_id = _require_uuid(user_id)
  is_admin = bool(body.get("is_admin", False))
  # Don't let an interactive admin demote themselves — they'd lock
  # themselves out and need DB access to recover. The service-token
  # path bypasses this guard since it's used by automated migration
  # tooling that may legitimately need to flip flags on any account.
  if not is_admin and caller.get("_via") != "service_token" and caller.get("id") == user_id:
    raise HTTPException(status_code=409,
                        detail="cannot demote yourself; ask another admin")
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "UPDATE auth_users SET is_admin = %s, updated_at = NOW() WHERE id = %s "
        "RETURNING id::text, is_admin",
        (is_admin, user_id),
      )
      row = cur.fetchone()
      if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    conn.commit()
  return row


@app.get("/api/admin/products", dependencies=[Depends(require_admin)])
def admin_list_products() -> dict:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT id, code, kind, price_cents, currency, period_days,
               stripe_price_id, name, description, metadata, active,
               service_code, created_at, updated_at
        FROM products ORDER BY service_code, id ASC
        """
      )
      rows = cur.fetchall()
  return {"products": rows}


@app.post("/api/admin/products", dependencies=[Depends(require_admin)])
def admin_create_product(req: ProductCreateRequest) -> dict:
  # service_code is always non-empty: _validate_service_code infers from
  # the code prefix when the caller omits it. Just use it directly.
  service_code = req.service_code
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        INSERT INTO products
          (code, kind, price_cents, currency, period_days, stripe_price_id,
           name, description, metadata, active, service_code)
        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s)
        RETURNING id, code, kind, price_cents, currency, period_days,
                  stripe_price_id, name, description, metadata, active, service_code
        """,
        (req.code, req.kind, req.price_cents, req.currency, req.period_days,
         req.stripe_price_id, _to_jsonb(req.name), _to_jsonb(req.description),
         _to_jsonb(req.metadata), req.active, service_code),
      )
      row = cur.fetchone()
    conn.commit()
  return {"product": row}


# ---------------------------------------------------------------------------
# Billing admin (model_pricing CRUD + global settings).  Surfaces in the
# ssl-service admin SPA via /api/user-service/billing/* proxy routes.
# ---------------------------------------------------------------------------


class ModelPricingUpsertRequest(BaseModel):
  model_id: str = Field(min_length=1, max_length=120)
  display_name: dict | None = None
  pricing_kind: str = Field(default="tokens")
  modality: str = Field(default="text")
  input_rate_micros: int | None = None
  cached_input_rate_micros: int | None = None
  output_rate_micros: int | None = None
  per_unit_micros: int | None = None
  per_unit_label: str | None = None
  active: bool = True
  notes: str | None = None
  source_url: str | None = None


@app.get("/api/admin/billing/pricing", dependencies=[Depends(require_admin)])
def admin_billing_pricing_list() -> dict:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT id, model_id, display_name, pricing_kind, modality,
               input_rate_micros, cached_input_rate_micros, output_rate_micros,
               per_unit_micros, per_unit_label, active, notes, source_url,
               updated_by_admin, updated_at
        FROM model_pricing
        ORDER BY active DESC, modality, model_id
        """
      )
      rows = cur.fetchall()
  return {"models": rows}


@app.post("/api/admin/billing/pricing", dependencies=[Depends(require_admin)])
def admin_billing_pricing_upsert(req: ModelPricingUpsertRequest,
                                  caller: dict = Depends(require_admin)) -> dict:
  who = caller.get("email") if isinstance(caller, dict) else None
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        INSERT INTO model_pricing(model_id, display_name, pricing_kind, modality,
            input_rate_micros, cached_input_rate_micros, output_rate_micros,
            per_unit_micros, per_unit_label, active, notes, source_url,
            updated_by_admin, updated_at)
        VALUES (%s, %s::jsonb, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (model_id) DO UPDATE SET
            display_name = EXCLUDED.display_name,
            pricing_kind = EXCLUDED.pricing_kind,
            modality = EXCLUDED.modality,
            input_rate_micros = EXCLUDED.input_rate_micros,
            cached_input_rate_micros = EXCLUDED.cached_input_rate_micros,
            output_rate_micros = EXCLUDED.output_rate_micros,
            per_unit_micros = EXCLUDED.per_unit_micros,
            per_unit_label = EXCLUDED.per_unit_label,
            active = EXCLUDED.active,
            notes = EXCLUDED.notes,
            source_url = EXCLUDED.source_url,
            updated_by_admin = EXCLUDED.updated_by_admin,
            updated_at = NOW()
        RETURNING id, model_id, display_name, pricing_kind, modality,
                  input_rate_micros, cached_input_rate_micros, output_rate_micros,
                  per_unit_micros, per_unit_label, active, notes, source_url,
                  updated_by_admin, updated_at
        """,
        (req.model_id, _to_jsonb(req.display_name or {}), req.pricing_kind,
         req.modality, req.input_rate_micros, req.cached_input_rate_micros,
         req.output_rate_micros, req.per_unit_micros, req.per_unit_label,
         req.active, req.notes, req.source_url, who),
      )
      row = cur.fetchone()
    conn.commit()
  return {"model": row}


@app.delete("/api/admin/billing/pricing/{pricing_id}",
            dependencies=[Depends(require_admin)])
def admin_billing_pricing_delete(pricing_id: int) -> dict:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("DELETE FROM model_pricing WHERE id = %s", (pricing_id,))
      if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="model_pricing row not found")
    conn.commit()
  return {"ok": True}


class BillingSettingsRequest(BaseModel):
  discount_factor: float | None = Field(default=None, ge=0, le=2)


@app.get("/api/admin/billing/settings", dependencies=[Depends(require_admin)])
def admin_billing_settings_get() -> dict:
  cfg = _get_system_config("billing.discount_factor")
  v = cfg.get("value", 0.8) if isinstance(cfg, dict) else 0.8
  return {"discount_factor": float(v)}


@app.put("/api/admin/billing/settings", dependencies=[Depends(require_admin)])
def admin_billing_settings_put(req: BillingSettingsRequest) -> dict:
  if req.discount_factor is None:
    raise HTTPException(status_code=400, detail="discount_factor required")
  import json as _json
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        INSERT INTO system_config(key, value, updated_at)
        VALUES ('billing.discount_factor', %s::jsonb, NOW())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        """,
        (_json.dumps({"value": float(req.discount_factor)}),),
      )
    conn.commit()
  return {"discount_factor": float(req.discount_factor)}


@app.get("/api/admin/billing/tiers", dependencies=[Depends(require_admin)])
def admin_billing_tiers_list() -> dict:
  """Return the tier_* products sorted by tier_rank (Free first)."""
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT id, code, kind, price_cents, currency, period_days,
               stripe_price_id, name, description, metadata, active
        FROM products
        WHERE code LIKE 'tier_%'
        ORDER BY COALESCE((metadata->>'tier_rank')::int, 0)
        """
      )
      rows = cur.fetchall()
  return {"tiers": rows}


@app.patch("/api/admin/products/{product_id}", dependencies=[Depends(require_admin)])
def admin_patch_product(product_id: int, req: ProductPatchRequest) -> dict:
  """Edit a generic product. Use admin_patch_xout_product for xout-specific
  fields (inbound_selector). Code and id are immutable -- delete + recreate
  if you need to rename."""
  _PATCHABLE = frozenset({
    "kind", "price_cents", "currency", "period_days", "stripe_price_id",
    "name", "description", "metadata", "active", "service_code",
  })
  _JSONB_FIELDS = frozenset({"name", "description", "metadata"})
  fields: list[tuple[str, Any]] = []
  data = req.model_dump(exclude_unset=True)
  for k, v in data.items():
    if k not in _PATCHABLE:
      continue  # silently skip unknown/non-patchable keys
    if k in _JSONB_FIELDS:
      fields.append((k, _to_jsonb(v)))
    else:
      fields.append((k, v))
  if not fields:
    return admin_list_products()  # nothing to do; return current state
  set_clause = ", ".join(
    f"{k} = %s::jsonb" if k in _JSONB_FIELDS else f"{k} = %s"
    for k, _ in fields
  )
  params = [v for _, v in fields] + [product_id]
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        f"""
        UPDATE products SET {set_clause}, updated_at = NOW()
        WHERE id = %s
        RETURNING id, code, kind, price_cents, currency, period_days,
                  stripe_price_id, name, description, metadata, active, service_code
        """,
        params,
      )
      row = cur.fetchone()
      if row is None:
        raise HTTPException(status_code=404, detail="product not found")
    conn.commit()
  return {"product": row}


@app.delete("/api/admin/products/{product_id}",
             dependencies=[Depends(require_admin)])
def admin_delete_product(product_id: int) -> dict:
  """Hard-delete a product. Refuses when any non-terminal subscription
  references it -- the operator must cancel those first. Canceled /
  expired sub rows are also cleaned up (subscriptions.product_id has
  ON DELETE RESTRICT, so we have to remove them before deleting the
  product). Payments / usage_events use ON DELETE SET NULL so their
  history is preserved with a NULL product_id."""
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT COUNT(*) AS n FROM subscriptions "
        " WHERE product_id = %s AND status IN ('active', 'pending', 'over_quota')",
        (product_id,),
      )
      n = (cur.fetchone() or {}).get("n", 0)
      if n and n > 0:
        raise HTTPException(
          status_code=409,
          detail=f"product has {n} active or pending subscription(s); cancel them first",
        )
      # Remove canceled/expired sub rows (FK ON DELETE RESTRICT would
      # otherwise block the product DELETE).
      cur.execute(
        "DELETE FROM subscriptions WHERE product_id = %s "
        " AND status IN ('canceled', 'expired')",
        (product_id,),
      )
      cur.execute("DELETE FROM products WHERE id = %s RETURNING id", (product_id,))
      row = cur.fetchone()
    conn.commit()
  if row is None:
    raise HTTPException(status_code=404, detail="product not found")
  return {"deleted": True, "id": row["id"]}


@app.get("/api/admin/orders", dependencies=[Depends(require_admin)])
def admin_list_orders(
  user_id: str | None = None,
  product_code: str | None = None,
  status: str | None = None,
  limit: int = 100,
  offset: int = 0,
) -> dict:
  """Browse the payments + subscriptions ledger.

  Joined view: each payment row carries the user (email + username),
  the product (code + name), the subscription (id + status if any),
  amount, currency, status, and Stripe identifiers. Optional filters
  for the operator's audit workflows.
  """
  limit = max(1, min(int(limit or 100), 500))
  offset = max(0, int(offset or 0))
  conds: list[str] = []
  params: list[Any] = []
  if user_id:
    conds.append("p.user_id = %s::uuid")
    params.append(user_id)
  if product_code:
    conds.append("pr.code = %s")
    params.append(product_code)
  if status:
    conds.append("p.status = %s")
    params.append(status)
  where = ("WHERE " + " AND ".join(conds)) if conds else ""
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        f"""
        SELECT p.id, p.user_id::text AS user_id,
               u.username, u.primary_email,
               p.product_id, pr.code AS product_code, pr.name AS product_name,
               p.amount_cents, p.currency, p.status,
               p.stripe_payment_intent_id, p.stripe_event_id,
               p.created_at, p.metadata,
               (SELECT s.id FROM subscriptions s
                 WHERE s.user_id = p.user_id AND s.product_id = p.product_id
                 ORDER BY s.starts_at DESC LIMIT 1) AS subscription_id,
               (SELECT s.status FROM subscriptions s
                 WHERE s.user_id = p.user_id AND s.product_id = p.product_id
                 ORDER BY s.starts_at DESC LIMIT 1) AS subscription_status,
               (SELECT s.expires_at FROM subscriptions s
                 WHERE s.user_id = p.user_id AND s.product_id = p.product_id
                 ORDER BY s.starts_at DESC LIMIT 1) AS subscription_expires_at
          FROM payments p
          LEFT JOIN auth_users u ON u.id = p.user_id
          LEFT JOIN products pr ON pr.id = p.product_id
          {where}
         ORDER BY p.created_at DESC
         LIMIT %s OFFSET %s
        """,
        (*params, limit, offset),
      )
      rows = cur.fetchall()
      cur.execute(
        f"SELECT COUNT(*) AS n FROM payments p"
        f" LEFT JOIN auth_users u ON u.id = p.user_id"
        f" LEFT JOIN products pr ON pr.id = p.product_id {where}",
        params,
      )
      total = (cur.fetchone() or {}).get("n", 0)
  return {"orders": rows, "total": total, "limit": limit, "offset": offset}


@app.get("/api/admin/users/{user_id}/payments", dependencies=[Depends(require_admin)])
def admin_user_payments(user_id: str) -> dict:
  """Per-user payment history -- shown on the admin user-detail page so
  operators can quickly answer "what has this user paid for?" """
  user_id = _require_uuid(user_id)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT p.id, p.product_id, pr.code AS product_code, pr.name AS product_name,
               p.amount_cents, p.currency, p.status,
               p.stripe_payment_intent_id, p.stripe_event_id,
               p.created_at, p.metadata
          FROM payments p
          LEFT JOIN products pr ON pr.id = p.product_id
         WHERE p.user_id = %s::uuid
         ORDER BY p.created_at DESC
        """,
        (user_id,),
      )
      rows = cur.fetchall()
  return {"payments": rows}


# ---------------------------------------------------------------------------
# Xout product management — admin endpoints
# ---------------------------------------------------------------------------


class XoutNodeSelector(BaseModel):
  name: str
  tags: list[str] = Field(default_factory=lambda: ["*"])


class XoutProductCreateRequest(BaseModel):
  code: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,40}$")
  kind: str = Field(default="period", pattern=r"^(one_time|recurring|period)$")
  price_cents: int = Field(default=0, ge=0, le=100_000_000)
  currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
  period_days: int | None = Field(default=30, ge=1, le=3650)
  name: dict[str, str] = Field(default_factory=dict)
  description: dict[str, str] = Field(default_factory=dict)
  metadata: dict[str, Any] = Field(default_factory=dict)
  active: bool = True
  # Per-product node/inbound visibility.
  inbound_selector: dict[str, Any] = Field(default_factory=lambda: {"version": 1, "nodes": []})


class XoutProductPatchRequest(BaseModel):
  # ``kind`` and ``currency`` are accepted (admin SPA's edit form sends
  # them on every save). Without them in the model, pydantic silently
  # dropped the values and the operator's edits looked like they
  # saved but never reached the DB. Mirrors the shape of
  # ``ProductPatchRequest`` so non-xout vs xout patch surfaces are
  # consistent.
  kind: str | None = Field(default=None, pattern=r"^(one_time|recurring|period)$")
  price_cents: int | None = Field(default=None, ge=0, le=100_000_000)
  currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
  period_days: int | None = Field(default=None, ge=1, le=3650)
  name: dict[str, str] | None = None
  description: dict[str, str] | None = None
  active: bool | None = None
  inbound_selector: dict[str, Any] | None = None


@app.get("/api/admin/xout/inbounds", dependencies=[Depends(require_admin)])
def admin_list_xout_inbounds() -> dict:
  """Return all (node, inbound) pairs visible from the current preset
  assignments. Admin uses this to build the inbound_selector in the
  xout-product editor.
  """
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT a.node_name, p.id AS preset_id, p.name AS preset_name,
               p.inbounds, n.host AS node_host
        FROM xout_node_assignments a
        JOIN xout_presets p ON p.id = a.preset_id
        LEFT JOIN nodes n ON n.name = a.node_name
        ORDER BY a.node_name
        """
      )
      rows = cur.fetchall()
  out = []
  for r in rows:
    inbounds = []
    for ib in (r["inbounds"] or []):
      tag = (ib.get("tag") or "").replace("{node_name}", r["node_name"])
      proto = (ib.get("protocol") or "").lower()
      inbounds.append({
        "tag": tag,
        "port": ib.get("port"),
        "protocol": proto,
        # Only vless inbounds produce user-facing subscription URIs.
        # The SPA dims/disables non-vless rows in the picker so the
        # operator doesn't pick a socks chain (silently dropped from
        # /sub) by mistake.
        "is_user_facing": proto == "vless",
      })
    out.append({
      "node_name": r["node_name"],
      "node_host": r["node_host"],
      "preset_name": r["preset_name"],
      "inbounds": inbounds,
    })
  return {"nodes": out}


@app.get("/api/admin/xout/products", dependencies=[Depends(require_admin)])
def admin_list_xout_products() -> dict:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT p.id, p.code, p.kind, p.price_cents, p.currency, p.period_days,
               p.name, p.description, p.metadata, p.active, p.created_at,
               xp.inbound_selector, xp.metadata AS xout_metadata,
               (SELECT COUNT(*) FROM subscriptions s
                WHERE s.product_id = p.id AND s.status='active') AS subscriber_count
        FROM products p
        JOIN xout_products xp ON xp.product_id = p.id
        ORDER BY p.id
        """
      )
      rows = cur.fetchall()
  return {"products": rows}


@app.post("/api/admin/xout/products", dependencies=[Depends(require_admin)])
def admin_create_xout_product(req: XoutProductCreateRequest) -> dict:
  _validate_xout_selector(req.inbound_selector)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT 1 FROM products WHERE code = %s", (req.code,))
      if cur.fetchone() is not None:
        raise HTTPException(status_code=409, detail=f"product code already taken: {req.code}")
      cur.execute(
        """
        INSERT INTO products
          (code, kind, price_cents, currency, period_days,
           name, description, metadata, active, service_code)
        VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, 'xout')
        RETURNING id, code, kind, price_cents, currency, period_days,
                  name, description, metadata, active, service_code, created_at
        """,
        (req.code, req.kind, req.price_cents, req.currency, req.period_days,
         _to_jsonb({**req.name, **{}} if req.name else {}),
         _to_jsonb(req.description or {}),
         _to_jsonb({**(req.metadata or {}), "kind": "xout"}),
         req.active),
      )
      product = cur.fetchone()
      cur.execute(
        """
        INSERT INTO xout_products (product_id, inbound_selector, metadata)
        VALUES (%s, %s::jsonb, '{}'::jsonb)
        RETURNING product_id, inbound_selector
        """,
        (product["id"], _to_jsonb(req.inbound_selector or {})),
      )
      xp = cur.fetchone()
    conn.commit()
  return {"product": {**product, "inbound_selector": xp["inbound_selector"]}}


@app.patch("/api/admin/xout/products/{product_id}", dependencies=[Depends(require_admin)])
def admin_patch_xout_product(product_id: int, req: XoutProductPatchRequest) -> dict:
  if req.inbound_selector is not None:
    _validate_xout_selector(req.inbound_selector)
  prod_fields: list[str] = []
  prod_params: list[Any] = []
  for k in ("kind", "currency", "price_cents", "period_days", "active"):
    v = getattr(req, k, None)
    if v is not None:
      prod_fields.append(f"{k} = %s")
      prod_params.append(v)
  for k in ("name", "description"):
    v = getattr(req, k, None)
    if v is not None:
      prod_fields.append(f"{k} = %s::jsonb")
      prod_params.append(_to_jsonb(v))
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT 1 FROM xout_products WHERE product_id = %s", (product_id,))
      if cur.fetchone() is None:
        raise HTTPException(status_code=404, detail="xout product not found")
      if prod_fields:
        prod_fields.append("updated_at = NOW()")
        prod_params.append(product_id)
        cur.execute(
          f"UPDATE products SET {', '.join(prod_fields)} WHERE id = %s",
          prod_params,
        )
      if req.inbound_selector is not None:
        cur.execute(
          "UPDATE xout_products SET inbound_selector = %s::jsonb, updated_at = NOW() WHERE product_id = %s",
          (_to_jsonb(req.inbound_selector), product_id),
        )
      cur.execute(
        """
        SELECT p.id, p.code, p.kind, p.price_cents, p.currency, p.period_days,
               p.name, p.description, p.metadata, p.active, p.updated_at,
               xp.inbound_selector
        FROM products p JOIN xout_products xp ON xp.product_id = p.id
        WHERE p.id = %s
        """,
        (product_id,),
      )
      row = cur.fetchone()
    conn.commit()
  return {"product": row}


@app.delete("/api/admin/xout/products/{product_id}",
             dependencies=[Depends(require_admin)])
def admin_delete_xout_product(product_id: int) -> dict:
  """Delete an xout product entirely.

  Refuses if any *active* subscription still references this product —
  those are real customers we'd silently break. Historical subscriptions
  (canceled/expired) are wiped along with the product so cleanup of
  test data is one click instead of multiple manual steps.

  The product row also goes, leaving usage_events / usage_quotas
  orphaned (their product_id is dead). That's intentional: those tables
  are append-only audit logs; dropping the product just means they no
  longer JOIN to anything, which is fine for analytics.
  """
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT id, code FROM products WHERE id = %s", (product_id,))
      prod = cur.fetchone()
      if prod is None:
        raise HTTPException(status_code=404, detail="product not found")
      cur.execute(
        "SELECT count(*) AS n FROM subscriptions "
        " WHERE product_id = %s AND status IN ('active', 'pending', 'over_quota')",
        (product_id,),
      )
      active_n = (cur.fetchone() or {}).get("n", 0)
      if active_n:
        raise HTTPException(
          status_code=409,
          detail=(f"product '{prod['code']}' has {active_n} non-terminal "
                  f"subscription(s); cancel them first, or just set "
                  f"the product inactive instead of deleting it"),
        )
      # FK order: subscriptions/usage_quotas → product.id, so wipe
      # those first. usage_events also FK; we delete them too.
      cur.execute("DELETE FROM usage_events WHERE product_id = %s",
                  (product_id,))
      cur.execute("DELETE FROM usage_quotas WHERE product_id = %s",
                  (product_id,))
      cur.execute("DELETE FROM subscriptions WHERE product_id = %s",
                  (product_id,))
      cur.execute("DELETE FROM xout_products WHERE product_id = %s",
                  (product_id,))
      cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
    conn.commit()
  return {"ok": True, "deleted": prod["code"]}


# ---------------------------------------------------------------------------
# Public subscription URL — /sub/{token}
# Token IS the auth. No cookie / X-Service-Token. Format defaults to
# base64 (the v2rayN / Streisand format) or ?format=raw for plain
# newline-separated URIs (for client apps that prefer that).
# ---------------------------------------------------------------------------


@app.get("/sub-qr/{token}.svg")
def subscription_qr(token: str, size: int = 196) -> Response:
  """SVG QR code for the subscription URL. The SPA links to this from
  the My Account page so users can scan it with v2rayN / Streisand /
  etc. Token presence is verified but the QR encodes the *URL* (not
  raw subscription content) — so leaking the QR is no worse than
  leaking the URL.
  """
  if not token or not _looks_like_token(token):
    raise HTTPException(status_code=404, detail="not found")
  size = max(64, min(512, size))
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT 1 FROM auth_users "
        " WHERE subscription_token = %s AND status = 'active'",
        (token,),
      )
      if cur.fetchone() is None:
        raise HTTPException(status_code=404, detail="not found")
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  url = f"{base}/sub/{token}"
  try:
    import segno
    qr = segno.make(url, error="m")
    # segno renders at scale=N → each module is N pixels. Compute scale
    # from the desired size + the QR's module count (including border)
    # so we end up close to ``size`` pixels rather than wildly off.
    border = 2
    modules_with_border = qr.symbol_size(border=border)[0]
    scale = max(1, round(size / max(1, modules_with_border)))
    import io
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=scale, border=border,
            light="#ffffff", dark="#0f0f0f")
    return Response(content=buf.getvalue(),
                    media_type="image/svg+xml",
                    headers={"Cache-Control": "private, max-age=60"})
  except Exception:  # noqa: BLE001
    LOGGER.exception("QR rendering failed")
    raise HTTPException(status_code=500, detail="qr render failed")


@app.get("/sub/{token}")
def subscription(token: str, format: str = "base64", request: Request = None) -> Response:
  """Public, token-gated subscription endpoint.

  Post-2026-05-06 user-system unification: ``token`` is the user's
  ``auth_users.subscription_token`` -- one URL per user, never per
  subscription. The response aggregates VLESS URIs from EVERY active
  xout subscription that user holds. Buying / cancelling a product
  changes the URL's content; the URL itself never rotates unless the
  operator manually rolls the user's subscription_token.
  """
  if not token or len(token) > 200 or not _looks_like_token(token):
    raise HTTPException(status_code=404, detail="not found")
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT id::text AS user_id, username, status
        FROM auth_users WHERE subscription_token = %s
        """,
        (token,),
      )
      row = cur.fetchone()
  # Missing token, disabled / deleted user → 404 (uniform error so an
  # attacker can't tell which state they hit).
  if row is None or row["status"] != "active":
    raise HTTPException(status_code=404, detail="not found")
  user_id = row["user_id"]

  # Build the inbound list across every active xout sub the user holds.
  subs = _user_xout_subscriptions(user_id)
  if not subs:
    # No active xout subs (none ever granted, all canceled, all
    # expired). Same 404 as a bad token to avoid information leakage.
    raise HTTPException(status_code=404, detail="not found")

  # Accumulate inbounds across every sub that's still under quota. If
  # every active sub is over quota, return 410 Gone so client
  # subscription updaters know to back off rather than spam the
  # endpoint. Single DB pass: _ensure_quota_period may roll the
  # period_start, so we only want to call it once per sub.
  all_inbounds: list[dict] = []
  primary_product_id: int | None = None
  # Dedup keyed by (node, tag, port) so two products that overlap on
  # the same physical inbound don't produce two identical VLESS URIs
  # in the bundle.
  seen: set[tuple] = set()
  with connect() as conn:
    with conn.cursor() as cur:
      for s in subs:
        q = _ensure_quota_period(cur, user_id, s["product_id"])
        over_quota = (q is not None and q.get("limit_qty")
                      and float(q["current_period_consumed"])
                      >= float(q["limit_qty"]))
        if over_quota:
          continue
        if primary_product_id is None:
          primary_product_id = s["product_id"]
        for ib in s["inbounds"]:
          key = (ib.get("node_name"), ib.get("tag"), ib.get("port"))
          if key in seen:
            continue
          seen.add(key)
          all_inbounds.append(ib)
    conn.commit()
  if primary_product_id is None:
    raise HTTPException(status_code=410,
                        detail="quota exceeded for current period")

  uris = _build_subscription_uris(user_id, 0, all_inbounds)
  body = "\n".join(uris).encode("utf-8")
  # CORS: /sub/{token} is a public, token-gated endpoint. Allowing
  # cross-origin reads lets the operator's admin SPA fetch + preview
  # content from a different origin without server-side proxying.
  base_headers = {"Cache-Control": "no-store",
                  "Access-Control-Allow-Origin": "*",
                  "Access-Control-Expose-Headers":
                    "Subscription-Userinfo, Content-Disposition, "
                    "profile-update-interval"}
  # filename hint — Clash GUI clients display this as the subscription
  # name. Pick the username so the operator sees who the sub is for;
  # if multiple products are aggregated this is more meaningful than
  # any single product code.
  fname = (row.get("username") or "subscription").replace('"', "")
  if format == "raw":
    return Response(content=body,
                    media_type="text/plain; charset=utf-8",
                    headers=base_headers)
  if format in ("clash", "yaml"):
    yaml_text = _build_clash_yaml(all_inbounds)
    # profile-update-interval (hours) tells Clash clients how often to
    # auto-refresh the sub. 24h is the convention.
    return Response(content=yaml_text.encode("utf-8"),
                    media_type="text/yaml; charset=utf-8",
                    headers={**base_headers,
                             "Content-Disposition":
                               f'attachment; filename="{fname}"',
                             "profile-update-interval": "24",
                             "Subscription-Userinfo":
                               _build_userinfo_header(user_id, primary_product_id)})
  # Default: base64 (newline-separated URIs, then the whole thing
  # base64-encoded). v2rayN / Streisand / Shadowrocket all expect this.
  import base64 as _b64
  encoded = _b64.b64encode(body).decode("ascii")
  return Response(content=encoded,
                  media_type="text/plain; charset=utf-8",
                  headers={**base_headers,
                           "Content-Disposition":
                             f'attachment; filename="{fname}"',
                           "profile-update-interval": "24",
                           "Subscription-Userinfo":
                             _build_userinfo_header(user_id, primary_product_id)})


_TOKEN_RE = None
def _looks_like_token(s: str) -> bool:
  # urlsafe base64 alphabet, length matches secrets.token_urlsafe(24)+ — 32 chars
  # of entropy at minimum to dodge brute-force scans.
  global _TOKEN_RE
  if _TOKEN_RE is None:
    import re
    _TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}={0,2}$")
  return bool(s) and bool(_TOKEN_RE.match(s))


def _build_userinfo_header(user_id: str, product_id: int) -> str:
  """Build the ``Subscription-Userinfo`` header that some clients show
  as quota/expiry. Format: ``upload=N; download=N; total=N; expire=N``
  (epoch seconds).
  """
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT limit_qty, current_period_consumed FROM usage_quotas
        WHERE user_id = %s AND product_id = %s
        """,
        (user_id, product_id),
      )
      q = cur.fetchone()
      cur.execute(
        "SELECT expires_at FROM subscriptions WHERE user_id = %s AND product_id = %s AND status='active'",
        (user_id, product_id),
      )
      sub = cur.fetchone()
  # Always emit a header — clients display it as "X / Y GB"; emitting
  # only when q exists would let an attacker distinguish "user has
  # quota record" vs "no record" via header presence alone.
  consumed = float((q or {}).get("current_period_consumed") or 0)
  limit = float((q or {}).get("limit_qty") or 0)
  # We track GB; subscription-userinfo uses bytes.
  consumed_bytes = int(consumed * (1 << 30))
  total_bytes = int(limit * (1 << 30)) if limit > 0 else 0
  parts = [f"upload=0", f"download={consumed_bytes}", f"total={total_bytes}"]
  if sub and sub["expires_at"]:
    parts.append(f"expire={int(sub['expires_at'].timestamp())}")
  return "; ".join(parts)


# ---------------------------------------------------------------------------
# /api/internal/xout/* endpoints removed in the xout-merge refactor.
# xout now reads from auth_users + subscriptions + xout_products and
# writes to usage_events / usage_quotas / xout_node_inbounds directly;
# user-service no longer proxies for it.
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# system_config helpers — read /api/internal-style settings the operator
# stores via the ssl-service admin Settings page.
# ---------------------------------------------------------------------------


def _get_system_config(key: str) -> dict:
  """Return the raw JSONB value for ``key`` or {} if missing.

  ssl-service writes these via PUT /api/system-config/{key}; we read
  here so user-service stays the only writer of business data while
  still picking up operator-tunable knobs out of the same DB.
  """
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT value FROM system_config WHERE key = %s", (key,))
      row = cur.fetchone()
  if row is None:
    return {}
  v = row["value"]
  return v if isinstance(v, dict) else {}


# ---------------------------------------------------------------------------
# P4: Stripe checkout — buy paid products end-to-end.
#   1. POST /api/checkout/create-session   (cookie auth, body: product_code)
#      → returns {"url": "https://checkout.stripe.com/..."}
#   2. User completes payment on Stripe.
#   3. Stripe → POST /api/stripe/webhook   (X-Stripe-Signature header)
#      → on `checkout.session.completed` we look up the session metadata,
#        INSERT a payments row + a subscriptions row (idempotent via the
#        unique index on stripe_event_id).
#
# The operator configures stripe.api_key (sk_test_… or sk_live_…) and
# stripe.webhook_secret via ssl-service admin Settings.
# ---------------------------------------------------------------------------


class CheckoutSessionRequest(BaseModel):
  # New offer-based model: caller picks a (product_code, duration_months)
  # pair from the catalog. Server resolves to the matching product_offers
  # row + its stripe_price_id. Legacy `product_code`-only callers (which
  # implicitly mean "the 1-month price") still work via the fallback at
  # the bottom of the resolver.
  product_code: str
  duration_months: int | None = None
  # Optional override URLs the SPA can pass; default to PUBLIC_URL paths.
  success_url: str | None = None
  cancel_url: str | None = None


def _stripe_client():
  """Return a configured stripe client or raise 503."""
  cfg = _get_system_config("stripe.api_key")
  api_key = (cfg.get("key") or cfg.get("api_key") or "").strip()
  if not api_key:
    raise HTTPException(status_code=503,
                        detail="Stripe is not configured (system_config['stripe.api_key'])")
  import stripe as _stripe
  _stripe.api_key = api_key
  return _stripe


@app.post("/api/checkout/create-session")
def create_checkout_session(req: CheckoutSessionRequest,
                              user: dict = Depends(get_current_user),
                              request: Request = None) -> dict:
  duration_months = req.duration_months or 1
  # Compute the upgrade credit using the SAME helper as the preview
  # endpoint. If the user opens the upgrade dialog (which calls
  # /api/me/checkout-preview) and then clicks buy a few seconds later,
  # the credit they see is the credit they pay — there's no
  # round-trip race.
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT p.id AS product_id, p.code, p.name, p.service_code, p.currency,
               COALESCE((p.metadata->>'tier_rank')::int, -1) AS tier_rank,
               o.id AS offer_id, o.duration_months, o.price_cents,
               o.discount_pct, o.stripe_price_id
        FROM product_offers o
        JOIN products p ON p.id = o.product_id
        WHERE p.code = %s
          AND p.active = TRUE
          AND o.active = TRUE
          AND o.duration_months = %s
        """,
        (req.product_code, duration_months),
      )
      offer = cur.fetchone()
      if offer is None:
        raise HTTPException(
          status_code=404,
          detail=f"offer not found: {req.product_code} × {duration_months}mo",
        )
      credit_info = _compute_upgrade_credit(
        cur,
        user_id=str(user["id"]),
        target_product_id=int(offer["product_id"]),
        target_service_code=offer["service_code"],
        target_tier_rank=int(offer["tier_rank"]),
      )
  base_price_cents = int(offer["price_cents"])
  credit_cents = min(int(credit_info["credit_cents"]), base_price_cents)
  final_price_cents = base_price_cents - credit_cents
  # No 409 on existing-active sub: under the one-time + duration model the
  # user is *allowed* to top up; the webhook stacks duration_months onto
  # the existing expires_at. This is the whole point of multi-month buys
  # alongside an active sub (early renewal at the discounted bulk price).
  stripe = _stripe_client()
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  success_url = req.success_url or f"{base}/?checkout=success"
  cancel_url = req.cancel_url or f"{base}/?checkout=cancel"
  # Two paths for line_items:
  #   - No credit: use the existing stripe_price_id (cheaper UX for
  #     Stripe's reporting/coupons, and matches what we've always done).
  #   - With credit: dynamic price_data so the user is charged the
  #     prorated final_price_cents. Stripe doesn't permit "discounts"
  #     on top of a custom price_data line item, so the credit is folded
  #     directly into unit_amount; the UI presents the breakdown.
  base_metadata = {
    "user_id": str(user["id"]),
    "product_id": str(offer["product_id"]),
    "product_code": offer["code"],
    "offer_id": str(offer["offer_id"]),
    "duration_months": str(offer["duration_months"]),
    "discount_pct": str(offer["discount_pct"]),
  }
  if credit_cents > 0:
    if not offer["stripe_price_id"]:
      # We still want a sensible product_data.name for the Stripe-
      # hosted checkout page when no canonical product mapping exists.
      product_name_for_stripe = offer["code"]
    else:
      # Pull the original Stripe Product name so the checkout page
      # shows e.g. "Develop · Chat Pro" — same string the fixed-price
      # path would show. Best-effort; on failure we fall back to code.
      product_name_for_stripe = offer["code"]
      try:
        stripe_price = stripe.Price.retrieve(offer["stripe_price_id"], expand=["product"])
        if stripe_price and getattr(stripe_price, "product", None):
          product_name_for_stripe = stripe_price.product.name or offer["code"]
      except Exception:
        # Don't block checkout if the lookup fails; just use the code.
        pass
    line_items = [{
      "price_data": {
        "currency": (offer.get("currency") or "USD").lower(),
        "unit_amount": final_price_cents,
        "product_data": {"name": product_name_for_stripe},
      },
      "quantity": 1,
    }]
    base_metadata["credit_applied_cents"] = str(credit_cents)
    base_metadata["credit_source_sub_ids"] = ",".join(
      str(s["sub_id"]) for s in credit_info["source_subs"]
    )
    base_metadata["base_price_cents"] = str(base_price_cents)
  else:
    if not offer["stripe_price_id"]:
      raise HTTPException(
        status_code=400,
        detail="offer has no stripe_price_id — re-run the Stripe catalog sync",
      )
    line_items = [{"price": offer["stripe_price_id"], "quantity": 1}]
  try:
    session = stripe.checkout.Session.create(
      # Always one-time payment now — we no longer use Stripe subscriptions
      # at all. The "subscription" inside our system is just a row whose
      # expires_at gets pushed forward on each successful payment.
      mode="payment",
      # Explicit method allowlist so Chinese users see the Alipay tile on
      # the Stripe-hosted checkout — our products are USD-priced and the
      # paid_tier dialog promises "USD payments also support Alipay".
      # Card stays first so non-CN users default to it.
      payment_method_types=["card", "alipay"],
      line_items=line_items,
      success_url=success_url,
      cancel_url=cancel_url,
      client_reference_id=str(user["id"]),
      customer_email=user.get("primary_email") or None,
      # Stripe copies session.metadata onto the payment_intent (and
      # therefore the webhook). Carry everything the webhook needs to
      # locate the right (user, product, offer) tuple without re-querying.
      metadata=base_metadata,
      # Allow promo codes the user enters on Stripe Checkout. We don't
      # mint them — operators create coupons in the dashboard.
      # Disable promo codes when we've already applied an upgrade
      # credit — Stripe rejects coupons on top of dynamic price_data.
      allow_promotion_codes=(credit_cents == 0),
    )
  except Exception as exc:  # noqa: BLE001
    LOGGER.exception("stripe.checkout.session create failed")
    raise HTTPException(status_code=502, detail=f"stripe error: {exc}")
  return {
    "url": session.url,
    "session_id": session.id,
    "base_price_cents": base_price_cents,
    "credit_cents": credit_cents,
    "final_price_cents": final_price_cents,
  }


def _build_checkout_preview(
  user_id: str,
  product_code: str,
  duration_months: int,
) -> dict:
  """Shared implementation for /api/me/checkout-preview and the
  service-to-service variant. Pure read — no rows modified.

  Returns the same shape on both endpoints so the chatbot can forward
  verbatim.
  """
  if duration_months <= 0:
    raise HTTPException(status_code=400, detail="duration_months must be > 0")
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT p.id AS product_id, p.code, p.service_code, p.currency,
               COALESCE((p.metadata->>'tier_rank')::int, -1) AS tier_rank,
               o.id AS offer_id, o.duration_months, o.price_cents,
               o.discount_pct
        FROM product_offers o
        JOIN products p ON p.id = o.product_id
        WHERE p.code = %s
          AND p.active = TRUE
          AND o.active = TRUE
          AND o.duration_months = %s
        """,
        (product_code, duration_months),
      )
      offer = cur.fetchone()
      if offer is None:
        raise HTTPException(
          status_code=404,
          detail=f"offer not found: {product_code} × {duration_months}mo",
        )
      base_price_cents = int(offer["price_cents"])
      # Credit only applies on a true UPGRADE (target rank strictly
      # greater than every existing chat sub's rank). For same-tier
      # renewal / downgrade, helper returns credit=0 naturally because
      # the SQL filter excludes equal- and higher-rank rows.
      credit_info = _compute_upgrade_credit(
        cur,
        user_id=user_id,
        target_product_id=int(offer["product_id"]),
        target_service_code=offer["service_code"],
        target_tier_rank=int(offer["tier_rank"]),
      )
  credit_cents = int(credit_info["credit_cents"])
  # Never let credit exceed price (a 100% discount turns the row free,
  # which is fine for Stripe `price_data.unit_amount=0`, but it's
  # cleaner if we clamp here).
  credit_cents = min(credit_cents, base_price_cents)
  final_price_cents = base_price_cents - credit_cents
  return {
    "product_code": offer["code"],
    "duration_months": int(offer["duration_months"]),
    "offer_id": int(offer["offer_id"]),
    "currency": (offer.get("currency") or "USD").upper(),
    "base_price_cents": base_price_cents,
    "credit_cents": credit_cents,
    "final_price_cents": final_price_cents,
    "credit_source": credit_info["source_subs"],
    "is_upgrade": credit_cents > 0,
  }


@app.get("/api/me/checkout-preview")
def me_checkout_preview(
  product_code: str,
  duration_months: int = 1,
  user: dict = Depends(get_current_user),
) -> dict:
  """Quote the price a logged-in user would actually pay for
  (product_code, duration_months), including any upgrade credit
  from their existing active subs.

  Idempotent — call as many times as you want from the upgrade UI.
  Same formula as the webhook so the displayed number matches what
  Stripe charges.
  """
  return _build_checkout_preview(str(user["id"]), product_code, duration_months)


@app.get("/api/internal/checkout-preview",
         dependencies=[Depends(require_service_token)])
def internal_checkout_preview(
  product_code: str,
  duration_months: int = 1,
  user_ident: str | None = None,
) -> dict:
  """Service-to-service variant of /api/me/checkout-preview. Same
  contract; auth is via X-Service-Token.

  ``user_ident`` is email or uuid (mirrors /api/internal/usage/charge).
  """
  if not user_ident:
    raise HTTPException(status_code=400, detail="user_ident is required")
  user_id = _resolve_user_id(user_ident)
  if not user_id:
    raise HTTPException(status_code=404, detail=f"user not found: {user_ident}")
  return _build_checkout_preview(user_id, product_code, duration_months)


@app.post("/api/me/billing/portal")
def me_billing_portal(user: dict = Depends(get_current_user)) -> dict:
  """Mint a Stripe customer-portal session URL for the current user.

  The portal lets the user manage their saved payment methods, view
  invoices, and cancel/upgrade subscriptions without us having to
  reimplement those flows. We look up (or create) a stripe Customer
  keyed off the user's UUID stored in metadata.
  """
  stripe = _stripe_client()
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  return_url = base + "/?from=billing-portal"
  email = (user.get("primary_email") or "").strip()
  uid = str(user.get("id") or "")
  if not uid:
    raise HTTPException(status_code=400, detail="user not loaded")

  # Reuse a customer that's already attached to this user. We tag
  # ``metadata.user_id`` on every Customer we create, so search by
  # that gives us O(1) lookup most of the time.
  #
  # Stripe's Customer.search isn't available on every API key/version
  # (it depends on the account being on a search-enabled API version).
  # If it raises, fall back to listing by email; that's eventually
  # consistent and slower but it prevents us from creating a brand-new
  # Customer every time the user clicks the billing-portal button --
  # which would leak Customer rows on each click and confuse Stripe
  # accounting.
  customer_id: str | None = None
  try:
    found = stripe.Customer.search(
      query=f"metadata['user_id']:'{uid}'", limit=1)
    customer_id = (found and found.data and found.data[0].id) or None
  except Exception:  # noqa: BLE001 -- search may be unavailable on dev keys
    if email:
      try:
        listed = stripe.Customer.list(email=email, limit=10)
        for c in (listed.data or []):
          if (c.metadata or {}).get("user_id") == uid:
            customer_id = c.id
            break
        # No metadata-tagged match? If exactly one Customer has this
        # email, it's safe to claim it (avoids creating a duplicate
        # for a real human who's been in the system without metadata).
        # Re-stamp metadata on that Customer so future lookups hit
        # the search-by-metadata fast path.
        if customer_id is None and listed.data and len(listed.data) == 1:
          claim = listed.data[0]
          customer_id = claim.id
          try:
            stripe.Customer.modify(customer_id, metadata={"user_id": uid})
          except Exception:  # noqa: BLE001
            LOGGER.exception("could not stamp metadata on existing Customer %s",
                             customer_id)
      except Exception:  # noqa: BLE001
        LOGGER.exception("stripe Customer.list fallback failed")
  if not customer_id:
    try:
      customer = stripe.Customer.create(
        email=email or None,
        name=user.get("display_name") or user.get("username") or None,
        metadata={"user_id": uid},
      )
      customer_id = customer.id
    except Exception as exc:  # noqa: BLE001
      LOGGER.exception("stripe Customer.create failed")
      raise HTTPException(status_code=502, detail=f"stripe error: {exc}")

  try:
    session = stripe.billing_portal.Session.create(
      customer=customer_id, return_url=return_url)
  except Exception as exc:  # noqa: BLE001
    LOGGER.exception("stripe billing_portal.Session.create failed")
    raise HTTPException(status_code=502, detail=f"stripe error: {exc}")
  return {"url": session.url}


@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request) -> dict:
  """Stripe → us. Verify signature, then handle the event idempotently.

  Idempotency: ``payments.stripe_event_id`` is the only place we
  store the Stripe event id; the unique partial index on it means
  re-delivery just no-ops.
  """
  cfg = _get_system_config("stripe.webhook_secret")
  secret = (cfg.get("secret") or cfg.get("webhook_secret") or "").strip()
  if not secret:
    raise HTTPException(status_code=503,
                        detail="Stripe webhook is not configured "
                                "(system_config['stripe.webhook_secret'])")
  body = await request.body()
  sig = request.headers.get("stripe-signature", "")
  stripe = _stripe_client()
  try:
    event = stripe.Webhook.construct_event(body, sig, secret)
  except Exception as exc:  # noqa: BLE001
    LOGGER.warning("stripe webhook signature failed: %s", exc)
    raise HTTPException(status_code=400, detail="invalid signature")

  event_id = event.get("id") or ""
  event_type = event.get("type") or ""
  data_obj = (event.get("data") or {}).get("object") or {}

  # Only react to terminal payment events; ignore intermediate ones.
  if event_type not in ("checkout.session.completed",
                        "checkout.session.async_payment_succeeded",
                        "invoice.payment_succeeded"):
    return {"ok": True, "ignored": event_type}

  # Defaults so the failure-logger in the except: branch can reference
  # these even when the exception fires before we've parsed metadata.
  user_id: str | None = None
  product_id: int | None = None
  try:
    return _handle_stripe_webhook_event(event_id, event_type, data_obj, body)
  except HTTPException:
    raise  # 400/503 etc. — already structured, no need to log as a failure
  except Exception as exc:
    import traceback as _tb
    tb_text = _tb.format_exc()
    # Try to pull what we can from the event body for the audit log;
    # this is best-effort because the exception may have happened
    # before any of these were extracted.
    try:
      _meta = data_obj.get("metadata") or {}
      user_id = _meta.get("user_id") or data_obj.get("client_reference_id")
      pid_raw = _meta.get("product_id")
      product_id = int(pid_raw) if pid_raw else None
    except Exception:
      pass
    try:
      with connect() as fail_conn:
        with fail_conn.cursor() as fc:
          fc.execute(
            """
            INSERT INTO stripe_webhook_failures
              (event_id, event_type, user_id, product_id,
               error_message, error_traceback, request_body)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
              event_id or None,
              event_type or None,
              user_id,
              product_id,
              str(exc)[:1000],
              tb_text[:32000],
              (body or b"")[:8192].decode("utf-8", "replace"),
            ),
          )
        fail_conn.commit()
    except Exception:
      LOGGER.exception("could not log stripe webhook failure to DB")
    LOGGER.exception("stripe webhook handler raised, event=%s", event_id)
    # Re-raise as 500 so Stripe retries — fixes that touch the bug
    # will pick up the next delivery automatically.
    raise


def _compute_upgrade_credit(
  cur,
  user_id: str,
  target_product_id: int,
  target_service_code: str,
  target_tier_rank: int,
  now: datetime | None = None,
) -> dict:
  """Compute the upgrade credit a user has accumulated from active
  lower-tier subscriptions in the same service family.

  Pure read — does NOT cancel or modify any row. Shared by
  ``/api/me/checkout-preview`` (read-only quote for the UI) and the
  webhook upgrade branch (which commits the cancellation + payment
  separately). Single source of truth so a user never sees a
  different number than what they're actually charged.

  Returns:
    {
      "credit_cents": int,                  # rounded down to nearest cent
      "source_subs": [                      # for transparency / DB linkage
         {"sub_id": int, "product_id": int, "product_code": str,
          "remaining_days": float, "rate_cents_per_day": float,
          "credit_cents": float}            # this sub's share, pre-round
      ],
      "new_offer_monthly_cents": int | None # 0/None if target has no 1mo offer
    }

  Algorithm (matches the bonus_days formula the webhook used to apply
  — same math, expressed as money):

  - Find every active sub in the same ``service_code`` family whose
    ``tier_rank`` is strictly less than the target's, whose
    ``expires_at IS NOT NULL`` (excludes the permanent tier_free
    grant), and whose product is NOT the target product (would be
    same-tier renewal, no credit).
  - For each, look up the 1-month offer's ``price_cents``. The
    *1-month rate* is intentionally chosen so bulk-discounted purchases
    don't shrink the credit and the math is transparent at any
    duration the user buys.
  - This sub's credit = remaining_days × (low_offer_monthly / 30).
  - Sum across sources, floor to int cents.
  """
  now = now or datetime.now(timezone.utc)
  cur.execute(
    """
    SELECT s.id AS sub_id, s.expires_at, s.product_id,
           p.code AS product_code,
           COALESCE((p.metadata->>'tier_rank')::int, -1) AS tier_rank
    FROM subscriptions s
    JOIN products p ON p.id = s.product_id
    WHERE s.user_id = %s
      AND p.service_code = %s
      AND s.status = 'active'
      AND s.product_id != %s
      AND s.expires_at IS NOT NULL
      AND COALESCE((p.metadata->>'tier_rank')::int, -1) < %s
    """,
    (user_id, target_service_code, target_product_id, target_tier_rank),
  )
  lower_subs = cur.fetchall()
  if not lower_subs:
    return {"credit_cents": 0, "source_subs": [], "new_offer_monthly_cents": 0}
  # Target's 1-month rate (denominator in the bonus-days formula).
  cur.execute(
    "SELECT price_cents FROM product_offers "
    "WHERE product_id=%s AND duration_months=1 AND active=TRUE",
    (target_product_id,),
  )
  new_offer = cur.fetchone()
  new_monthly_cents = int(new_offer["price_cents"]) if new_offer else 0
  total_credit_cents = 0.0
  sources: list[dict] = []
  for low in lower_subs:
    remaining_days = 0.0
    if low["expires_at"] is not None:
      remaining = (low["expires_at"] - now).total_seconds() / 86_400.0
      remaining_days = max(0.0, remaining)
    cur.execute(
      "SELECT price_cents FROM product_offers "
      "WHERE product_id=%s AND duration_months=1 AND active=TRUE",
      (low["product_id"],),
    )
    low_offer = cur.fetchone()
    low_monthly_cents = int(low_offer["price_cents"]) if low_offer else 0
    rate_per_day = low_monthly_cents / 30.0 if low_monthly_cents > 0 else 0.0
    this_credit = remaining_days * rate_per_day
    if this_credit > 0:
      total_credit_cents += this_credit
    sources.append({
      "sub_id": int(low["sub_id"]),
      "product_id": int(low["product_id"]),
      "product_code": low["product_code"],
      "remaining_days": round(remaining_days, 4),
      "rate_cents_per_day": round(rate_per_day, 4),
      "credit_cents": round(this_credit, 4),
    })
  return {
    "credit_cents": int(total_credit_cents),  # floor to whole cents
    "source_subs": sources,
    "new_offer_monthly_cents": new_monthly_cents,
  }


def _handle_stripe_webhook_event(
  event_id: str,
  event_type: str,
  data_obj: dict,
  body: bytes,
) -> dict:
  """Inner handler for stripe_webhook. Pulled out so the outer
  function's try/except can wrap a single statement; everything in
  here is allowed to raise and the wrapper will (a) log the failure
  to stripe_webhook_failures and (b) re-raise as a 500 so Stripe
  retries delivery."""
  meta = data_obj.get("metadata") or {}
  user_id = meta.get("user_id") or data_obj.get("client_reference_id")
  product_id = int(meta.get("product_id") or 0)
  product_code = meta.get("product_code")
  # New under the one-time + duration model: how many months this purchase
  # grants. Defaults to 1 so a legacy session without the field still works.
  duration_months = int(meta.get("duration_months") or 1)
  amount = int(data_obj.get("amount_total") or data_obj.get("amount_paid") or 0)
  currency = (data_obj.get("currency") or "usd").upper()
  pi_id = data_obj.get("payment_intent") or data_obj.get("invoice") or ""

  if not user_id or not product_id:
    LOGGER.warning("stripe webhook missing metadata: event=%s", event_id)
    return {"ok": True, "skipped": "missing metadata"}

  with connect() as conn:
    with conn.cursor() as cur:
      # Check user + product exist.
      cur.execute("SELECT id::text FROM auth_users WHERE id = %s", (user_id,))
      if cur.fetchone() is None:
        LOGGER.warning("stripe webhook user not found: %s", user_id)
        return {"ok": True, "skipped": "user not found"}
      cur.execute(
        "SELECT id, kind, period_days, service_code, "
        "COALESCE((metadata->>'tier_rank')::int, -1) AS tier_rank "
        "FROM products WHERE id = %s",
        (product_id,),
      )
      product = cur.fetchone()
      if product is None:
        return {"ok": True, "skipped": "product not found"}
      # Insert payment idempotently. Stash product_code + duration_months
      # + discount_pct on the row so the user's Orders page can render
      # "Chat Pro · 3 months · 15% off" without re-joining product_offers.
      cur.execute(
        """
        INSERT INTO payments
          (user_id, product_id, amount_cents, currency, status,
           stripe_payment_intent_id, stripe_event_id, metadata)
        VALUES (%s, %s, %s, %s, 'paid', %s, %s, %s::jsonb)
        ON CONFLICT (stripe_event_id) DO NOTHING
        RETURNING id
        """,
        (user_id, product_id, amount, currency, pi_id, event_id,
         _to_jsonb({
           "event_type": event_type,
           "product_code": product_code,
           "duration_months": duration_months,
           "discount_pct": int(meta.get("discount_pct") or 0),
           "offer_id": int(meta.get("offer_id") or 0) or None,
         })),
      )
      payment_row = cur.fetchone()
      if payment_row is None:
        # Already processed — idempotent retry.
        return {"ok": True, "duplicate": True}
      # Auto-grant subscription or extend the existing one. Under the
      # one-time + duration model we shift expires_at forward by the
      # purchased duration_months; the row stays active throughout.
      expires_at = None
      if product["kind"] in ("one_time", "period", "recurring"):
        # `relativedelta` from dateutil would be tidier (handles leap
        # months) but we already depend on stdlib timedelta everywhere;
        # 30 d/month is the same rule the legacy `period_days` path used
        # and matches Stripe's billing precedent for "monthly".
        expires_at = datetime.now(timezone.utc) + timedelta(days=30 * duration_months)
      # Three cases drive the subscription state change:
      #
      #   1. Same-product renewal — user already has an active sub for
      #      this exact product. Extend its expires_at by the purchased
      #      duration. "Early renewal" preserves remaining time
      #      (extend from max(now, current expiry)).
      #
      #   2. Cross-tier UPGRADE — user has no sub for THIS product, but
      #      does have an active lower-rank sub in the same service
      #      family (e.g. signup_7day_basic or paid tier_basic, while
      #      buying tier_pro). Cancel the lower sub, convert its
      #      remaining DAYS into bonus NEW-TIER days using the ratio of
      #      their 1-month-offer daily prices, and INSERT the new sub
      #      with expires_at = now + duration + bonus.
      #
      #   3. Fresh purchase — no related active sub. INSERT with
      #      SAVEPOINT-protected race recovery (concurrent Stripe
      #      retries can fight for the same unique-per-(user,product)
      #      slot; the loser re-reads and extends).
      now = datetime.now(timezone.utc)
      cur.execute(
        """
        SELECT id, expires_at FROM subscriptions
        WHERE user_id=%s AND product_id=%s AND status='active'
        """,
        (user_id, product_id),
      )
      existing_sub = cur.fetchone()
      sub_row = None
      base_period_days = 30 * duration_months
      if existing_sub is not None and expires_at is not None:
        # Case 1: same-tier renewal. (THIS is the path that had the
        # NameError-on-`period` bug — fixed by using base_period_days.)
        from_dt = max(now, existing_sub["expires_at"] or now)
        new_exp = from_dt + timedelta(days=base_period_days)
        cur.execute(
          """
          UPDATE subscriptions SET expires_at=%s, updated_at=NOW()
          WHERE id=%s RETURNING id
          """,
          (new_exp, existing_sub["id"]),
        )
        sub_row = cur.fetchone()
        LOGGER.info("stripe webhook extended sub user=%s product=%s to %s",
                    user_id, product_code, new_exp)
      else:
        # Case 2 / Case 3. The new contract: when the checkout flow
        # already applied the upgrade credit at price-time (Session
        # metadata.credit_applied_cents > 0), we just need to cancel
        # the lower-tier subs and let the new one start at exactly
        # `base_period_days` from now. The user already saw — and
        # paid — the prorated price.
        #
        # The bonus_days branch survives strictly as a backwards-
        # compatible path for Stripe events that were created BEFORE
        # this deploy (and may still be retrying). Those sessions
        # were charged full price; the only way the user gets their
        # money's worth is the day-credit applied here. Delete this
        # legacy branch ~30 days post-deploy.
        credit_applied_cents = int(meta.get("credit_applied_cents") or 0)
        credit_source_sub_ids: list[int] = []
        if meta.get("credit_source_sub_ids"):
          credit_source_sub_ids = [
            int(s) for s in str(meta["credit_source_sub_ids"]).split(",") if s.strip()
          ]
        replaced_ids: list[int] = []
        bonus_days = 0.0
        if credit_applied_cents > 0:
          # New flow — credit was already applied at checkout. Cancel
          # exactly the subs that backed that credit (use the IDs from
          # session metadata so we don't accidentally cancel a sub the
          # user added between preview and webhook). No bonus_days.
          replaced_ids = credit_source_sub_ids
        elif expires_at is not None:
          # Legacy flow — no credit_applied_cents on the session. Use
          # the shared helper to compute bonus_days, same formula as
          # before. Reads the same lower-rank-active-sub set; pays
          # off remaining time as extra days on the new sub.
          info = _compute_upgrade_credit(
            cur,
            user_id=user_id,
            target_product_id=product_id,
            target_service_code=product["service_code"],
            target_tier_rank=product["tier_rank"],
            now=now,
          )
          new_monthly = info["new_offer_monthly_cents"]
          if new_monthly and info["credit_cents"] > 0:
            # credit_cents is the dollar value; convert back to days
            # at the new tier's daily rate: credit / (new_monthly/30).
            bonus_days = info["credit_cents"] / (new_monthly / 30.0)
          replaced_ids = [s["sub_id"] for s in info["source_subs"]]
        if replaced_ids:
          cur.execute(
            """
            UPDATE subscriptions
            SET status='canceled',
                updated_at=NOW(),
                metadata = metadata || jsonb_build_object(
                  'canceled_reason', 'upgraded',
                  'canceled_by_event_id', %s::text
                )
            WHERE id = ANY(%s) AND status='active'
            """,
            (event_id, replaced_ids),
          )
        # INSERT the new sub. SAVEPOINT recovers from concurrent
        # Stripe-retry races (unique partial index on
        # (user_id, product_id) where status IN ('pending','active',
        # 'over_quota') would block a duplicate).
        new_expires = (
          expires_at + timedelta(days=bonus_days) if expires_at is not None else None
        )
        cur.execute("SAVEPOINT before_sub_insert")
        try:
          cur.execute(
            """
            INSERT INTO subscriptions
              (user_id, product_id, status, starts_at, expires_at, source, metadata)
            VALUES (%s, %s, 'active', NOW(), %s, 'stripe', %s::jsonb)
            RETURNING id
            """,
            (
              user_id, product_id, new_expires,
              _to_jsonb({
                "stripe_payment_id": payment_row["id"],
                **(
                  {
                    "replaced_sub_ids": replaced_ids,
                    **({"credit_applied_cents": credit_applied_cents}
                       if credit_applied_cents > 0 else {}),
                    **({"bonus_days_from_upgrade": round(bonus_days, 3)}
                       if bonus_days > 0 else {}),
                  }
                  if replaced_ids
                  else {}
                ),
              }),
            ),
          )
          sub_row = cur.fetchone()
          cur.execute("RELEASE SAVEPOINT before_sub_insert")
          if replaced_ids and sub_row:
            cur.execute(
              """
              UPDATE subscriptions
              SET metadata = metadata || jsonb_build_object(
                'replaced_by_sub_id', %s::bigint
              )
              WHERE id = ANY(%s)
              """,
              (sub_row["id"], replaced_ids),
            )
            LOGGER.info(
              "stripe webhook upgraded user=%s to product=%s (rank=%s); "
              "canceled %d lower-tier sub(s) %s; "
              "credit_applied=%dc; bonus_days=%.2f; new expires=%s",
              user_id, product_code, product["tier_rank"],
              len(replaced_ids), replaced_ids,
              credit_applied_cents, bonus_days, new_expires,
            )
        except psycopg.errors.UniqueViolation:
          # Concurrent Stripe retry beat us to the INSERT. Roll back to
          # the savepoint (preserves the payments row + the lower-sub
          # cancellations from this txn), find the winner, and apply
          # the same extension logic as Case 1.
          cur.execute("ROLLBACK TO SAVEPOINT before_sub_insert")
          cur.execute(
            "SELECT id, expires_at FROM subscriptions "
            " WHERE user_id=%s AND product_id=%s AND status='active'",
            (user_id, product_id),
          )
          existing_sub = cur.fetchone()
          if existing_sub is not None and expires_at is not None:
            from_dt = max(now, existing_sub["expires_at"] or now)
            new_exp = from_dt + timedelta(days=base_period_days + bonus_days)
            cur.execute(
              """
              UPDATE subscriptions SET expires_at=%s, updated_at=NOW()
              WHERE id=%s RETURNING id
              """,
              (new_exp, existing_sub["id"]),
            )
            sub_row = cur.fetchone()
            LOGGER.info(
              "stripe webhook extended sub (after concurrent-insert race) "
              "user=%s product=%s to %s",
              user_id, product_code, new_exp,
            )
          else:
            sub_row = existing_sub
      # No xout-side provisioning needed: xout containers read user
      # state from auth_users + subscriptions + xout_products on every
      # tick, and the user's VLESS UUID is on auth_users (not per node).
      #
      # Provision (or refresh) the usage_quotas row for chat-tier
      # purchases. Without this the user sees their new tier but
      # limit_cents=0 because get_usage_summary reads from
      # usage_quotas — there's no on-the-fly derivation from
      # product.metadata.daily_allowance_cents. ON CONFLICT DO NOTHING
      # so renewals don't wipe the running consumption for the day.
      cur.execute(
        """
        INSERT INTO usage_quotas
          (user_id, product_id, limit_qty, reset_kind,
           current_period_start, current_period_consumed, updated_at)
        SELECT %s, p.id,
               COALESCE((p.metadata->>'daily_allowance_cents')::int, 0),
               'daily',
               date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
               0, NOW()
        FROM products p
        WHERE p.id = %s
          AND (p.metadata->>'daily_allowance_cents') IS NOT NULL
        ON CONFLICT (user_id, product_id) DO NOTHING
        """,
        (user_id, product_id),
      )
    conn.commit()
  LOGGER.info("stripe webhook handled event=%s user=%s product=%s",
               event_id, user_id, product_code)
  return {"ok": True}


# ---------------------------------------------------------------------------
# P5: OAuth login (Google as first provider).
#   /api/auth/oauth/{provider}/start    — redirects to provider's authz URL
#   /api/auth/oauth/{provider}/callback — exchanges code, finds-or-creates
#                                         auth_users, sets session cookie
#
# Operator configures system_config['oauth.google.client_id'],
# 'oauth.google.client_secret', 'oauth.google.redirect_uri' via Settings.
# ---------------------------------------------------------------------------


_SUPPORTED_OAUTH_PROVIDERS = ("google",)
_OAUTH_STATE_COOKIE = "user_oauth_state"


def _oauth_provider_config(provider: str) -> dict:
  if provider not in _SUPPORTED_OAUTH_PROVIDERS:
    raise HTTPException(status_code=404, detail=f"unsupported provider: {provider}")
  cfg = _get_system_config(f"oauth.{provider}")
  if not cfg.get("client_id") or not cfg.get("client_secret"):
    raise HTTPException(status_code=503,
                        detail=f"{provider} oauth not configured")
  return cfg


@app.get("/api/auth/oauth/{provider}/start")
def oauth_start(provider: str, response: Response) -> Response:
  cfg = _oauth_provider_config(provider)
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  redirect_uri = cfg.get("redirect_uri") or f"{base}/api/auth/oauth/{provider}/callback"
  client_id = cfg["client_id"]
  import secrets as _secrets, urllib.parse as _up
  state = _secrets.token_urlsafe(24)
  if provider == "google":
    authz = (
      "https://accounts.google.com/o/oauth2/v2/auth?"
      + _up.urlencode({
          "client_id": client_id,
          "redirect_uri": redirect_uri,
          "response_type": "code",
          "scope": "openid email profile",
          "state": state,
          "access_type": "online",
          "include_granted_scopes": "true",
          "prompt": "select_account",
      })
    )
  else:
    raise HTTPException(status_code=404, detail="unsupported provider")
  # Set state cookie + redirect. Cookie is short-lived (10 min) and
  # SameSite=Lax so it survives the cross-site Google redirect back.
  resp = Response(status_code=303, headers={"Location": authz})
  resp.set_cookie(
    key=_OAUTH_STATE_COOKIE,
    value=state,
    max_age=600,
    secure=(os.getenv("SESSION_COOKIE_SECURE", "true").lower() in ("1","true","yes")),
    httponly=True,
    samesite="lax",
    path="/",
  )
  return resp


@app.get("/api/auth/oauth/{provider}/callback")
async def oauth_callback(provider: str, code: str | None = None,
                          state: str | None = None,
                          oauth_state: str | None = Cookie(default=None,
                                                              alias=_OAUTH_STATE_COOKIE),
                          request: Request = None,
                          response: Response = None) -> Response:
  cfg = _oauth_provider_config(provider)
  if not code or not state or not oauth_state or state != oauth_state:
    raise HTTPException(status_code=400, detail="invalid oauth state")
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  redirect_uri = cfg.get("redirect_uri") or f"{base}/api/auth/oauth/{provider}/callback"
  import httpx
  if provider == "google":
    token_url = "https://oauth2.googleapis.com/token"
    userinfo_url = "https://openidconnect.googleapis.com/v1/userinfo"
  else:
    raise HTTPException(status_code=404, detail="unsupported provider")
  async with httpx.AsyncClient(timeout=15) as client:
    try:
      tr = await client.post(token_url, data={
        "code": code,
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
      })
      tr.raise_for_status()
      tok = tr.json()
      ur = await client.get(userinfo_url,
                              headers={"Authorization": f"Bearer {tok['access_token']}"})
      ur.raise_for_status()
      profile = ur.json()
    except Exception as exc:  # noqa: BLE001
      LOGGER.exception("oauth token exchange failed")
      raise HTTPException(status_code=502, detail=f"oauth provider error: {exc}")

  provider_user_id = profile.get("sub") or profile.get("id")
  email = (profile.get("email") or "").lower().strip()
  name = profile.get("name") or profile.get("given_name") or ""
  if not provider_user_id:
    raise HTTPException(status_code=502, detail="oauth provider returned no user id")

  # Find or create auth_users + auth_oauth_links.
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT user_id::text FROM auth_oauth_links WHERE provider=%s AND provider_user_id=%s",
        (provider, str(provider_user_id)),
      )
      link = cur.fetchone()
      if link is not None:
        user_id = link["user_id"]
      else:
        # Only match (or use) the email when the provider says it's
        # verified. Otherwise an attacker could register a Google
        # account claiming admin@victim.com (unverified) and squat
        # on the email or hijack a future signup.
        email_verified = (profile.get("email_verified") is True)
        if email and email_verified:
          cur.execute("SELECT id::text FROM auth_users WHERE LOWER(primary_email)=%s",
                      (email,))
          existing = cur.fetchone()
        else:
          existing = None
        if existing is not None:
          user_id = existing["id"]
        else:
          cur.execute("SELECT pg_advisory_xact_lock(%s)", (_FIRST_USER_LOCK_KEY,))
          is_first = _no_users_yet(cur)
          # Stand-in email — never use the unverified one for the
          # primary_email field; keep the original in profile JSONB
          # so the operator can see what the provider returned.
          if email and email_verified:
            synth_email = email
          else:
            synth_email = f"{provider}-{provider_user_id}@oauth.local"
          # username is NOT NULL on auth_users. Derive from email's
          # local part with collision suffix; OAuth signups must not
          # 500 just because two providers happen to give us the
          # same local part.
          local = re.sub(r"[^a-z0-9_.-]", "",
                         synth_email.split("@", 1)[0].lower())
          base_username = local or f"{provider}_{provider_user_id}"
          candidate = base_username
          attempt = 0
          while True:
            cur.execute("SELECT 1 FROM auth_users WHERE LOWER(username) = LOWER(%s)",
                        (candidate,))
            if cur.fetchone() is None:
              break
            attempt += 1
            candidate = f"{base_username}_{attempt}"
            if attempt > 99:
              raise HTTPException(status_code=503,
                                  detail="could not allocate username")
          cur.execute(
            """
            INSERT INTO auth_users (username, primary_email, display_name, locale,
                                     is_admin, status, metadata)
            VALUES (%s, %s, %s, %s, %s, 'active', %s::jsonb)
            RETURNING id::text
            """,
            (candidate, synth_email, name or None, DEFAULT_LOCALE, is_first,
             _to_jsonb({"source": "oauth", "provider": provider,
                         "provider_email": email,
                         "provider_email_verified": email_verified})),
          )
          user_id = cur.fetchone()["id"]
        cur.execute(
          """
          INSERT INTO auth_oauth_links (user_id, provider, provider_user_id, profile)
          VALUES (%s, %s, %s, %s::jsonb)
          ON CONFLICT (provider, provider_user_id) DO NOTHING
          """,
          (user_id, provider, str(provider_user_id), _to_jsonb(profile)),
        )
    conn.commit()

  # Issue session cookie + redirect to /
  token = issue_session(user_id,
                        ip=request.client.host if request and request.client else None,
                        ua=request.headers.get("user-agent") if request else None)
  resp = Response(status_code=303, headers={"Location": "/"})
  _set_session_cookie(resp, token)
  resp.delete_cookie(_OAUTH_STATE_COOKIE, path="/")
  LOGGER.info("oauth login provider=%s user=%s", provider, user_id)
  return resp


@app.get("/api/me/orders")
def me_orders(user: dict = Depends(get_current_user)) -> dict:
  """Return the user's purchase history — every successful Stripe
  payment they've made, newest first. The data lives in the
  ``payments`` table; we join ``products`` and ``product_offers`` so
  the response carries tier name + duration + Stripe receipt URL
  without the SPA having to do follow-up lookups."""
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT pay.id, pay.amount_cents, pay.currency, pay.status,
               pay.stripe_payment_intent_id, pay.created_at, pay.metadata,
               p.code AS product_code, p.name AS product_name
        FROM payments pay
        JOIN products p ON p.id = pay.product_id
        WHERE pay.user_id = %s
        ORDER BY pay.created_at DESC
        LIMIT 100
        """,
        (user["id"],),
      )
      rows = cur.fetchall()
  out = []
  for r in rows:
    m = r["metadata"] or {}
    if isinstance(m, str):
      try:
        m = json.loads(m)
      except Exception:
        m = {}
    out.append({
      "id": r["id"],
      "product_code": r["product_code"],
      "product_name": r["product_name"],
      "duration_months": int(m.get("duration_months") or 1),
      "discount_pct": int(m.get("discount_pct") or 0),
      "amount_cents": r["amount_cents"],
      "currency": r["currency"],
      "status": r["status"],
      "stripe_payment_intent_id": r["stripe_payment_intent_id"],
      "created_at": r["created_at"].isoformat() if r["created_at"] else None,
    })
  return {"orders": out}


@app.get("/api/internal/users/{ident}/orders",
         dependencies=[Depends(require_service_token)])
def internal_orders(ident: str) -> dict:
  """Service-to-service mirror of /api/me/orders. chatbot calls this
  to power the upgrade/orders dialog without re-auth."""
  uid = _resolve_user_id(ident)
  if not uid:
    raise HTTPException(status_code=404, detail="user not found")
  return me_orders({"id": uid})  # reuse the cookie-auth impl


class InternalCheckoutSessionRequest(BaseModel):
  user_ident: str  # email or auth_users.id
  product_code: str
  duration_months: int | None = None
  success_url: str | None = None
  cancel_url: str | None = None


@app.post("/api/internal/checkout/create-session",
          dependencies=[Depends(require_service_token)])
def internal_create_checkout_session(req: InternalCheckoutSessionRequest) -> dict:
  """Service-to-service mirror of /api/checkout/create-session for
  callers (chatbot) that don't have a user-service cookie. Resolves
  the user via email or uuid, then delegates to the same code path
  as the cookie-authed endpoint."""
  uid = _resolve_user_id(req.user_ident)
  if not uid:
    raise HTTPException(status_code=404, detail="user not found")
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT id, primary_email, display_name, username FROM auth_users WHERE id = %s",
        (uid,),
      )
      user_row = cur.fetchone()
  if user_row is None:
    raise HTTPException(status_code=404, detail="user not found")
  cookie_req = CheckoutSessionRequest(
    product_code=req.product_code,
    duration_months=req.duration_months,
    success_url=req.success_url,
    cancel_url=req.cancel_url,
  )
  return create_checkout_session(cookie_req, user=dict(user_row))


@app.get("/api/billing/catalog")
def billing_catalog(service_code: str = "chat") -> dict:
  """Public chat-tier catalog: every (product, offer) the user can
  buy for ``service_code``. Server-side computation so the SPA only
  has to render. Free / non-user-facing products are filtered out."""
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT p.code, p.name, p.description, p.metadata,
               p.price_cents AS base_cents,
               o.id AS offer_id, o.duration_months,
               o.price_cents, o.discount_pct, o.stripe_price_id
        FROM products p
        LEFT JOIN product_offers o ON o.product_id = p.id AND o.active = TRUE
        WHERE p.service_code = %s
          AND p.active = TRUE
          AND p.kind = 'one_time'
          AND (p.metadata->>'user_facing')::boolean = TRUE
        ORDER BY (p.metadata->>'tier_rank')::int NULLS LAST, o.duration_months
        """,
        (service_code,),
      )
      rows = cur.fetchall()
  by_product: dict[str, dict] = {}
  for r in rows:
    code = r["code"]
    entry = by_product.setdefault(code, {
      "code": code,
      "name": r["name"],
      "description": r["description"],
      "metadata": r["metadata"] or {},
      "base_cents_monthly": r["base_cents"],
      "offers": [],
    })
    if r["offer_id"] is not None:
      entry["offers"].append({
        "offer_id": r["offer_id"],
        "duration_months": r["duration_months"],
        "price_cents": r["price_cents"],
        "discount_pct": r["discount_pct"],
        "stripe_price_id": r["stripe_price_id"],
      })
  return {"service_code": service_code, "products": list(by_product.values())}


@app.get("/api/me/oauth-links")
def me_oauth_links(user: dict = Depends(get_current_user)) -> dict:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT provider, profile->>'email' AS email,
               profile->>'name' AS name, created_at
        FROM auth_oauth_links WHERE user_id = %s ORDER BY created_at DESC
        """,
        (user["id"],),
      )
      rows = cur.fetchall()
  return {"links": rows}


@app.delete("/api/me/oauth-links/{provider}")
def me_unlink_oauth(provider: str,
                     user: dict = Depends(get_current_user)) -> dict:
  with connect() as conn:
    with conn.cursor() as cur:
      # Refuse to unlink if the user has no other auth method —
      # otherwise they'd be permanently locked out. They need either
      # a password row OR another oauth link still attached.
      cur.execute("SELECT 1 FROM auth_passwords WHERE user_id=%s", (user["id"],))
      has_password = cur.fetchone() is not None
      cur.execute(
        "SELECT COUNT(*) AS n FROM auth_oauth_links WHERE user_id=%s",
        (user["id"],),
      )
      total_links = cur.fetchone()["n"]
      if not has_password and total_links <= 1:
        raise HTTPException(status_code=409,
                            detail="cannot unlink your only sign-in method; set a password first")
      cur.execute(
        "DELETE FROM auth_oauth_links WHERE user_id=%s AND provider=%s",
        (user["id"], provider),
      )
      n = cur.rowcount
    conn.commit()
  return {"deleted": n}


@app.get("/api/auth/providers")
def list_oauth_providers() -> dict:
  """Public endpoint — tells the SPA which providers the operator
  has actually configured so it can show the right buttons."""
  available = []
  for p in _SUPPORTED_OAUTH_PROVIDERS:
    cfg = _get_system_config(f"oauth.{p}")
    if cfg.get("client_id") and cfg.get("client_secret"):
      available.append(p)
  return {"providers": available}


# NOTE: /api/admin/products/{product_id} PATCH handler lives near the
# other product CRUD endpoints (search for ``admin_patch_product``).
# An older second copy used to live here; it was unreachable (FastAPI
# resolves to the first registered route) and has been removed to
# avoid the next reader thinking it's the live code path.
