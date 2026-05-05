"""HTTP surface for the user-service.

Endpoints (v1, P1 scope):

  POST /api/auth/signup            email + password
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
  init_pool()
  yield


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
  locale: str | None = None
  is_admin: bool = False


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


def _user_row_to_public(row: dict) -> dict:
  """Project an auth_users row to the shape we send back to clients."""
  return {
    "id": row["id"],
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
# Mental model:
#   - A "xout product" is a row in `xout_products` joined to `products`.
#     It carries an `inbound_selector` JSONB describing which (node,
#     inbound_tag) pairs the product offers.
#   - When an admin grants an xout product to a user, the resulting
#     `subscriptions` row gets a unique `subscription_token`. The
#     public endpoint /sub/{token} returns a base64-encoded subscription
#     containing one VLESS URI per matching inbound (live computed —
#     adding/removing nodes flows through immediately).
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

  ``tags=["*"]`` (or just no tags key) means all inbounds on that node.
  Missing top-level ``nodes`` means the product is empty (no
  inbounds), not "all nodes" — we want explicit opt-in to dodge
  surprises.
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
    tags = n.get("tags")
    if not tags or "*" in tags:
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
    if tags is not None and not isinstance(tags, list):
      raise HTTPException(status_code=400,
                          detail=f"selector node {n.get('name')} 'tags' must be a list")


def _user_xout_subscriptions(user_id: str) -> list[dict]:
  """Return one row per active xout subscription for the user.

  Each row carries the subscription_token, product info, and a
  resolved list of (node, inbound) entries the user can connect to.
  This is what /api/me uses to render the SPA cards and what /sub/<tok>
  builds VLESS URIs from.
  """
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT s.id AS sub_id, s.subscription_token, s.expires_at,
               s.starts_at, s.status,
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
      # Pre-fetch all node→inbounds for nodes mentioned in any selector.
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
      cur.execute(
        """
        SELECT n.node_name, n.user_id::text AS user_id,
               n.vless_uuid::text AS vless_uuid
        FROM xout_node_users n
        WHERE n.user_id = %s AND n.node_name = ANY(%s)
        """,
        (user_id, list(node_names) or [""]),
      )
      provisioning = {r["node_name"]: r["vless_uuid"] for r in cur.fetchall()}

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
          "vless_uuid": provisioning.get(node_name),
          # Include reality for the URI builder. /api/me also returns
          # this so the SPA can display the SNI per-line if it wants.
          "reality": ib.get("reality"),
        })
    out.append({
      "subscription_id": s["sub_id"],
      "subscription_token": s["subscription_token"],
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


def _xout_config_for_user(user_id: str) -> dict | None:
  """Compose the ``xout`` block returned by /api/me.

  Returns None when the user has no xout subscriptions. Otherwise
  returns one entry per subscription with subscription URL, product
  name, expiry, and per-node connection info.
  """
  subs = _user_xout_subscriptions(user_id)
  if not subs:
    return None
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  out_subs = []
  for s in subs:
    uris = _build_subscription_uris(user_id, s["subscription_id"], s["inbounds"])
    out_subs.append({
      "subscription_id": s["subscription_id"],
      "product_code": s["product_code"],
      "product_name": s["product_name"],
      "expires_at": s["expires_at"],
      "subscription_url": (f"{base}/sub/{s['subscription_token']}"
                            if s["subscription_token"] else None),
      "inbounds": s["inbounds"],
      "uri_count": len(uris),
    })
  return {"subscriptions": out_subs}


def _list_user_subscriptions(user_id: str) -> list[dict]:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT s.id, s.product_id, p.code AS product_code, p.kind,
               s.status, s.starts_at, s.expires_at, s.source,
               s.subscription_token,
               p.name AS product_name, p.description AS product_description
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


@app.post("/api/auth/signup")
def auth_signup(req: SignupRequest, request: Request, response: Response) -> dict:
  locale_hint = req.locale or request.headers.get("accept-language")
  locale = negotiate_locale(locale_hint)
  email = _normalize_email(req.email)
  if not EMAIL_RE.match(email):
    raise HTTPException(status_code=400, detail=t(locale, "auth.signup.invalid_email"))
  if len(req.password) < PASSWORD_MIN_LEN:
    raise HTTPException(status_code=400,
                        detail=t(locale, "auth.signup.password_too_short"))

  # First-user bootstrap: the very first signup becomes admin so the
  # operator has a way in without running SQL by hand. Two concurrent
  # signups racing here would both observe an empty table without the
  # advisory lock — we'd end up with two admins or a unique-index
  # collision. The lock is transaction-scoped: held until commit, then
  # auto-released. Cheap (microseconds) and doesn't survive crashes.
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT pg_advisory_xact_lock(%s)", (_FIRST_USER_LOCK_KEY,))
      is_first = _no_users_yet(cur)
      cur.execute(
        "SELECT id::text FROM auth_users WHERE LOWER(primary_email) = %s",
        (email,),
      )
      if cur.fetchone() is not None:
        raise HTTPException(status_code=409, detail=t(locale, "auth.signup.email_taken"))
      cur.execute(
        """
        INSERT INTO auth_users (primary_email, locale, is_admin, status)
        VALUES (%s, %s, %s, 'active')
        RETURNING id::text, primary_email, locale, is_admin, display_name, status
        """,
        (email, locale, is_first),
      )
      user_row = cur.fetchone()
      cur.execute(
        "INSERT INTO auth_passwords (user_id, argon2_hash) VALUES (%s, %s)",
        (user_row["id"], hash_password(req.password)),
      )
    conn.commit()

  token = issue_session(user_row["id"],
                        ip=request.client.host if request.client else None,
                        ua=request.headers.get("user-agent"))
  _set_session_cookie(response, token)
  LOGGER.info("auth.signup id=%s admin=%s", user_row["id"], is_first)
  # Best-effort verification email — log fallback if SMTP isn't set,
  # so dev-mode operators can copy from `docker logs`. We don't fail
  # signup if the email fails.
  try:
    vt = _make_verification_token(user_row["id"], email, "verify_email", 24)
    base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
    _send_email(email, "Verify your email",
                f"Welcome! Click the link to verify your email:\n\n"
                f"{base}/?verify={vt}\n\nThis link expires in 24 hours.")
  except Exception:  # noqa: BLE001
    LOGGER.exception("could not enqueue verification email at signup")
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
  use_starttls = (str(cfg.get("starttls") or "true").lower() in ("1","true","yes"))
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
  link = f"{base}/?verify={token}"
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
  """Per-product quota state for the logged-in user. Period-resets
  happen lazily here too so the response is always fresh."""
  return {"quotas": _list_user_quotas(user["id"])}


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
) -> dict:
  # Logged-in users get content in their stored locale; anonymous
  # users fall back to Accept-Language → DEFAULT_LOCALE.
  locale = _request_locale(request, user)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT id, code, kind, price_cents, currency, period_days,
               name, description, metadata, active
        FROM products WHERE active = TRUE ORDER BY id ASC
        """
      )
      rows = cur.fetchall()
  out = []
  for r in rows:
    name = (r["name"] or {})
    desc = (r["description"] or {})
    out.append({
      "id": r["id"],
      "code": r["code"],
      "kind": r["kind"],
      "price_cents": r["price_cents"],
      "currency": r["currency"],
      "period_days": r["period_days"],
      "name": name.get(locale) or name.get(DEFAULT_LOCALE) or r["code"],
      "description": desc.get(locale) or desc.get(DEFAULT_LOCALE) or "",
    })
  return {"products": out, "locale": locale}


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
             "OR LOWER(display_name) LIKE %s ESCAPE '\\'")
    needle = f"%{escaped}%"
    params.extend([needle, needle])
  list_params = list(params) + [limit, offset]
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        f"""
        SELECT id::text AS id, primary_email, display_name, locale, is_admin,
               status, created_at,
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
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT id FROM auth_users WHERE LOWER(primary_email) = %s",
        (email,),
      )
      if cur.fetchone() is not None:
        raise HTTPException(status_code=409, detail="email already registered")
      cur.execute(
        """
        INSERT INTO auth_users (primary_email, display_name, locale, is_admin, status)
        VALUES (%s, %s, %s, %s, 'active')
        RETURNING id::text, primary_email, display_name, locale, is_admin, status
        """,
        (email, req.display_name, locale, req.is_admin),
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
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT id::text, primary_email, display_name, locale, is_admin,
               status, metadata, created_at
        FROM auth_users WHERE id = %s
        """,
        (user_id,),
      )
      row = cur.fetchone()
      if row is None:
        raise HTTPException(status_code=404, detail="user not found")
  subs = _list_user_subscriptions(user_id)
  return {"user": row, "subscriptions": subs}


@app.post("/api/admin/users/{user_id}/grant", dependencies=[Depends(require_admin)])
def admin_grant_product(user_id: str, req: GrantRequest) -> dict:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("SELECT id::text FROM auth_users WHERE id = %s", (user_id,))
      if cur.fetchone() is None:
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
      # Every active subscription gets a unique random token for the
      # /sub/<token> endpoint. v1 reuses this for any product kind —
      # non-xout products simply ignore the token.
      import secrets as _secrets
      sub_token = _secrets.token_urlsafe(24)
      cur.execute(
        """
        INSERT INTO subscriptions
          (user_id, product_id, status, starts_at, expires_at, source,
           subscription_token)
        VALUES (%s, %s, 'active', NOW(), %s, %s, %s)
        RETURNING id, starts_at, expires_at, subscription_token
        """,
        (user_id, product["id"], expires_at, req.source, sub_token),
      )
      sub = cur.fetchone()

      # If this is an xout product, eagerly provision xout_node_users
      # for every node the selector targets so /sub/{token} can build
      # URIs immediately. The agent on each node will pick up these
      # rows on its next sync.
      cur.execute(
        "SELECT inbound_selector FROM xout_products WHERE product_id = %s",
        (product["id"],),
      )
      xp_row = cur.fetchone()
      if xp_row is not None:
        import uuid as _uuid
        selector = xp_row["inbound_selector"] or {}
        for node_entry in selector.get("nodes") or []:
          node_name = node_entry.get("name")
          if not node_name:
            continue
          new_uuid = str(_uuid.uuid4())
          cur.execute(
            """
            INSERT INTO xout_node_users
              (node_name, user_id, vless_uuid, provisioned_at, last_seen_at)
            VALUES (%s, %s, %s::uuid, NOW(), NOW())
            ON CONFLICT (node_name, user_id) DO NOTHING
            """,
            (node_name, user_id, new_uuid),
          )
    conn.commit()
  return {"subscription_id": sub["id"], "starts_at": sub["starts_at"],
          "expires_at": sub["expires_at"],
          # Returning the token here lets the operator paste / preview the
          # /sub/{token} URL right after granting, without a second
          # round-trip to /api/admin/users/{id}.
          "subscription_token": sub["subscription_token"]}


@app.post("/api/admin/users/{user_id}/revoke", dependencies=[Depends(require_admin)])
def admin_revoke_subscription(user_id: str, body: dict) -> dict:
  """Cancel an active subscription. Body: {product_code}.

  Marks the subscriptions row as 'canceled' (matching the DB CHECK
  constraint). xout's next active-users sync (≤30s) will pick up the
  state change and remove the user from xray. /sub/{token} starts
  returning 404 immediately.
  """
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
               created_at, updated_at
        FROM products ORDER BY id ASC
        """
      )
      rows = cur.fetchall()
  return {"products": rows}


@app.post("/api/admin/products", dependencies=[Depends(require_admin)])
def admin_create_product(req: ProductCreateRequest) -> dict:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        INSERT INTO products
          (code, kind, price_cents, currency, period_days, stripe_price_id,
           name, description, metadata, active)
        VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s)
        RETURNING id, code, kind, price_cents, currency, period_days,
                  stripe_price_id, name, description, metadata, active
        """,
        (req.code, req.kind, req.price_cents, req.currency, req.period_days,
         req.stripe_price_id, _to_jsonb(req.name), _to_jsonb(req.description),
         _to_jsonb(req.metadata), req.active),
      )
      row = cur.fetchone()
    conn.commit()
  return {"product": row}


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
  price_cents: int | None = Field(default=None, ge=0, le=100_000_000)
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
           name, description, metadata, active)
        VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s)
        RETURNING id, code, kind, price_cents, currency, period_days,
                  name, description, metadata, active, created_at
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
  for k in ("price_cents", "period_days", "active"):
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
        "WHERE product_id = %s AND status = 'active'",
        (product_id,),
      )
      active_n = (cur.fetchone() or {}).get("n", 0)
      if active_n:
        raise HTTPException(
          status_code=409,
          detail=(f"product '{prod['code']}' has {active_n} active "
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
      cur.execute("SELECT 1 FROM subscriptions WHERE subscription_token = %s",
                  (token,))
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
  if not token or len(token) > 200 or not _looks_like_token(token):
    raise HTTPException(status_code=404, detail="not found")
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT s.id, s.user_id::text AS user_id, s.status, s.expires_at,
               p.id AS product_id, p.code, xp.inbound_selector
        FROM subscriptions s
        JOIN products p ON p.id = s.product_id
        LEFT JOIN xout_products xp ON xp.product_id = p.id
        WHERE s.subscription_token = %s
        """,
        (token,),
      )
      row = cur.fetchone()
  # Treat missing tokens, inactive subs, AND past-expiry subs all as
  # 404 — same response so an attacker can't tell which token state
  # they hit. Without the expiry check, a period-product whose
  # expires_at has passed but whose status is still 'active' would
  # keep handing out URIs forever.
  if (row is None
      or row["status"] != "active"
      or (row.get("expires_at") is not None
          and row["expires_at"] <= datetime.now(timezone.utc))):
    raise HTTPException(status_code=404, detail="not found")
  # Refuse to hand out URIs when the user is over their period quota
  # — otherwise clients keep using a stale subscription against a
  # server that's already kicked them out. 410 Gone is the right
  # signal for client subscription updaters.
  with connect() as conn:
    with conn.cursor() as cur:
      q = _ensure_quota_period(cur, row["user_id"], row["product_id"])
    conn.commit()
  if q is not None and q["limit_qty"] and \
     float(q["current_period_consumed"]) >= float(q["limit_qty"]):
    raise HTTPException(status_code=410,
                        detail="quota exceeded for current period")
  # Build the inbound list using the same code path /api/me uses, then
  # render to URIs.
  subs = _user_xout_subscriptions(row["user_id"])
  this_sub = next((s for s in subs if s["subscription_id"] == row["id"]), None)
  if this_sub is None:
    # Either the user_xout_subscriptions filter said no match (sub
    # exists but xout_products row is missing) or the subscription
    # isn't xout. Treat as 404 either way.
    raise HTTPException(status_code=404, detail="not a xout subscription")
  uris = _build_subscription_uris(row["user_id"], row["id"], this_sub["inbounds"])
  body = "\n".join(uris).encode("utf-8")
  if format == "raw":
    return Response(content=body,
                    media_type="text/plain; charset=utf-8",
                    headers={"Cache-Control": "no-store"})
  # Default: base64 (newline-separated URIs, then the whole thing
  # base64-encoded). v2rayN / Streisand / Shadowrocket all expect this.
  import base64 as _b64
  encoded = _b64.b64encode(body).decode("ascii")
  return Response(content=encoded,
                  media_type="text/plain; charset=utf-8",
                  headers={"Cache-Control": "no-store",
                           "Subscription-Userinfo": _build_userinfo_header(row["user_id"], row["product_id"])})


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
# xout now reads/writes the same tables (xout_node_users, usage_events,
# xout_node_inbounds, usage_quotas) directly; user-service no longer
# proxies for it.
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
  product_code: str
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
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT id, code, kind, price_cents, currency, period_days,
               stripe_price_id, name
        FROM products WHERE code = %s AND active = TRUE
        """,
        (req.product_code,),
      )
      product = cur.fetchone()
  if product is None:
    raise HTTPException(status_code=404, detail=f"product not found: {req.product_code}")
  if product["price_cents"] <= 0:
    raise HTTPException(status_code=400, detail="this product is free; no checkout required")
  if not product["stripe_price_id"]:
    raise HTTPException(status_code=400,
                        detail="product has no stripe_price_id — set it via Admin → Products")
  # Reject if the user already has an active subscription to this
  # product. Without this guard a user can re-pay the same product;
  # the webhook ON CONFLICT would record the second payment but
  # never grant a second subscription — money lost.
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "SELECT 1 FROM subscriptions WHERE user_id=%s AND product_id=%s AND status='active'",
        (user["id"], product["id"]),
      )
      if cur.fetchone() is not None:
        raise HTTPException(status_code=409,
                            detail="already subscribed to this product")
  stripe = _stripe_client()
  base = (os.getenv("PUBLIC_URL") or "https://user.develop.cc").rstrip("/")
  success_url = req.success_url or f"{base}/?checkout=success"
  cancel_url = req.cancel_url or f"{base}/?checkout=cancel"
  try:
    session = stripe.checkout.Session.create(
      mode="subscription" if product["kind"] in ("recurring",) else "payment",
      line_items=[{"price": product["stripe_price_id"], "quantity": 1}],
      success_url=success_url,
      cancel_url=cancel_url,
      client_reference_id=str(user["id"]),
      customer_email=user.get("primary_email") or None,
      metadata={
        "user_id": str(user["id"]),
        "product_id": str(product["id"]),
        "product_code": product["code"],
      },
    )
  except Exception as exc:  # noqa: BLE001
    LOGGER.exception("stripe.checkout.session create failed")
    raise HTTPException(status_code=502, detail=f"stripe error: {exc}")
  return {"url": session.url, "session_id": session.id}


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

  meta = data_obj.get("metadata") or {}
  user_id = meta.get("user_id") or data_obj.get("client_reference_id")
  product_id = int(meta.get("product_id") or 0)
  product_code = meta.get("product_code")
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
      cur.execute("SELECT id, kind, period_days FROM products WHERE id = %s", (product_id,))
      product = cur.fetchone()
      if product is None:
        return {"ok": True, "skipped": "product not found"}
      # Insert payment idempotently.
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
         _to_jsonb({"event_type": event_type})),
      )
      payment_row = cur.fetchone()
      if payment_row is None:
        # Already processed — idempotent retry.
        return {"ok": True, "duplicate": True}
      # Auto-grant subscription if not already active. For renewals
      # (invoice.payment_succeeded on a recurring sub the user already
      # has), we *extend* expires_at instead of NO-OPing on conflict;
      # otherwise recurring subs would never expire AND never count
      # the renewal payment as anything that grants more access.
      import secrets as _secrets
      sub_token = _secrets.token_urlsafe(24)
      expires_at = None
      period = product["period_days"] or 30  # fallback for kind=recurring without period_days
      if product["kind"] in ("period", "recurring") and period:
        expires_at = datetime.now(timezone.utc) + timedelta(days=period)
      cur.execute(
        """
        SELECT id, expires_at FROM subscriptions
        WHERE user_id=%s AND product_id=%s AND status='active'
        """,
        (user_id, product_id),
      )
      existing_sub = cur.fetchone()
      if existing_sub is None:
        cur.execute(
          """
          INSERT INTO subscriptions
            (user_id, product_id, status, starts_at, expires_at, source,
             subscription_token, metadata)
          VALUES (%s, %s, 'active', NOW(), %s, 'stripe', %s, %s::jsonb)
          RETURNING id
          """,
          (user_id, product_id, expires_at, sub_token,
           _to_jsonb({"stripe_payment_id": payment_row["id"]})),
        )
        sub_row = cur.fetchone()
      elif expires_at is not None:
        # Renewal — extend expiry from the later of (now, current expiry)
        # so users who renew early don't lose remaining time.
        from_dt = max(datetime.now(timezone.utc),
                       (existing_sub["expires_at"] or datetime.now(timezone.utc)))
        new_exp = from_dt + timedelta(days=period)
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
        sub_row = None
      # If a subscription was just created and it's an xout product, eagerly
      # provision xout_node_users so /sub/{token} works immediately.
      if sub_row is not None:
        cur.execute(
          "SELECT inbound_selector FROM xout_products WHERE product_id = %s",
          (product_id,),
        )
        xp = cur.fetchone()
        if xp is not None:
          import uuid as _uuid
          for n in (xp["inbound_selector"] or {}).get("nodes") or []:
            if not n.get("name"):
              continue
            cur.execute(
              """
              INSERT INTO xout_node_users (node_name, user_id, vless_uuid, provisioned_at, last_seen_at)
              VALUES (%s, %s, %s::uuid, NOW(), NOW())
              ON CONFLICT (node_name, user_id) DO NOTHING
              """,
              (n["name"], user_id, str(_uuid.uuid4())),
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
          cur.execute(
            """
            INSERT INTO auth_users (primary_email, display_name, locale, is_admin, status, metadata)
            VALUES (%s, %s, %s, %s, 'active', %s::jsonb)
            RETURNING id::text
            """,
            (synth_email, name or None, DEFAULT_LOCALE, is_first,
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


@app.patch("/api/admin/products/{product_id}", dependencies=[Depends(require_admin)])
def admin_patch_product(product_id: int, req: ProductPatchRequest) -> dict:
  fields: list[str] = []
  params: list[Any] = []
  for k, v in req.model_dump(exclude_unset=True).items():
    if k in ("name", "description", "metadata"):
      fields.append(f"{k} = %s::jsonb")
      params.append(_to_jsonb(v))
    else:
      fields.append(f"{k} = %s")
      params.append(v)
  if not fields:
    raise HTTPException(status_code=400, detail="no fields to update")
  fields.append("updated_at = NOW()")
  params.append(product_id)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        f"UPDATE products SET {', '.join(fields)} WHERE id = %s "
        f"RETURNING id, code, kind, price_cents, currency, period_days, "
        f"stripe_price_id, name, description, metadata, active",
        params,
      )
      row = cur.fetchone()
      if row is None:
        raise HTTPException(status_code=404, detail="product not found")
    conn.commit()
  return {"product": row}
