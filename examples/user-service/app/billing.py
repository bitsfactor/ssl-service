"""In-memory billing engine for the AI tier subscription model.

Design (see ssl-service/docs/billing-design-v2.md):

- Each AI request → caller POSTs ``/api/usage/charge`` with token counts
  and the model id.
- We compute cost in micro-USD using ``model_pricing`` × ``discount_factor``.
- Deduct against the user's currently-active highest-tier ``usage_quotas``
  row. ``tier_free`` users draw down a one-time $2 trial; paid tiers draw
  down a daily allowance that resets at UTC midnight.
- **DB writes are deferred.** Every charge accumulates in a per-user
  in-memory delta + a list of pending events. A background flush task
  writes the deltas back to ``usage_quotas`` and inserts the events
  into ``usage_events`` every ``FLUSH_INTERVAL_SECONDS`` (or sooner if
  buffered events exceed ``FLUSH_BATCH_THRESHOLD``).
- Restart loses pending state — accepted as a small cost (a handful
  of unmetered cents per restart, max).
- Quota state is also cached in memory so the hot path checks
  ``in-memory consumed + pending`` against ``in-memory limit_qty``
  with zero DB hits when the cache is fresh.

Concurrency notes:
- ``threading.Lock`` per-user for the consume path.
- A single global lock around buffer rotation when flushing.
- The flush task is asyncio (FastAPI native) and snapshots-then-writes.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import connect

LOGGER = logging.getLogger("user_service.billing")

# How often the flush task wakes up. Frequent enough that admin queries
# of "today's spend" are within ~5s of reality, infrequent enough that
# we don't hammer the DB.
FLUSH_INTERVAL_SECONDS = 5

# Flush early when buffered events cross this threshold (avoids
# unbounded growth under bursty load).
FLUSH_BATCH_THRESHOLD = 50

# How long an in-memory cached quota row is trusted before we re-read
# from the DB. After this we re-fetch on the next charge to pick up
# admin changes or cross-process writes (Stripe webhook upserts).
QUOTA_TTL_SECONDS = 30


# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------


@dataclass
class _CachedQuota:
    """Snapshot of a usage_quotas row plus an in-memory delta."""

    limit_qty: float                    # daily allowance / lifetime trial in cents
    reset_kind: str                     # "daily" | "never" | ...
    current_period_start: datetime      # UTC
    db_consumed: float                  # what the DB row's consumed was at fetch
    pending_delta: float                # cents charged since last flush
    fetched_at: float                   # monotonic ts


@dataclass
class _PendingEvent:
    """An unflushed usage_events row to insert."""

    user_id: str
    product_id: int
    event: str                          # the model_id, e.g. "gpt-5.4"
    qty: float                          # cents
    metadata: dict[str, Any]


# Keyed by (user_id, product_id). Per-key lock guards mutations.
_QUOTAS: dict[tuple[str, int], _CachedQuota] = {}
_USER_LOCKS: dict[str, threading.Lock] = {}
_USER_LOCKS_LOCK = threading.Lock()

# Pending event buffer — flushed in batches.
_EVENT_BUFFER: list[_PendingEvent] = []
_EVENT_BUFFER_LOCK = threading.Lock()

# Pending quota deltas — keyed by (user_id, product_id), value = pending cents
# (we keep this separate from _QUOTAS for clean snapshot semantics).
_PENDING_DELTAS: dict[tuple[str, int], float] = {}
_PENDING_DELTAS_LOCK = threading.Lock()

# Idempotency dedupe: which (user_id, event, resource_id) triples we
# accepted recently. Bounded — drops oldest after MAX_IDEMP_KEYS.
_IDEMP_SEEN: set[tuple[str, str, str]] = set()
_IDEMP_LOCK = threading.Lock()
_MAX_IDEMP_KEYS = 5000


def _user_lock(user_id: str) -> threading.Lock:
    with _USER_LOCKS_LOCK:
        lock = _USER_LOCKS.get(user_id)
        if lock is None:
            lock = threading.Lock()
            _USER_LOCKS[user_id] = lock
        return lock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _today_utc_midnight() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _is_quota_stale(q: _CachedQuota) -> bool:
    return (time.monotonic() - q.fetched_at) > QUOTA_TTL_SECONDS


def _maybe_roll_period(q: _CachedQuota) -> _CachedQuota:
    """In-memory period roll for daily quotas.

    Note: this touches only the in-memory mirror; the DB UPDATE is
    deferred to the flush task. If multiple charges happen between
    rolls we stay consistent because pending_delta is reset as part
    of the roll.
    """
    if q.reset_kind != "daily":
        return q
    today = _today_utc_midnight()
    if q.current_period_start < today:
        # Roll: zero out consumed + pending, advance period_start.
        # The flush task will clobber the DB row's current_period_start
        # next cycle.
        q.current_period_start = today
        q.db_consumed = 0.0
        q.pending_delta = 0.0
    return q


def _fetch_quota_from_db(user_id: str, product_id: int) -> _CachedQuota | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT limit_qty, reset_kind, current_period_start, current_period_consumed
                FROM usage_quotas
                WHERE user_id = %s AND product_id = %s
                """,
                (user_id, product_id),
            )
            row = cur.fetchone()
    if row is None:
        return None
    return _CachedQuota(
        limit_qty=float(row["limit_qty"] or 0),
        reset_kind=row["reset_kind"] or "never",
        current_period_start=row["current_period_start"].astimezone(timezone.utc),
        db_consumed=float(row["current_period_consumed"] or 0),
        pending_delta=0.0,
        fetched_at=time.monotonic(),
    )


def _resolve_active_tier(user_id: str) -> dict | None:
    """Return the user's highest-tier active subscription product row, or None.

    Picks among all rows with status='active' and (expires_at IS NULL OR
    expires_at > now()), ordering by ``products.metadata.tier_rank`` desc.
    """
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.id AS product_id, p.code, p.name, p.metadata, s.id AS sub_id,
                       s.expires_at, s.status
                FROM subscriptions s
                JOIN products p ON p.id = s.product_id
                WHERE s.user_id = %s
                  AND s.status = 'active'
                  AND (s.expires_at IS NULL OR s.expires_at > NOW())
                ORDER BY COALESCE((p.metadata->>'tier_rank')::int, -1) DESC,
                         s.created_at DESC
                LIMIT 1
                """,
                (user_id,),
            )
            row = cur.fetchone()
    return row


def _fetch_model_pricing(model_id: str) -> dict | None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT pricing_kind, modality,
                       input_rate_micros, cached_input_rate_micros, output_rate_micros,
                       per_unit_micros, per_unit_label
                FROM model_pricing
                WHERE model_id = %s AND active = TRUE
                LIMIT 1
                """,
                (model_id,),
            )
            return cur.fetchone()


def _fetch_discount_factor() -> float:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM system_config WHERE key = 'billing.discount_factor'")
            row = cur.fetchone()
    if row is None:
        return 0.8
    v = row["value"]
    if isinstance(v, dict):
        return float(v.get("value", 0.8))
    try:
        return float(v)
    except Exception:
        return 0.8


# Cached for hot path; refreshed by flush task each cycle.
_DISCOUNT_FACTOR: float = 0.8
_DISCOUNT_FETCHED_AT: float = 0.0


def get_discount_factor() -> float:
    """Read the discount factor with a 30s TTL cache."""
    global _DISCOUNT_FACTOR, _DISCOUNT_FETCHED_AT
    if time.monotonic() - _DISCOUNT_FETCHED_AT > 30:
        try:
            _DISCOUNT_FACTOR = _fetch_discount_factor()
            _DISCOUNT_FETCHED_AT = time.monotonic()
        except Exception as e:
            LOGGER.warning("failed to refresh discount factor: %s", e)
    return _DISCOUNT_FACTOR


# ---------------------------------------------------------------------------
# Cost computation
# ---------------------------------------------------------------------------


def compute_cost_cents(
    pricing: dict,
    *,
    input_tokens: int = 0,
    cached_input_tokens: int = 0,
    output_tokens: int = 0,
    duration_seconds: float = 0,
    discount: float = 0.8,
) -> tuple[float, float]:
    """Return (charged_cents, openai_cents).

    Both are floats in cents. We don't quantize to integer cents — the
    quota is double-precision so we keep fractional cents to avoid
    rounding to zero on tiny calls.
    """
    if pricing["pricing_kind"] == "tokens":
        uncached_input = max(0, input_tokens - cached_input_tokens)
        ir = pricing["input_rate_micros"] or 0
        cir = pricing["cached_input_rate_micros"] or pricing["input_rate_micros"] or 0
        or_ = pricing["output_rate_micros"] or 0
        # rates are micro-USD per 1M tokens. token_count × rate / 1M = micro-USD
        raw_micros = (
            uncached_input * ir
            + cached_input_tokens * cir
            + output_tokens * or_
        ) / 1_000_000
    elif pricing["pricing_kind"] == "per_call":
        raw_micros = pricing["per_unit_micros"] or 0
    elif pricing["pricing_kind"] == "per_second":
        raw_micros = (pricing["per_unit_micros"] or 0) * (duration_seconds or 0)
    else:
        raw_micros = 0

    charged_micros = raw_micros * discount
    # 1 micro-USD = 0.0001 cents → divide by 10_000 to get cents
    openai_cents = raw_micros / 10_000.0
    charged_cents = charged_micros / 10_000.0
    return charged_cents, openai_cents


# ---------------------------------------------------------------------------
# Hot path: charge_usage
# ---------------------------------------------------------------------------


@dataclass
class ChargeResult:
    ok: bool
    charged_cents: float
    openai_cents: float
    remaining_cents: float
    limit_cents: float
    tier_code: str
    tier_rank: int
    error: str | None = None


def charge_usage(
    user_id: str,
    *,
    model: str,
    input_tokens: int = 0,
    cached_input_tokens: int = 0,
    output_tokens: int = 0,
    duration_seconds: float = 0,
    resource_id: str | None = None,
    metadata: dict | None = None,
) -> ChargeResult:
    """Apply a usage charge against the user's active tier quota.

    All work happens in memory; the actual DB write is deferred to the
    flush task. Returns a ChargeResult with `ok=False` and `error` set
    if the quota is exhausted or anything else goes wrong.
    """
    # Idempotency check — if this resource_id has already been charged
    # in the current process, return ok with charged_cents=0 (the prior
    # delta is already in pending or DB).
    if resource_id:
        idemp_key = (user_id, model, resource_id)
        with _IDEMP_LOCK:
            if idemp_key in _IDEMP_SEEN:
                LOGGER.debug("dedupe charge resource_id=%s", resource_id)
                return ChargeResult(
                    ok=True, charged_cents=0, openai_cents=0,
                    remaining_cents=0, limit_cents=0,
                    tier_code="?", tier_rank=-1, error="already_charged",
                )

    pricing = _fetch_model_pricing(model)
    if pricing is None:
        return ChargeResult(
            ok=False, charged_cents=0, openai_cents=0,
            remaining_cents=0, limit_cents=0,
            tier_code="?", tier_rank=-1, error=f"unknown_model:{model}",
        )

    tier = _resolve_active_tier(user_id)
    if tier is None:
        return ChargeResult(
            ok=False, charged_cents=0, openai_cents=0,
            remaining_cents=0, limit_cents=0,
            tier_code="?", tier_rank=-1, error="no_active_tier",
        )

    discount = get_discount_factor()
    charged_cents, openai_cents = compute_cost_cents(
        pricing,
        input_tokens=input_tokens,
        cached_input_tokens=cached_input_tokens,
        output_tokens=output_tokens,
        duration_seconds=duration_seconds,
        discount=discount,
    )

    # Floor at 0 — nothing prevents a free op (e.g. 0-token call). We
    # still record it but with cost 0 so it doesn't pollute usage_events
    # with thousands of $0 rows. Skip the deduction & event entirely.
    if charged_cents <= 0:
        return ChargeResult(
            ok=True, charged_cents=0, openai_cents=0,
            remaining_cents=0, limit_cents=0,
            tier_code=tier["code"],
            tier_rank=int((tier["metadata"] or {}).get("tier_rank") or -1),
        )

    pid = int(tier["product_id"])
    key = (user_id, pid)

    with _user_lock(user_id):
        # Get-or-fetch cached quota
        cached = _QUOTAS.get(key)
        if cached is None or _is_quota_stale(cached):
            fresh = _fetch_quota_from_db(user_id, pid)
            if fresh is None:
                # No quota row → tier has no entitlement (shouldn't happen
                # because Stripe webhook / signup creates one). Fail open
                # would lose money; fail closed here.
                return ChargeResult(
                    ok=False, charged_cents=0, openai_cents=0,
                    remaining_cents=0, limit_cents=0,
                    tier_code=tier["code"],
                    tier_rank=int((tier["metadata"] or {}).get("tier_rank") or -1),
                    error="no_quota",
                )
            # Preserve any pending_delta we'd accumulated since the
            # previous fetch — DB just doesn't know about it yet.
            if cached is not None:
                fresh.pending_delta = cached.pending_delta
            _QUOTAS[key] = fresh
            cached = fresh

        # Roll period if needed (in-memory only; DB will catch up on flush)
        cached = _maybe_roll_period(cached)

        consumed_total = cached.db_consumed + cached.pending_delta
        remaining = cached.limit_qty - consumed_total

        if charged_cents > remaining:
            return ChargeResult(
                ok=False, charged_cents=0, openai_cents=openai_cents,
                remaining_cents=max(0.0, remaining),
                limit_cents=cached.limit_qty,
                tier_code=tier["code"],
                tier_rank=int((tier["metadata"] or {}).get("tier_rank") or -1),
                error="quota_exhausted",
            )

        # Commit in memory
        cached.pending_delta += charged_cents
        with _PENDING_DELTAS_LOCK:
            _PENDING_DELTAS[key] = _PENDING_DELTAS.get(key, 0.0) + charged_cents
        with _EVENT_BUFFER_LOCK:
            _EVENT_BUFFER.append(_PendingEvent(
                user_id=user_id,
                product_id=pid,
                event=model,
                qty=charged_cents,
                metadata={
                    "resource_id": resource_id,
                    "model": model,
                    "input_tokens": input_tokens,
                    "cached_input_tokens": cached_input_tokens,
                    "output_tokens": output_tokens,
                    "duration_seconds": duration_seconds,
                    "openai_cents": openai_cents,
                    "discount": discount,
                    "tier_code": tier["code"],
                    **(metadata or {}),
                },
            ))
        if resource_id:
            with _IDEMP_LOCK:
                _IDEMP_SEEN.add(idemp_key)
                if len(_IDEMP_SEEN) > _MAX_IDEMP_KEYS:
                    # Naive eviction: clear half. We err toward losing
                    # idempotency than memory-bloating.
                    _IDEMP_SEEN.clear()

    return ChargeResult(
        ok=True,
        charged_cents=charged_cents,
        openai_cents=openai_cents,
        remaining_cents=remaining - charged_cents,
        limit_cents=cached.limit_qty,
        tier_code=tier["code"],
        tier_rank=int((tier["metadata"] or {}).get("tier_rank") or -1),
    )


# ---------------------------------------------------------------------------
# Read path: today's usage / tier info for /api/me/usage
# ---------------------------------------------------------------------------


def get_usage_summary(user_id: str) -> dict:
    """Return the user's tier + today's spend + remaining.

    Reads the cached quota when fresh, falls back to a DB hit. Cheap.
    """
    tier = _resolve_active_tier(user_id)
    if tier is None:
        return {
            "tier_code": "anonymous",
            "tier_name": {"en": "Anonymous"},
            "limit_cents": 0,
            "consumed_cents": 0,
            "remaining_cents": 0,
            "reset_kind": "never",
            "current_period_start": None,
        }
    pid = int(tier["product_id"])
    key = (user_id, pid)
    cached = _QUOTAS.get(key)
    if cached is None or _is_quota_stale(cached):
        cached = _fetch_quota_from_db(user_id, pid)
        if cached is not None:
            _QUOTAS[key] = cached
    if cached is None:
        return {
            "tier_code": tier["code"],
            "tier_name": tier["name"],
            "tier_metadata": tier["metadata"],
            "limit_cents": 0,
            "consumed_cents": 0,
            "remaining_cents": 0,
            "reset_kind": "never",
            "current_period_start": None,
        }
    cached = _maybe_roll_period(cached)
    consumed_total = cached.db_consumed + cached.pending_delta
    return {
        "tier_code": tier["code"],
        "tier_name": tier["name"],
        "tier_metadata": tier["metadata"],
        "limit_cents": cached.limit_qty,
        "consumed_cents": consumed_total,
        "remaining_cents": max(0.0, cached.limit_qty - consumed_total),
        "reset_kind": cached.reset_kind,
        "current_period_start": cached.current_period_start.isoformat(),
        "discount_factor": get_discount_factor(),
    }


# ---------------------------------------------------------------------------
# Async flush
# ---------------------------------------------------------------------------


async def flush_loop():
    """Background task: periodically flush pending deltas + events to DB.

    Started from main.py's lifespan handler. Runs forever until cancelled.
    """
    LOGGER.info("billing flush loop started (interval=%ds)", FLUSH_INTERVAL_SECONDS)
    while True:
        try:
            await asyncio.sleep(FLUSH_INTERVAL_SECONDS)
            await asyncio.to_thread(flush_now)
        except asyncio.CancelledError:
            LOGGER.info("billing flush loop cancelled, final flush")
            try:
                await asyncio.to_thread(flush_now)
            except Exception:
                LOGGER.exception("final flush failed")
            raise
        except Exception:
            LOGGER.exception("flush loop iteration failed")


def flush_now() -> tuple[int, int]:
    """Snapshot the buffers and write to DB in one transaction.

    Returns (events_inserted, deltas_applied).
    """
    # Snapshot — under locks
    with _EVENT_BUFFER_LOCK:
        events = list(_EVENT_BUFFER)
        _EVENT_BUFFER.clear()
    with _PENDING_DELTAS_LOCK:
        deltas = dict(_PENDING_DELTAS)
        _PENDING_DELTAS.clear()

    if not events and not deltas:
        return 0, 0

    inserted = 0
    applied = 0
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                # 1. Insert events (batch)
                for ev in events:
                    cur.execute(
                        """
                        INSERT INTO usage_events
                          (user_id, product_id, event, qty, source, metadata, ts)
                        VALUES (%s, %s, %s, %s, 'chatbot', %s::jsonb, NOW())
                        ON CONFLICT DO NOTHING
                        """,
                        (
                            ev.user_id,
                            ev.product_id,
                            ev.event,
                            ev.qty,
                            __import__("json").dumps(ev.metadata, default=str),
                        ),
                    )
                    if cur.rowcount:
                        inserted += 1
                # 2. Apply quota deltas
                for (uid, pid), delta in deltas.items():
                    if delta <= 0:
                        continue
                    cur.execute(
                        """
                        UPDATE usage_quotas
                        SET current_period_consumed = current_period_consumed + %s,
                            updated_at = NOW()
                        WHERE user_id = %s AND product_id = %s
                        """,
                        (delta, uid, pid),
                    )
                    applied += cur.rowcount or 0
                    # Also push the cached quota's db_consumed forward so
                    # we don't double-count on next read.
                    key = (uid, pid)
                    cached = _QUOTAS.get(key)
                    if cached is not None:
                        cached.db_consumed += delta
                        cached.pending_delta = max(0.0, cached.pending_delta - delta)
                        cached.fetched_at = time.monotonic()
                # 3. Daily reset for any cached row whose period rolled
                #    in memory — write the new current_period_start back.
                today = _today_utc_midnight()
                for (uid, pid), cached in list(_QUOTAS.items()):
                    if cached.reset_kind == "daily" and cached.current_period_start <= today:
                        cur.execute(
                            """
                            UPDATE usage_quotas
                            SET current_period_start = %s,
                                current_period_consumed = %s,
                                updated_at = NOW()
                            WHERE user_id = %s AND product_id = %s
                              AND current_period_start < %s
                            """,
                            (today, cached.db_consumed, uid, pid, today),
                        )
            conn.commit()
        if inserted or applied:
            LOGGER.debug("flushed %d events, %d quota updates", inserted, applied)
    except Exception:
        LOGGER.exception("flush failed; pushing data back to buffer")
        # Best-effort: stuff the unflushed work back so we retry next
        # interval. Idempotency on usage_events guards double-insert.
        with _EVENT_BUFFER_LOCK:
            _EVENT_BUFFER.extend(events)
        with _PENDING_DELTAS_LOCK:
            for k, v in deltas.items():
                _PENDING_DELTAS[k] = _PENDING_DELTAS.get(k, 0.0) + v
    return inserted, applied
