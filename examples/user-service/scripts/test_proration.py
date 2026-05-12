"""End-to-end test for the Stripe webhook subscription/proration logic.

Runs inside the user-service container so we have ``app.main`` and the
real DB connection. Calls ``_handle_stripe_webhook_event`` directly
with synthetic Stripe event payloads, then SQL-asserts the resulting
subscription state.

Run with:

    docker cp examples/user-service/scripts/test_proration.py user:/tmp/
    docker exec user python /tmp/test_proration.py

(Or copy + exec via the admin Commands page.)

Each scenario uses a fresh test email so runs are isolated. We DO
write to the production DB (subscriptions / payments rows) under the
test user — cleanup at the end deletes those rows.
"""

from __future__ import annotations

import sys
import time
import uuid as _uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/app")

from app.db import connect            # noqa: E402
from app.main import (                # noqa: E402
    _build_checkout_preview,
    _compute_upgrade_credit,
    _handle_stripe_webhook_event,
)


def db_exec(sql: str, params: tuple = ()):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            try:
                return cur.fetchall()
            except Exception:
                return None
        conn.commit()


def db_commit(sql: str, params: tuple = ()):
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
        conn.commit()


def make_user(email: str) -> str:
    """Create a bare auth_users row + tier_free + signup_7day_basic
    grant exactly the way /api/auth/signup-confirm does. Returns the
    user id."""
    uid = str(_uuid.uuid4())
    # username has a NOT NULL constraint; mirror the email's local-part
    # the way the real signup flow does.
    username = email.split("@", 1)[0]
    db_commit(
        """
        INSERT INTO auth_users (id, primary_email, username, status,
                                  created_at, updated_at)
        VALUES (%s, %s, %s, 'active', NOW(), NOW())
        """,
        (uid, email, username),
    )
    # Free tier grant (no expiry)
    db_commit(
        """
        INSERT INTO subscriptions (user_id, product_id, status, starts_at,
                                    expires_at, source, metadata)
        SELECT %s, id, 'active', NOW(), NULL, 'grant', '{}'::jsonb
        FROM products WHERE code='tier_free' AND active=TRUE LIMIT 1
        """,
        (uid,),
    )
    # 7-day basic trial (the situation real users land in after signup)
    db_commit(
        """
        INSERT INTO subscriptions (user_id, product_id, status, starts_at,
                                    expires_at, source, metadata)
        SELECT %s, id, 'active', NOW(), NOW() + INTERVAL '7 days', 'grant',
               jsonb_build_object('reason', 'signup_7day_basic')
        FROM products WHERE code='tier_basic' AND active=TRUE LIMIT 1
        """,
        (uid,),
    )
    return uid


def product_id_for(code: str) -> int:
    rows = db_exec("SELECT id FROM products WHERE code=%s", (code,))
    assert rows, f"product {code} not found"
    return int(rows[0]["id"])


def fetch_subs(user_id: str) -> list[dict]:
    """All subscriptions for the user, latest first."""
    return db_exec(
        """
        SELECT s.id, p.code, s.status, s.starts_at, s.expires_at, s.source,
               s.metadata
        FROM subscriptions s JOIN products p ON p.id = s.product_id
        WHERE s.user_id = %s
        ORDER BY s.created_at DESC
        """,
        (user_id,),
    ) or []


def fake_event(
    event_id: str,
    user_id: str,
    product_code: str,
    duration_months: int,
    amount_cents: int,
    credit_applied_cents: int = 0,
    credit_source_sub_ids: list[int] | None = None,
) -> tuple[str, str, dict, bytes]:
    """Mirror the shape of a real Stripe checkout.session.completed
    payload — just the fields the handler reads.

    For the new-flow tests (credit applied at checkout), pass
    ``credit_applied_cents`` + the IDs of the lower-tier subs that
    backed the credit. The webhook should then skip bonus_days and
    cancel exactly those subs.
    """
    pid = product_id_for(product_code)
    meta = {
        "user_id": user_id,
        "product_id": str(pid),
        "product_code": product_code,
        "duration_months": str(duration_months),
        "discount_pct": "0",
        "offer_id": "0",
    }
    if credit_applied_cents > 0:
        meta["credit_applied_cents"] = str(credit_applied_cents)
        meta["credit_source_sub_ids"] = ",".join(
            str(i) for i in (credit_source_sub_ids or [])
        )
    data_obj = {
        "object": "checkout.session",
        "id": f"cs_test_{event_id}",
        "payment_intent": f"pi_test_{event_id}",
        "amount_total": amount_cents,
        "currency": "usd",
        "metadata": meta,
    }
    return event_id, "checkout.session.completed", data_obj, b"{}"


def cleanup(user_id: str):
    """Remove test rows so the prod DB doesn't accumulate noise."""
    db_commit("DELETE FROM payments WHERE user_id=%s", (user_id,))
    db_commit("DELETE FROM subscriptions WHERE user_id=%s", (user_id,))
    db_commit("DELETE FROM usage_quotas WHERE user_id=%s", (user_id,))
    db_commit("DELETE FROM accounts WHERE user_id=%s", (user_id,))
    db_commit("DELETE FROM auth_users WHERE id=%s", (user_id,))


def assert_close_days(actual: timedelta, expected_days: float, tol_hours: float = 12.0):
    """Compare timedeltas with a tolerance because clock-driven math
    accumulates seconds during the test run."""
    actual_days = actual.total_seconds() / 86400.0
    diff_hours = abs(actual_days - expected_days) * 24.0
    if diff_hours > tol_hours:
        raise AssertionError(
            f"expected ~{expected_days:.3f}d, got {actual_days:.3f}d "
            f"(diff={diff_hours:.2f}h > tol={tol_hours}h)"
        )


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_same_tier_renewal():
    """User has signup_7day_basic; buys tier_basic 1 month.

    Expected: the existing tier_basic row's expires_at extends from
    (now + 7d) by another 30d → new expires_at ≈ now + 37d.
    No new sub row.
    """
    email = f"proration-test-{int(time.time())}-renewal@bitsfactor.dev"
    uid = make_user(email)
    try:
        # Confirm starting state: one basic sub ~7d out
        subs = [s for s in fetch_subs(uid) if s["code"] == "tier_basic"]
        assert len(subs) == 1 and subs[0]["status"] == "active"
        orig_basic_expires = subs[0]["expires_at"]

        ev = fake_event(f"evt_renew_{int(time.time())}", uid, "tier_basic", 1, 500)
        out = _handle_stripe_webhook_event(*ev)
        assert out.get("ok"), f"handler returned: {out}"

        subs_after = [s for s in fetch_subs(uid) if s["code"] == "tier_basic"]
        assert len(subs_after) == 1, f"expected 1 basic sub, got {len(subs_after)}"
        new_exp = subs_after[0]["expires_at"]
        delta = new_exp - orig_basic_expires
        # Same-tier renewal: from_dt = max(now, original_expires_at)
        # = original_expires_at (still in future), so new = original + 30d
        assert_close_days(delta, 30.0)
        print(f"  [renewal] extended {orig_basic_expires} → {new_exp} (Δ ~30 days) ✓")
    finally:
        cleanup(uid)


def test_upgrade_with_proration():
    """User has signup_7day_basic; buys tier_pro 1 month.

    Expected:
      - The basic sub gets status='canceled' with metadata.replaced_by
      - A new tier_pro sub is created with expires_at = now + 30 + bonus
      - bonus = 7 × (basic_monthly / pro_monthly) = 7 × (500/1000) = 3.5 days
        (approximately — depends on actual time the trial has left)
    """
    email = f"proration-test-{int(time.time())}-upgrade@bitsfactor.dev"
    uid = make_user(email)
    try:
        # Trial set up at "now"; bonus_days will be ~7 × 500/1000 = 3.5d
        # but slightly less because trial countdown started.
        orig_basic_subs = [s for s in fetch_subs(uid) if s["code"] == "tier_basic"]
        assert len(orig_basic_subs) == 1 and orig_basic_subs[0]["status"] == "active"
        trial_expires = orig_basic_subs[0]["expires_at"]
        remaining_days = (
            trial_expires - datetime.now(timezone.utc)
        ).total_seconds() / 86400.0
        expected_bonus = remaining_days * 500 / 1000  # basic vs pro monthly cents

        ev = fake_event(f"evt_upgrade_{int(time.time())}", uid, "tier_pro", 1, 1000)
        out = _handle_stripe_webhook_event(*ev)
        assert out.get("ok"), f"handler returned: {out}"

        subs_after = fetch_subs(uid)
        basic_after = [s for s in subs_after if s["code"] == "tier_basic"]
        pro_after = [s for s in subs_after if s["code"] == "tier_pro"]
        assert len(basic_after) == 1 and basic_after[0]["status"] == "canceled", (
            f"basic should be canceled, got {basic_after}"
        )
        assert len(pro_after) == 1 and pro_after[0]["status"] == "active", (
            f"expected 1 active pro sub, got {pro_after}"
        )
        # basic row should carry replaced_by_sub_id pointing at the new pro
        basic_meta = basic_after[0]["metadata"] or {}
        assert basic_meta.get("replaced_by_sub_id") == pro_after[0]["id"], (
            f"replaced_by linkage missing/wrong: {basic_meta}"
        )
        # pro row should carry bonus_days_from_upgrade
        pro_meta = pro_after[0]["metadata"] or {}
        recorded_bonus = float(pro_meta.get("bonus_days_from_upgrade") or 0)
        # And the actual expires_at should reflect that
        pro_total_days = (
            pro_after[0]["expires_at"] - datetime.now(timezone.utc)
        ).total_seconds() / 86400.0
        # expected = 30 + bonus
        assert_close_days(timedelta(days=pro_total_days), 30 + expected_bonus, tol_hours=12.0)
        print(
            f"  [upgrade] basic canceled, pro created "
            f"with bonus={recorded_bonus:.3f}d (expected ~{expected_bonus:.3f}d), "
            f"pro total {pro_total_days:.3f}d ✓"
        )
    finally:
        cleanup(uid)


def test_fresh_purchase():
    """A user with no chat subscription buys tier_basic 1 month.

    Pre-condition: kill the trial so the user is truly sub-less for
    tier_basic. tier_free row remains — and the handler must leave
    it alone (no expires_at means it's the permanent fallback floor).

    Expected: brand-new tier_basic row, expires_at ≈ now + 30d. The
    tier_free row remains 'active' and untouched.
    """
    email = f"proration-test-{int(time.time())}-fresh@bitsfactor.dev"
    uid = make_user(email)
    try:
        # Remove the signup trial so we start clean for tier_basic
        db_commit(
            "DELETE FROM subscriptions WHERE user_id=%s AND product_id=%s",
            (uid, product_id_for("tier_basic")),
        )

        ev = fake_event(f"evt_fresh_{int(time.time())}", uid, "tier_basic", 1, 500)
        out = _handle_stripe_webhook_event(*ev)
        assert out.get("ok"), f"handler returned: {out}"

        subs_after = fetch_subs(uid)
        basic_after = [s for s in subs_after if s["code"] == "tier_basic"]
        free_after = [s for s in subs_after if s["code"] == "tier_free"]
        assert len(basic_after) == 1 and basic_after[0]["status"] == "active"
        exp = basic_after[0]["expires_at"]
        delta = exp - datetime.now(timezone.utc)
        assert_close_days(delta, 30.0)
        # tier_free's permanent grant must be untouched.
        assert len(free_after) == 1 and free_after[0]["status"] == "active", (
            f"tier_free row should remain active untouched: {free_after}"
        )
        assert free_after[0]["expires_at"] is None
        print(
            f"  [fresh] new basic sub created (expires in {delta.days}d); "
            f"tier_free untouched ✓"
        )
    finally:
        cleanup(uid)


def test_upgrade_preserves_free_tier():
    """Upgrade case: tier_basic trial → tier_pro purchase.

    Same as test_upgrade_with_proration but explicitly asserts the
    permanent tier_free grant survives the upgrade. This is the
    regression test for the bug where the proration loop initially
    canceled tier_free (because it has rank 0 < pro rank 2)."""
    email = f"proration-test-{int(time.time())}-upfree@bitsfactor.dev"
    uid = make_user(email)
    try:
        ev = fake_event(f"evt_upfree_{int(time.time())}", uid, "tier_pro", 1, 1000)
        out = _handle_stripe_webhook_event(*ev)
        assert out.get("ok"), f"handler returned: {out}"

        subs = fetch_subs(uid)
        free_after = [s for s in subs if s["code"] == "tier_free"]
        assert len(free_after) == 1 and free_after[0]["status"] == "active", (
            f"tier_free must survive upgrade: {free_after}"
        )
        # tier_basic should be cancelled (it had an expiry → time-bound)
        basic_after = [s for s in subs if s["code"] == "tier_basic"]
        assert len(basic_after) == 1 and basic_after[0]["status"] == "canceled"
        # tier_pro is the new active
        pro_after = [s for s in subs if s["code"] == "tier_pro"]
        assert len(pro_after) == 1 and pro_after[0]["status"] == "active"
        print("  [upgrade-preserves-free] tier_free survived, basic cancelled ✓")
    finally:
        cleanup(uid)


def test_idempotency():
    """Same event delivered twice — second delivery must be a no-op."""
    email = f"proration-test-{int(time.time())}-idem@bitsfactor.dev"
    uid = make_user(email)
    try:
        ev_id = f"evt_idem_{int(time.time())}"
        ev = fake_event(ev_id, uid, "tier_basic", 1, 500)
        out1 = _handle_stripe_webhook_event(*ev)
        out2 = _handle_stripe_webhook_event(*ev)
        assert out1.get("ok") and out2.get("ok"), f"{out1} / {out2}"
        assert out2.get("duplicate") is True, f"second call should be duplicate: {out2}"
        # State should reflect ONE renewal only — total ~37d (trial + 30d)
        subs_after = [s for s in fetch_subs(uid) if s["code"] == "tier_basic"]
        assert len(subs_after) == 1
        delta = (
            subs_after[0]["expires_at"] - datetime.now(timezone.utc)
        ).total_seconds() / 86400.0
        # ~7 (trial remaining) + 30 = 37
        if not 36.0 < delta < 38.0:
            raise AssertionError(f"idempotency failed: expires_at delta={delta:.2f}d, expected ~37")
        print(f"  [idem] second delivery no-op, single 37d extension ✓")
    finally:
        cleanup(uid)


def test_preview_no_lower_sub():
    """User without trial / paid sub → preview returns credit 0."""
    email = f"proration-test-{int(time.time())}-prev-fresh@bitsfactor.dev"
    uid = make_user(email)
    try:
        db_commit(
            "DELETE FROM subscriptions WHERE user_id=%s AND product_id=%s",
            (uid, product_id_for("tier_basic")),
        )
        preview = _build_checkout_preview(uid, "tier_pro", 1)
        assert preview["base_price_cents"] == 1000
        assert preview["credit_cents"] == 0
        assert preview["final_price_cents"] == 1000
        assert preview["is_upgrade"] is False
        print("  [preview/no-sub] credit=0 ✓")
    finally:
        cleanup(uid)


def test_preview_trial_to_pro():
    """signup_7day_basic (7d remaining) → upgrade to pro 1mo.

    Credit = remaining_days × (basic_monthly_cents / 30)
           ≈ 7 × (500/30) = ~117 cents.
    """
    email = f"proration-test-{int(time.time())}-prev-up@bitsfactor.dev"
    uid = make_user(email)
    try:
        preview = _build_checkout_preview(uid, "tier_pro", 1)
        assert preview["base_price_cents"] == 1000
        # Allow ±3c for the few seconds of trial countdown during the test
        assert 110 <= preview["credit_cents"] <= 120, preview
        assert preview["final_price_cents"] == 1000 - preview["credit_cents"]
        assert preview["is_upgrade"] is True
        assert len(preview["credit_source"]) == 1
        assert preview["credit_source"][0]["product_code"] == "tier_basic"
        print(
            f"  [preview/trial→pro] credit={preview['credit_cents']}c, "
            f"final={preview['final_price_cents']}c ✓"
        )
    finally:
        cleanup(uid)


def test_preview_same_tier_returns_zero():
    """User on tier_basic buys tier_basic again → credit 0 (renewal,
    not upgrade)."""
    email = f"proration-test-{int(time.time())}-prev-same@bitsfactor.dev"
    uid = make_user(email)
    try:
        preview = _build_checkout_preview(uid, "tier_basic", 1)
        assert preview["base_price_cents"] == 500
        assert preview["credit_cents"] == 0
        assert preview["is_upgrade"] is False
        print("  [preview/same-tier] credit=0 ✓")
    finally:
        cleanup(uid)


def test_webhook_with_credit_applied_no_bonus_days():
    """Simulate the new flow: checkout already applied the credit and
    set ``credit_applied_cents`` in session metadata. Webhook should
    cancel exactly those subs but NOT add bonus_days — expires_at =
    now + 30d exact.
    """
    email = f"proration-test-{int(time.time())}-new-flow@bitsfactor.dev"
    uid = make_user(email)
    try:
        # Use preview to know which sub backs the credit
        preview = _build_checkout_preview(uid, "tier_pro", 1)
        source_sub_ids = [s["sub_id"] for s in preview["credit_source"]]
        assert source_sub_ids, "expected at least one source sub"
        # Stripe charged the user only final_price_cents
        ev = fake_event(
            event_id=f"evt_newflow_{int(time.time())}",
            user_id=uid,
            product_code="tier_pro",
            duration_months=1,
            amount_cents=preview["final_price_cents"],
            credit_applied_cents=preview["credit_cents"],
            credit_source_sub_ids=source_sub_ids,
        )
        out = _handle_stripe_webhook_event(*ev)
        assert out.get("ok"), out
        subs = fetch_subs(uid)
        pro = [s for s in subs if s["code"] == "tier_pro"]
        basic = [s for s in subs if s["code"] == "tier_basic"]
        assert len(pro) == 1 and pro[0]["status"] == "active"
        assert len(basic) == 1 and basic[0]["status"] == "canceled"
        # Crucial: pro_expires = now + 30d EXACTLY (no bonus). Allow
        # 12h tolerance for clock drift during the test.
        delta = (
            pro[0]["expires_at"] - datetime.now(timezone.utc)
        ).total_seconds() / 86400.0
        assert_close_days(timedelta(days=delta), 30.0, tol_hours=12.0)
        # Metadata should reflect the new flow
        pro_meta = pro[0]["metadata"] or {}
        assert pro_meta.get("credit_applied_cents") == preview["credit_cents"], (
            f"credit_applied_cents missing/wrong: {pro_meta}"
        )
        assert "bonus_days_from_upgrade" not in pro_meta, (
            "new-flow row should NOT have bonus_days metadata"
        )
        # Source sub gets the replaced_by linkage
        basic_meta = basic[0]["metadata"] or {}
        assert basic_meta.get("replaced_by_sub_id") == pro[0]["id"]
        print(
            f"  [new-flow] credit=${preview['credit_cents']/100:.2f}, "
            f"pro={delta:.2f}d (no bonus), basic canceled ✓"
        )
    finally:
        cleanup(uid)


def main():
    print("=" * 60)
    print("Stripe webhook proration — end-to-end test")
    print("=" * 60)
    test_same_tier_renewal()
    test_upgrade_with_proration()
    test_upgrade_preserves_free_tier()
    test_fresh_purchase()
    test_idempotency()
    print("-- preview API + new flow --")
    test_preview_no_lower_sub()
    test_preview_trial_to_pro()
    test_preview_same_tier_returns_zero()
    test_webhook_with_credit_applied_no_bonus_days()
    print("\nAll tests passed.")


if __name__ == "__main__":
    main()
