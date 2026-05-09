"""Auth primitives — password hashing, session tokens, cookie helpers.

Hash:
  argon2id, default parameters from argon2-cffi (memory_cost=64MB, time_cost=3,
  parallelism=4). Plenty for a v1 user service; we tune later when we
  see real load.

Sessions:
  Cookie value is a 32-byte random token (urlsafe-base64 → ~43 chars).
  We store ``sha256(token)`` in ``auth_sessions.token_hash`` so a DB
  leak doesn't immediately surrender usable cookies.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError, VerificationError

from .db import connect


_HASHER = PasswordHasher()

SESSION_COOKIE_NAME = "user_sid"
SESSION_DEFAULT_LIFETIME = timedelta(days=30)


def hash_password(plain: str) -> str:
  return _HASHER.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
  try:
    _HASHER.verify(hashed, plain)
    return True
  except (VerifyMismatchError, InvalidHashError, VerificationError):
    return False


def needs_rehash(hashed: str) -> bool:
  try:
    return _HASHER.check_needs_rehash(hashed)
  except (InvalidHashError, VerificationError):
    return False


def _hash_token(token: str) -> str:
  return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_session(user_id: str, *, ip: str | None = None, ua: str | None = None,
                  lifetime: timedelta = SESSION_DEFAULT_LIFETIME) -> str:
  """Create a new session row and return the cookie value (the plaintext
  token). Caller sets the cookie on the response."""
  token = secrets.token_urlsafe(32)
  token_hash = _hash_token(token)
  now = datetime.now(timezone.utc)
  expires = now + lifetime
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        INSERT INTO auth_sessions
          (token_hash, user_id, created_at, expires_at, last_used_at, ip, user_agent)
        VALUES (%s, %s, NOW(), %s, NOW(), %s, %s)
        """,
        (token_hash, user_id, expires, ip, ua),
      )
    conn.commit()
  return token


def lookup_session(token: str) -> dict | None:
  """Return the user row for a valid (non-expired) session, else None.
  Also bumps last_used_at."""
  if not token:
    return None
  token_hash = _hash_token(token)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        """
        SELECT u.id::text AS id, u.username, u.primary_email, u.locale,
               u.display_name, u.is_admin, u.status, u.metadata,
               u.email_verified_at,
               u.subscription_token, u.vless_uuid::text AS vless_uuid
        FROM auth_sessions s
        JOIN auth_users u ON u.id = s.user_id
        WHERE s.token_hash = %s
          AND s.expires_at > NOW()
          AND u.status = 'active'
        """,
        (token_hash,),
      )
      row = cur.fetchone()
      if row is None:
        return None
      cur.execute(
        "UPDATE auth_sessions SET last_used_at = NOW() WHERE token_hash = %s",
        (token_hash,),
      )
    conn.commit()
  return row


def revoke_session(token: str) -> bool:
  if not token:
    return False
  token_hash = _hash_token(token)
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "DELETE FROM auth_sessions WHERE token_hash = %s RETURNING token_hash",
        (token_hash,),
      )
      ok = cur.fetchone() is not None
    conn.commit()
  return ok


def revoke_all_user_sessions(user_id: str) -> int:
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute(
        "DELETE FROM auth_sessions WHERE user_id = %s",
        (user_id,),
      )
      n = cur.rowcount or 0
    conn.commit()
  return n


def cleanup_expired_sessions() -> int:
  """Best-effort GC; called from a periodic task or admin endpoint."""
  with connect() as conn:
    with conn.cursor() as cur:
      cur.execute("DELETE FROM auth_sessions WHERE expires_at < NOW()")
      n = cur.rowcount or 0
    conn.commit()
  return n
