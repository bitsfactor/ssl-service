# Backend endpoints needed from user-service

These endpoints are called by user-center pages but are not yet implemented in
user-service. Until they exist the relevant UI sections show placeholder states
rather than live data.

---

## Already available (used today)

| Method | Path           | Used by                      |
|--------|----------------|------------------------------|
| GET    | /api/me        | Every page (auth gate)       |
| GET    | /api/me/usage  | Dashboard, Billing           |
| GET    | /api/products  | Billing page — plans table   |
| GET    | /api/pricing   | Billing page — model pricing |
| POST   | /api/auth/login    | Login form                |
| POST   | /api/auth/logout   | Sign-out button           |
| POST   | /api/auth/register | Registration form         |

---

## Missing — needed for full feature set

### PATCH /api/me
Update the current user's profile fields.

**Request body** (all optional):
```json
{
  "display_name": "Alice",
  "locale": "zh"
}
```

**Success response** `200`: the updated `UserProfile` object.

Used by: `app/(protected)/profile/profile-client.tsx`

---

### POST /api/me/password
Change the current user's password.

**Request body**:
```json
{
  "current_password": "old-pass",
  "new_password": "new-pass-min-8-chars"
}
```

**Success response** `200`: `{ "ok": true }`

**Error response** `400`: `{ "detail": "Current password is incorrect" }`

Used by: `app/(protected)/security/security-client.tsx`

---

### GET /api/me/sessions
List all active sessions for the current user.

**Response** `200`:
```json
[
  {
    "id": "sess_abc123",
    "created_at": "2026-05-01T10:00:00Z",
    "last_seen_at": "2026-05-09T08:30:00Z",
    "user_agent": "Mozilla/5.0 ...",
    "ip": "1.2.3.4",
    "is_current": true
  }
]
```

Used by: `app/(protected)/security/security-client.tsx` (currently shows placeholder)

---

### DELETE /api/me/sessions/{id}
Revoke a specific session (or pass `all` to revoke all sessions).

**Path param**: `id` — session ID, or the literal string `all`

**Success response** `200`: `{ "ok": true }`

Note: revoking `all` should include the current session (user will be logged out).

Used by: `app/(protected)/security/security-client.tsx` ("Sign out everywhere" button)

---

### POST /api/auth/verify-email
Verify an email address using the token from the verification email.

**Request body**:
```json
{ "token": "<jwt-from-email>" }
```

**Success response** `200`: `{ "ok": true }`

**Error response** `400`: `{ "detail": "Token is invalid or expired" }`

Used by: `app/auth/verify-email/verify-email-client.tsx`

---

## Notes

- All endpoints require a valid session cookie (`session` / `access_token` — whatever
  name user-service uses). user-center forwards the browser's cookies on every
  server-side fetch via `lib/api/server.ts::serverFetch()`.
- Error bodies should follow `{ "detail": "human-readable message" }` so the
  frontend can surface them directly to the user.
- No new auth mechanism is needed — user-center piggybacks on the same session
  that user-service already issues.
