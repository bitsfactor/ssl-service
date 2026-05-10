# Plan — Commands sidebar in admin SPA

**Status:** proposal, ready to implement
**Owner of next session:** TBD
**Date drafted:** 2026-05-09

---

## Why this exists

The agent's current operational workflow has a major bottleneck. Every time we
need to do something "imperative" (commit + push, redeploy a service, wipe a
remote dir, run a one-shot SQL on the DB, sync a submodule, restart admin) the
loop is:

1. Write a `.command` shell script under `scripts/dev/`.
2. `chmod +x` it.
3. Drive Finder (Cmd+Shift+G → type path → Return).
4. Double-click the `.command` to launch Terminal.
5. Wait, screenshot, parse output, decide next step.

Each cycle costs 30–60 seconds of wall-clock time and a non-trivial chunk of
context (computer-use coordinates, screenshot images, retries when the
double-click misses, etc.). In a single overnight session the agent ran this
loop **12+ times**. The cost compounds because the screenshots themselves
saturate the model's context budget, which means fewer cycles before another
hand-off becomes necessary.

The fix: a **Commands** page inside the admin SPA where every imperative
operation is a button. The operator (or the agent driving the page through
the Chrome MCP) clicks the button, fills any required inputs, and the admin
process executes the work and streams output back inline. No Finder. No
double-click. No `.command` files cluttering `scripts/dev/`.

**Expected payoff:** ~80% reduction in time-per-imperative-action; a much
larger reduction in agent context burn (no more screenshot rounds for git
pushes); commands become first-class, discoverable, repeatable artefacts
that survive across sessions.

---

## Scope (MVP)

A new top-level admin route at `#/commands` rendered as a service-plugin
view (using the existing `uiPageHeader` / `uiCard` / `uiSection` /
`uiToolbar` helpers in `static/index.html`).

### Backend

Three new admin endpoints, all behind `with_auth` (admin token required):

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/local/run` | Run a shell command on the host where admin runs (the operator's Mac). Returns `{stdout, stderr, exit_code, elapsed_ms, cwd}`. Streams optional via SSE later — MVP can be synchronous. |
| `POST` | `/api/local/git/commit-push` | Convenience wrapper for the most common workflow. Body: `{repo_path, message, paths?, allow_empty?, push_to?}`. If `paths` is empty, stages everything in `repo_path`. If `push_to` is omitted, pushes to `origin/<current-branch>`. Returns the same shape as `/api/local/run` plus the resulting SHA. |
| `POST` | `/api/local/repo-sync` | Pull + reset + clean a working tree. Body: `{repo_path, remote?, branch?}`. Used to recover from "uncommitted changes block deploy" scenarios. |

The existing endpoints we'll lean on (already implemented, just need UI):

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/admin/restart` | os.execv the admin process. Already wired into the nav-footer button — the Commands page can re-expose it for completeness. |
| `POST` | `/api/services/{name}/deploy` | Trigger a full service deploy with optional node list. |
| `POST` | `/api/nodes/{name}/run` | Run a shell command on a remote node via the platform's SSH mux. |
| `POST` | `/api/databases/{id}/apply-schema` | Apply `sql/schema.sql` to a registered database. |

**Security model:** every endpoint sits behind the same admin-token auth as
`/api/nodes/{name}/run`. There is no incremental risk — the operator already
has unrestricted shell access via that endpoint.

**Error envelope:** all three new endpoints return on any failure path with
`HTTP 200` body `{ok: false, exit_code: <n>, stdout, stderr, error}` so the
UI can show the failure inline without losing access to the partial output.
Reserve non-200 codes for genuine HTTP-layer errors (auth, malformed body).

**Timeouts:** default 60 s, allow overrides up to 600 s in the body. Long
deploys still go through `/api/services/{name}/deploy` which has its own
timeout machinery — the local-run endpoint is for git / shell glue, not
for shipping container builds.

**Audit log:** persist every successful local-run in a new
`local_command_runs` table: `(id, operator_token_id, command, args_json,
exit_code, started_at, finished_at, output_truncated)`. So if anything weird
happens, there's a trail. Truncate stored output at 64 KiB; full output is
in the immediate response only.

### Frontend

Add `commands` to `NAV_REGISTRY` in `static/index.html`, between
`databases` and `logs`. Render via `renderCommandsView(root)` following the
same service-plugin pattern as the Billing page.

Layout (top to bottom):

```
[ Commands · run common imperative actions on your host or remote nodes ]

╔══ Quick actions ════════════════════════════════════════════════════╗
║  [Restart admin]   [Apply schema (DB picker)]   [Refresh node       ║
║                                                  inventory]         ║
╚═════════════════════════════════════════════════════════════════════╝

╔══ Service deploys ═════════════════════════════════════════════════╗
║  Service: [ chat ▾ ]   Node: [ xcenter ▾ ]                         ║
║  [Deploy now]   [Wipe install dir + Deploy]                        ║
║  [Force rebuild (compose down + up --build --force-recreate)]      ║
║  Last 3 runs:                                                      ║
║   • 12:41 ✓ deploy:user-center → xcenter (16s)                     ║
║   • 12:38 ✓ deploy:chatbot     → xcenter (53s)                     ║
║   • 12:30 ✗ deploy:user-center → xcenter (failed: prerender)       ║
╚════════════════════════════════════════════════════════════════════╝

╔══ Git workflows ═══════════════════════════════════════════════════╗
║  Repo: [ ssl-service ▾ ]                                            ║
║  Commit message: [ ___________________________________________ ]    ║
║  Paths (optional, blank = all): [ ___________________________ ]     ║
║  [Commit + push]                                                    ║
║                                                                     ║
║  Submodule: [ chatbot ▾ ]                                          ║
║  [Sync to chat.git mirror]   [Bump submodule pointer in parent]     ║
╚════════════════════════════════════════════════════════════════════╝

╔══ Database ════════════════════════════════════════════════════════╗
║  DB: [ one ▾ ]                                                      ║
║  [Apply schema]   [Run SQL file…] (file input)                      ║
║  Or paste SQL: [ multiline _______________________ ]   [Run]        ║
╚════════════════════════════════════════════════════════════════════╝

╔══ Free-form ═══════════════════════════════════════════════════════╗
║  Target: [ local ▾ | xcenter | us01 | … ]                           ║
║  Command: [ _______________________________________ ]               ║
║  Working dir: [ /Users/leo-m-a/projects/ssl-service ___________ ]   ║
║  [Run]                                                              ║
╚════════════════════════════════════════════════════════════════════╝

╔══ Output ══════════════════════════════════════════════════════════╗
║  ⏱ 0.4 s · exit 0 · /Users/.../ssl-service                          ║
║  $ git log -1 --oneline                                             ║
║  6da32ad fix(user-center): proxy /sub /sub-qr /product/info to ...  ║
║                                                                     ║
║  [Copy stdout]   [Copy stderr]   [Run again]   [Save as preset]     ║
╚════════════════════════════════════════════════════════════════════╝
```

Each command card has:

- A title + one-line description
- Required form inputs (text, dropdown, checkbox)
- `Run` button (disabled while in flight, shows spinner)
- Inline output panel (last result, ~5 KiB inline; "show full" link
  reveals the rest)
- A small "history" link that opens a modal listing the last 25 runs
  for that command, with one-click "re-run with same args"

### Initial command catalog (the high-frequency ones we hit tonight)

These are the buttons the operator should be able to click with no input
beyond a confirm dialog, plus the parametrised ones used in this session:

**Quick actions (no input):**
- Restart admin
- Reload Caddy config (if the route reconciler is stuck)
- Refresh service catalog from local repo (re-read `service-source/*/.deploy.yaml`)

**Service deploys (service + node + flag inputs):**
- chat / chatbot / user / user-center / vpsbox / xout
- Flag: "force rebuild" (passes `--build --force-recreate` extra arg)
- Flag: "wipe install dir before deploy" (rms `/opt/<svc>` first)

**Git workflows:**
- ssl-service: commit + push (message input)
- chatbot submodule: commit + push (message input) — pushes to chatbot.git
- Bump chatbot submodule pointer in ssl-service parent
- Sync chatbot HEAD to chat.git mirror (force-push opt-in checkbox)
- Discard local changes + pull origin (recovery action)

**Database:**
- Apply schema (DB picker)
- Run pasted SQL (DB picker + textarea)
- Migrate `accounts` table (one-shot helper for the v4 trial migration)

**Remote node ops:**
- xcenter: stop + remove orphaned `chat` lobehub container
- xcenter: docker compose pull + up -d --force-recreate (per service)
- us01: clear stale Caddy retry locks
- Any node: free-form `docker logs --tail 50 <container>`

### Persistence model

Two new tables in the home schema:

```sql
CREATE TABLE IF NOT EXISTS commands_catalog (
  id            TEXT PRIMARY KEY,           -- e.g. 'deploy.user-center'
  title         TEXT NOT NULL,
  description   TEXT,
  category      TEXT NOT NULL,              -- 'quick' | 'deploy' | 'git' | 'db' | 'remote' | 'free'
  schema        JSONB NOT NULL,             -- input field spec
  exec          JSONB NOT NULL,             -- {kind: 'local-run' | 'service-deploy' | …, args: {…}}
  is_builtin    BOOLEAN NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS command_runs (
  id            BIGSERIAL PRIMARY KEY,
  command_id    TEXT NOT NULL REFERENCES commands_catalog(id) ON DELETE CASCADE,
  args_json     JSONB NOT NULL,
  status        TEXT NOT NULL,              -- 'running' | 'success' | 'failed'
  exit_code     INTEGER,
  stdout_head   TEXT,                       -- first 64 KiB
  stderr_head   TEXT,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at   TIMESTAMPTZ
);
CREATE INDEX command_runs_recent_idx ON command_runs (command_id, started_at DESC);
```

Built-in commands seed via `INSERT … ON CONFLICT DO NOTHING` from `sql/schema.sql`
so they're always available even on a fresh install. Operator can add custom
commands via a "+ New command" button (the form is just the same JSON shape
as a builtin).

---

## Phasing

**Phase 1 — MVP (~1 day):**
- Backend: `/api/local/run`, `/api/local/git/commit-push`, `/api/local/repo-sync`
- Backend: `commands_catalog` + `command_runs` tables + seed
- Frontend: `Commands` nav entry, hardcoded form for the 5 categories above
- 5 builtin commands seeded: restart-admin, deploy-service, git-commit-push,
  apply-schema, free-form-run
- Inline output panel (synchronous, no streaming)
- 30-round review pass on the new code

**Phase 2 — quality of life (~half day):**
- SSE streaming output (so long deploys show progress live)
- Preset save: form values + command id captured as a new builtin
- Run history modal with one-click re-run
- Output diff between consecutive runs (helpful for debugging "why did this
  run differ from last time")

**Phase 3 — operator extensibility (~half day):**
- Custom command CRUD (operator-defined builtins)
- Permission model: `commands.run` scope on admin tokens (split from the
  existing all-or-nothing `admin` scope)
- Notification on failure: webhook or email on commands flagged "alert on fail"

---

## Testing

Unit:
- `/api/local/run` happy path, non-zero exit, timeout
- `/api/local/git/commit-push` with no staged changes (should be a no-op,
  not an error)
- `/api/local/repo-sync` against a clean and a dirty tree

Integration:
- Click "Restart admin" → admin restarts → SPA reconnects within 5 s
- Click "Deploy chatbot to xcenter" → mirrors what the existing
  `chatbot/v4` deploy did this session, end-to-end

Browser:
- Drive the new page via Chrome MCP, run each builtin once, capture output

---

## Migration / rollback

- New tables only, no schema changes to existing ones — safe rollout
- If anything goes wrong, `DROP TABLE commands_catalog, command_runs` and
  remove the new endpoints. Nothing else depends on them.

---

# Carry-over: items found but not fixed across the night

Captured here so the next session has full visibility. Source:
`service-source/user-center/REVIEW_LOG_v5.md` plus this session's chat log.

## Architecture / perf (deferred — needs operator decision)

1. **Transatlantic Caddy hop** — `chat.develop.cc` and `user.develop.cc`
   both go browser → Caddy on us01 (US east) → backend on xcenter (Hetzner
   Finland). Server-side response is ~10 ms locally on xcenter; the
   user-visible latency is 3–5 s because of the hop. Two real fixes:
   (a) move Caddy edge to xcenter, (b) add a EU edge node and let geo-DNS
   route. Both are routing-topology changes — not a code patch.

2. **`drizzle migrate` conflict with lobehub tables** (#64, pre-existing) —
   chatbot's drizzle migrations skip when they detect existing lobehub-named
   tables in the shared `chat` DB. Real fix is namespacing chatbot's tables
   under a dedicated schema or splitting the DB. Tracked, not blocking.

3. **`/Users/leo-m-a/projects/ssl-service/service-source/chat/`** is now a
   stale lobehub source tree. The `chat` service in the admin still points
   at it (port 3210 lobehub container). chat.develop.cc actually serves the
   `chatbot` service (port 3220). The lobehub container should be torn down
   and the `chat` service entry retired or repointed.

## Code-review TODOs from REVIEW_LOG_v5

Already reviewed but deferred (low priority):

4. Usage badge tooltip text "Resets at UTC 0:00" / "Lifetime trial credit"
   is English-only — needs `nav.usageBadgeResets` / `nav.usageBadgeTrial`
   keys in 5 locales.
5. Mobile sidebar swipe-to-close gesture — no-op currently, sidebar must
   be tapped closed.
6. Billing page skeleton loader — page shows blank briefly before the
   server fetch completes.
7. Five test scaffolding gaps:
   - `chargeUsageBackground` quota_exhausted 402 path
   - `checkRateLimit` GC (expired entry removal)
   - `return_to` open-redirect sanitization (4 input cases)
   - `inlineFileParts` file-not-found 404 → skip-part path
   - `usage-badge` 401-stops-polling path
8. Public-API JSDoc on `getBootstrapData`, `chargeUsageBackground`,
   `checkRateLimit` — missing.

## UX polish

9. Stale `chat` (lobehub) container on xcenter: 3210 — listed in
   `docker ps` but no traffic. Stop + remove + retire its admin entry.
10. `chat` service registered in the admin still points at `chat.git`
    after this session's PATCH attempt — verify the URL change persisted
    and that no scheduled job re-clones the old SHA.
11. Memory file `feedback_user_service_deploy_pending.md` is stale (the
    private-repo deploy issue was worked around via `local_repo_dir`
    mode for user-service) — should be either deleted or updated.
12. The `commit-*.command` files under `scripts/dev/` self-delete on
    success, but the failed runs leave `commit-chatbot-header-fix.command`
    and `sync-chat-repo.command` behind. They should be cleaned up
    (commit-v3 + restart-admin + commit-sub-fix + commit-user-center-v2 are
    already gone — only the failed two persist).

## Operational

13. SSL-service `default_node_name` system_config still says `us01`
    despite the 2026-05-09 directive that xcenter is now primary. Update.
14. `services_create.create_service` defaults the new service's
    `github_repo_url` to a placeholder when the operator hasn't set one;
    after this session's relaxation (allow `local_repo_dir` only),
    we should also update the New Service form UI to make the GitHub URL
    optional with a clear "I'll deploy from a local tree" toggle.

## Open security review items (not bugs, but to track)

15. The admin token is stored in `localStorage` — fine for an
    operator-only console, but if we ever expose the admin SPA outside the
    operator's network, this needs to move to httpOnly cookies. Note in
    threat model.
16. `/api/local/run` (proposed) widens the attack surface from "remote SSH
    to managed nodes" to "shell on the operator's Mac". Same trust level
    as today since the operator already has a terminal there, but worth
    explicit acknowledgement before phase 1 ships.

---

# What's already shipped tonight (for context)

Pushed commits, in order, on the ssl-service main branch:

- `70ac7d3` — user-service in-memory billing engine + token-based USD metering
- `6793ce5` — admin Billing tab + user-service xcenter migration
- `95e7753` — user-center Next.js account center scaffold
- `6da32ad` — perf consolidation + /account merge + subscriptions card + chat header unification
- `a1c207e` — products-by-service refactor + 30-round review + billing smoke
- `8819b0c` — fix: proxy /sub /sub-qr /product/info to user-service (regression fix)
- `97ff573` — chore: bump chatbot submodule to v4 (header unify + image retry)
- `f0a326b` — review fixes (cents bug, open-redirect protection, locale polish)

Pushed on chatbot main branch:

- `93456d1` — per-token USD metering + per-user 20/min rate limit
- `6ec9198` — unified header + 300s timeout + retry once + no charge on failure
- `7269391` — sidebar hover/cursor fix + i18n audit (P22)

Live state:

- `https://user.develop.cc` — Next.js user-center, 6 protected pages
  (Dashboard / Account / Security / Billing / Products / verify-email),
  account-level $2 trial credit, token consumption tables, sub/{token}
  passthrough, 5-locale i18n
- `https://chat.develop.cc` — chatbot service (port 3220), unified
  header, sidebar hover fixed, image-gen 300 s timeout + auto-retry
- `https://user.develop.cc/sub/{token}?format=clash` — restored
- Token billing math verified end-to-end (1000 input + 100 output gpt-5.4
  → 0.4¢ list × 0.8 discount = 0.32¢, DB persisted)
- Database has `accounts` table with 15 rows (trial credit migration)
- Schema has `services_code` column on products (refactor migration)

---

End of plan.
