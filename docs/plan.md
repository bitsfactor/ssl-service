# Plan — Commands palette Phase 2 + UI rework

**Status:** Phase 1 landed as `cea8f8d` on origin/main. Phase 2 in progress.
**Owner of next session:** Claude Code (handoff from Cowork; Cowork session got
flaky on Anthropic-side capacity, Claude Code unaffected today).
**Date drafted:** 2026-05-09 evening (post-Phase-1).

---

## What's live right now

`cea8f8d feat(admin): Commands palette — operator-facing #/commands page`

- `/api/local/run`, `/api/local/git/commit-push`, `/api/local/repo-sync` —
  the three executors against the host where admin runs.
- `/api/commands` (GET catalog), `/api/commands/{id}/run` (POST dispatch
  by `exec.kind` over 8 kinds), `/api/commands/runs` (GET history).
- Tables `commands_catalog` and `command_runs` (FK with ON DELETE SET NULL)
  on the home schema.
- 18 builtin command rows seeded (idempotent, ON CONFLICT DO NOTHING).
- SPA route `#/commands` with category sections, form-driven cards,
  inline output panel, copy buttons, history modal.
- Phase 1 review-pass fixes already in `cea8f8d`: psycopg connect_timeout
  + statement_timeout, template-expansion guard against operator-input
  cmd, `git commit -- <paths>` (so plain `git commit` doesn't sweep
  stale staged work — bit us twice during Phase 1 testing), exec_spec
  parse-failure surfacing, FK constraint, frontend confirm() before
  `git add -A`.

## Uncommitted in the working tree (Cowork left this for Claude Code)

`src/ssl_proxy_controller/static/index.html` has Phase 2 task #9
(history modal one-click re-run) **partially landed but not e2e-verified**.
Specifically:

- `buildCommandCard` exposes `applyArgs(args)` and `triggerRun()` closures.
- `historyBtn.click` now passes `{applyArgs, triggerRun}` to
  `showHistoryModal` as a 3rd arg.
- `showHistoryModal` adds an "Action" column with a "Re-run" button that
  copies the row's `args_json` back into the card form, closes the modal,
  and triggers Run after a 50ms settle.

The change is small and looks correct; it just hasn't been clicked through
in a real browser. **First task for Claude Code: reload `#/commands`,
open History on any card, verify the Re-run column shows up and the
button does what the docstring says, then commit + push.**

(Other dirty files in the tree — `_p22_commit.command`, `_tmp_*`,
`scripts/.DS_Store`, `scripts/dev/commit-chatbot-header-fix.command`,
`examples/user-service/app/billing.py`, `examples/user-service/app/main.py`
— are NOT Cowork's. Don't touch them. Stage only `src/ssl_proxy_controller/static/index.html`
when committing the re-run change. `git commit -- <paths>` is critical;
see memory `feedback_git_commit_paths_only.md`.)

---

## Phase 2 — what's still to build

Priority order. Each item ships independently; commit + push between
items, don't accumulate.

### 1. UI rework (HIGH — user explicitly flagged the page as messy)

Current state of `#/commands`:

- 5 SECTION blocks stacked vertically (Quick / Git / Deploy / DB / Remote / Free-form).
- 2-column grid of cards inside each section.
- Cards have wildly different heights (empty form like restart-admin is
  ~80px, deploy-service with 3 fields is ~280px).
- Inline output panel pushes each card down when run; no consistent
  position for the "where do I look for output" question.
- No top-level "I just want to run the thing I always run" affordance —
  operator scans the whole catalog every time.

Target state:

1. **Top: segmented tabs** for the categories (default to "Quick"). Show
   one category at a time. Halves vertical scroll, makes the screen feel
   like a tool palette instead of a directory listing.

2. **Cards become uniform height in a category.** CSS grid with
   `align-items: stretch` + `grid-auto-rows: 1fr`. Form area grows; Run
   button anchored at the card's footer (right-aligned) so the click
   target is always in the same spot.

3. **Sticky output drawer** on the right side of the page (or bottom on
   narrow viewports). The active card's output streams into it. Clicking
   Run on a different card switches the drawer to that card. Drawer has
   a header `<command title> · <timestamp> · <duration> · <exit>` and
   the same Copy stdout / Copy stderr / Re-run buttons we have today
   inline. Width ~420px desktop, collapsible to icon-strip when not in
   use. The card itself loses its inline output panel.

4. **"Recent" strip at the top** of the page (above the tabs). Pulls
   the last 5 runs across all commands from `/api/commands/runs?limit=5`.
   Each pill shows `<command title> · <relative time>` and clicking
   re-runs with the same args (uses the closures we just built for the
   history modal). This is the "I just hit the same thing again" path.

5. **Empty-form cards** like restart-admin / xcenter-clear-orphan-chat
   should render at half-width or two-up so they don't waste a column.

Files to touch:
- `src/ssl_proxy_controller/static/index.html`, `renderCommandsView` and
  `buildCommandCard` (search for those names; they're the only two
  functions that matter). The card builder needs to NOT append the
  output panel to itself; instead expose a `renderInto(panelEl, result)`
  method that the drawer can call. The drawer is a single element owned
  by `renderCommandsView`.
- `static/index.html` CSS (the `<style>` block at the top): add
  `.commands-tabs`, `.commands-grid`, `.commands-drawer`,
  `.commands-recent-strip` rules. Reuse existing `--surface`, `--border`
  CSS vars; don't introduce new colors.

Verification: open `#/commands`, switch tabs (no scroll), click Run on
3 different cards in succession, confirm the drawer swaps cleanly and
each card's output is captured in `command_runs`. Take a screenshot
when done; the page should look like a real tool palette, not a form
catalogue.

### 2. Preset save (MEDIUM)

After a successful run, the output drawer (or inline panel pre-rework)
should show a "Save as preset" button. Clicking opens a small modal:

```
Title:        [____________________________]
Description:  [____________________________]
Category:     [ same as parent ▾ ]
[Cancel]                          [Save]
```

On save, POST `/api/commands` with a new row whose:
- `id` = slug of title (operator-edit-able)
- `is_builtin` = false
- `category` = chosen
- `schema` = the parent command's schema
- `exec` = parent's `exec.kind` + `args` = the form values that just ran

So a frequent "deploy chat with --force-rebuild" becomes a one-click
button.

Backend: add `POST /api/commands` and `DELETE /api/commands/{id}` (only
for is_builtin=false rows; refuse to delete builtins). Both behind
`with_auth` + `_require_readwrite`. Validate `id` matches
`^[a-z0-9-_.]{1,63}$`.

Schema: no migration — `commands_catalog` already has `is_builtin`.

Frontend: small modal in `static/index.html`, similar to existing
`Modal.open` patterns.

### 3. SSE streaming output (MEDIUM, scope-limit)

Long deploys (`service-deploy` to xcenter takes 30-60s) currently show
nothing until done. Add `/api/commands/{id}/stream` returning
`text/event-stream`. **Scope-limit: only stream `local-run`,
`local-git-commit-push`, `local-repo-sync`.** Other kinds
(`service-deploy` calls `deploy_service_to_nodes` synchronously,
`node-run` uses paramiko which buffers, `db-*` is a single SQL trip)
fall through to the existing synchronous endpoint.

Backend: in `commands.py`, add `run_local_shell_streaming(args, on_line)`
that uses `subprocess.Popen` + reads stdout line-by-line and calls
`on_line(stream, text)` for each chunk. The HTTP handler iterates these
into `data: {...}\n\n` SSE events.

Frontend: `EventSource` doesn't support `Authorization` headers, so use
`fetch(..., {headers}).then(res => res.body.getReader())` and parse the
`data: ...` framing manually. The drawer renders chunks incrementally;
final event has `{done: true, exit_code, ok}`.

Audit: insert_run_start at handler entry, update_run_finish on
final-event-emit, exactly like the synchronous path.

Verification: `git-discard-and-pull-ssl-service` (because git fetch
streams progress) should show progress lines as they arrive, not all
at once.

### 4. Output diff (LOW — skip if running tight)

In the history modal, allow ticking 2 rows + clicking "Diff". Renders
a side-by-side or unified diff of the two runs' `stdout_head`. Frontend
only — server already returns stdout_head in the runs list response.
Use the existing `jsdiff` lib if it's already in the bundle, otherwise
inline a tiny LCS-based diff function.

---

## Carry-over (still real, untouched by Phase 1)

These are the same items that lived at the bottom of the original plan;
none have been addressed yet. Reproduced verbatim for reference. Most
are not Phase 2 work — pick them up only when a related task is open.

1. **Transatlantic Caddy hop** — chat.develop.cc / user.develop.cc go
   browser → Caddy on us01 (US east) → backend on xcenter (Hetzner FI).
   3-5s user-visible latency vs. 10ms server-side. Routing-topology
   change, not a code fix. Move Caddy edge to xcenter, OR add an EU
   edge node + geo-DNS. Operator decision.

2. **drizzle migrate vs. lobehub tables** (#64, pre-existing). Chatbot's
   drizzle skips when it sees existing lobehub-named tables in the shared
   `chat` DB. Real fix is namespacing chatbot tables under a dedicated
   schema or splitting the DB. Tracked, not blocking.

3. **`service-source/chat/` is stale lobehub source.** The `chat`
   service in admin still points at port 3210 (lobehub container).
   chat.develop.cc actually serves the chatbot service (port 3220).
   Lobehub container should be torn down (we have a builtin command
   for that — `xcenter-clear-orphan-chat`). The `chat` service entry
   should be retired or repointed.

4. Usage badge tooltip "Resets at UTC 0:00" / "Lifetime trial credit"
   English-only — needs `nav.usageBadgeResets` / `nav.usageBadgeTrial`
   keys in 5 locales.

5. Mobile sidebar swipe-to-close — no-op, sidebar must be tapped closed.

6. Billing page skeleton loader — page shows blank briefly before fetch.

7. Five test scaffolding gaps (chargeUsageBackground 402 path,
   checkRateLimit GC, return_to open-redirect, inlineFileParts 404,
   usage-badge 401 polling stop).

8. Public-API JSDoc on getBootstrapData, chargeUsageBackground,
   checkRateLimit — missing.

9. Stale `chat` (lobehub) container on xcenter:3210 — listed in
   `docker ps` but no traffic. Stop + remove + retire admin entry.
   **Now a one-click button: `xcenter-clear-orphan-chat`.**

10. `chat` service registered in admin still points at chat.git after
    a previous PATCH attempt — verify URL change persisted, no
    scheduled job re-clones the old SHA.

11. Memory file `feedback_user_service_deploy_pending.md` is stale
    (workaround via `local_repo_dir` mode). Delete or update.

12. Failed `.command` runs left `commit-chatbot-header-fix.command` and
    (formerly) `sync-chat-repo.command` behind in scripts/dev/. Clean up.

13. SSL-service `default_node_name` system_config still says `us01`
    despite the 2026-05-09 directive that xcenter is primary. Update.

14. New Service form UI: GitHub URL should be optional with a clear
    "I'll deploy from a local tree" toggle.

15. Admin token in `localStorage` — fine for operator-only console;
    move to httpOnly cookies if SPA ever exposed beyond operator's
    network.

16. `/api/local/run` widens attack surface from "remote SSH" to "shell
    on operator's Mac". Same trust level as today (operator already has
    a terminal there) but worth the explicit acknowledgement.

---

## How to work on this branch

1. **Always commit with explicit paths.** `git commit -- <paths>` is
   load-bearing now (memory `feedback_git_commit_paths_only.md`).
   Plain `git commit` will sweep up `_p22_commit.command`,
   `_tmp_17_8f547be9c010381a00f6c7d57e2646ae`, `scripts/.DS_Store`,
   `scripts/dev/commit-chatbot-header-fix.command`, and the `examples/`
   pending edits — none of which are ours.

2. **Use the Commands page itself** for shell / commit / deploy /
   restart. memory `feedback_use_commands_page.md` is the rule.
   `POST /api/commands/free-form-run/run` body
   `{"args":{"cmd":"<shell line>"}}` is the everyday hammer.
   For Claude Code which can run shell directly, the bash tool is fine
   too — but prefer the commands path when it's a documented action so
   the run lands in `command_runs` audit history.

3. **E2E in a real browser, not just curl.** memory
   `feedback_real_e2e_in_browser.md`. The drawer/tabs rework
   especially needs visual verification.

4. **Apply schema is idempotent.** Re-run after any schema.sql change.
   Builtins re-seed via ON CONFLICT DO NOTHING — operator edits to a
   builtin row stay put.

5. **Restart admin** after any Python edit (admin.py / commands.py).
   The SPA-only edits don't need a restart, just a hard reload (Cmd+R
   typically suffices; F5 in Chrome).

End of plan.
