# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

---

## Platform contract — {{name}}

This service runs inside the BitsFactor micro-product platform. The
platform handles routing, TLS, deployment, and (eventually) user identity
and billing. The service code obeys the rules below so it stays
swappable and the platform stays cheap.

### Service boundary

- Don't build a `users` table. Don't build a login page. Don't build
  payment logic. Those are the platform's job.
- User identity arrives in `request.headers["X-User-Id"]`. When the
  header is absent, treat the caller as anonymous. Use
  `app.product_adapter.get_user(request)`.
- Plan tier (e.g. `free`, `pro`) arrives in `X-Plan`. Read it, don't
  invent it.

### Billing hooks

- For any billable action, call
  `app.product_adapter.report_usage(event, qty=1, user_id=...)`.
  Today this is a noop (no `BILLING_SINK_URL` set); when the platform
  turns it on, every existing call starts counting. Names you pick
  become billing history — choose carefully and don't rename later.

### Don't touch

- `.deploy.yaml` — `service`, `exposed_ports`, `healthcheck.url` are
  load-bearing. Routes layer and cert provisioning depend on them.
- `.product.yaml` — `slug` is in the public URL. Renaming breaks links.
- `docker-compose.yml` — the `ports:` mapping is what the routes layer
  points at. Don't change the host port (`{{port}}`) or the variable
  binding.
- Don't ssh to the deploy node and edit anything there. All changes go
  through `git push` + admin Deploy.

### File organisation

- HTTP endpoints live in `app/main.py`.
- Business logic by topic: `app/<topic>.py`. Don't dump it all into one
  file once it grows past ~200 lines.
- Tests in `tests/test_<topic>.py`, named after the module they cover.
- The repo root is for config files only (no `*.py` at top level).

### Dependencies

- Standard library first. Before adding a package, ask whether stdlib
  or an existing dep can do it.
- Pin versions in `requirements.txt`. Add a one-line comment above any
  new entry explaining why it's needed.

### How to run / deploy

- Local: `docker compose up --build`. Health check at
  `http://localhost:{{port}}/health`.
- Tests: `pytest`.
- Deploy: `git push` to `main`, then admin → Services → Deploy.
