#!/usr/bin/env bash
# dev-push.command — single-button "ship local changes to the running admin"
#
# What it does, in order:
#   1) git add -A on the source tree, commit (if there's a diff), push
#   2) POST /api/admin/restart so the running admin self-rotates and picks
#      up the new code WITHOUT needing kill+start scripts
#   3) Poll /api/admin/version for ~30s to confirm the new process is up
#
# Replaces the family of run-*-rollout.command files. If you find yourself
# writing yet another rollout script, just edit this one's commit message
# logic or pass --message "..." in.
#
# Flags:
#   --message "..."   Use this commit message instead of opening EDITOR
#   --no-restart      Skip the /api/admin/restart step (push only)
#   --no-push         Skip git push (commit + restart only)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

LOG=/tmp/ssl-service-dev-push.log
: > "$LOG"
exec > >(tee -a "$LOG") 2>&1

ADMIN_URL="${SSL_SERVICE_ADMIN_URL:-http://127.0.0.1:8088}"
ADMIN_TOKEN="${SSL_SERVICE_ADMIN_TOKEN:-dev-token}"

MSG=""
DO_PUSH=1
DO_RESTART=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --message|-m) MSG="${2:-}"; shift 2 ;;
    --no-push)    DO_PUSH=0; shift ;;
    --no-restart) DO_RESTART=0; shift ;;
    *) echo "Unknown flag: $1"; exit 2 ;;
  esac
done

echo "==> stage changes"
rm -f .git/index.lock .git/HEAD.lock 2>/dev/null
git reset >/dev/null
# Stage the whole working tree minus tracked-but-deleted; we always want the
# full picture going up, not a hand-curated subset.
git add -A 2>&1 | tail -5

if git diff --cached --quiet; then
  echo "Nothing to commit."
else
  if [[ -z "$MSG" ]]; then
    MSG="dev-push: $(date '+%Y-%m-%d %H:%M:%S')"
  fi
  git commit -m "$MSG"
fi

if [[ "$DO_PUSH" == "1" ]]; then
  echo
  echo "==> rebase + push"
  git -c rebase.autoStash=true pull --rebase origin main || exit 1
  git push origin main
fi

if [[ "$DO_RESTART" == "1" ]]; then
  echo
  echo "==> restart admin via API ($ADMIN_URL)"
  BEFORE_VERSION="$(curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$ADMIN_URL/api/admin/version" 2>/dev/null || echo '')"
  echo "  before: $BEFORE_VERSION"

  RESTART_RESP="$(curl -fsS -X POST \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{}' \
    "$ADMIN_URL/api/admin/restart" 2>/dev/null || echo '')"
  echo "  scheduled: $RESTART_RESP"

  if [[ -z "$BEFORE_VERSION" ]]; then
    echo "  (no /api/admin/version baseline — skipping confirmation poll)"
  else
    BEFORE_STAMP="$(echo "$BEFORE_VERSION" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("started_at",""))' 2>/dev/null || echo '')"
    echo "  waiting for new process…"
    UP=0
    for i in $(seq 1 30); do
      sleep 1
      NOW="$(curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
        "$ADMIN_URL/api/admin/version" 2>/dev/null || echo '')"
      [[ -z "$NOW" ]] && continue
      NOW_STAMP="$(echo "$NOW" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("started_at",""))' 2>/dev/null || echo '')"
      if [[ -n "$NOW_STAMP" && "$NOW_STAMP" != "$BEFORE_STAMP" ]]; then
        echo "  admin up after ${i}s (started_at $NOW_STAMP)"
        UP=1
        break
      fi
    done
    if [[ "$UP" == "0" ]]; then
      echo "  WARNING: admin did not come back up within 30s; check logs"
    fi
  fi
fi

echo
echo "Done."
sleep 1
