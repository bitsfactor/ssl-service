#!/bin/bash
# One-shot: clear sandbox-leftover lock files, stage every change
# inside service-source/chat (all 700+ locale deletions + source
# patches), commit, and push. Single message because we're folding
# the entire DevChat fork prep into one commit on top of the
# previous deploy spec.
set -e
cd "$(dirname "$0")/service-source/chat"

echo "==> Clearing stale .git/*.lock"
rm -f .git/index.lock .git/HEAD.lock .git/refs/heads/*.lock 2>/dev/null || true

echo "==> git add -A (this may take a moment with 700+ files)"
git add -A

if git diff --cached --quiet; then
  echo "==> No staged changes."
else
  git -c user.name="DevChat" -c user.email="bitsfactorcom@gmail.com" \
    commit -m "DevChat brand + OpenAI-only provider gate + gpt-image-2 default" --quiet
  echo "==> Committed: $(git log -1 --oneline)"
fi

echo "==> Pushing to origin/main"
git push origin main

echo
echo "Done. Press any key to close."
read -n 1 -s
