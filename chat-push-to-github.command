#!/bin/bash
# Push the chat repo to git@github.com:bitsfactor/chat.git.
# Run this once after the initial commit to seed the GitHub repo.
# Uses --force-with-lease in case the GitHub repo was created with
# an auto-README (we want our chat repo's contents to win, since
# the local commit IS the canonical chat baseline).
set -e
cd "$(dirname "$0")/service-source/chat"

REMOTE_URL="git@github.com:bitsfactor/chat.git"

echo "==> Configuring origin"
if git remote | grep -q "^origin$"; then
  git remote set-url origin "$REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
fi

echo "==> Verifying SSH access to GitHub"
ssh -T git@github.com 2>&1 | head -1 || true

echo "==> Pushing main (force, safe — fresh repo)"
git push -u origin main --force

echo
echo "==> Result"
echo "Remote: $(git remote get-url origin)"
echo "Branch: $(git rev-parse --abbrev-ref HEAD)"
echo "Pushed:  $(git rev-parse HEAD)"
echo
echo "Done. Press any key to close this window."
read -n 1 -s
