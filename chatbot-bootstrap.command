#!/bin/bash
# One-time: take the freshly-downloaded vercel/ai-chatbot tree in
# service-source/chatbot/, wipe its upstream git, re-init as a clean
# DevChat repo, and stage an initial commit. Does NOT push — run
# chatbot-push-to-github.command after verifying pnpm dev works.
#
# Idempotent: safe to re-run; will detect an already-initialized repo
# and just print the current state.

set -e
cd "$(dirname "$0")/service-source/chatbot"

if [[ -d .git && -f .git/HEAD ]]; then
  if git config remote.origin.url >/dev/null 2>&1; then
    REMOTE="$(git config remote.origin.url)"
  else
    REMOTE="<none>"
  fi
  if [[ "$REMOTE" == *"bitsfactor/chatbot"* ]]; then
    echo "==> Already initialized as DevChat repo (remote: $REMOTE)."
    echo "    Latest commit: $(git log -1 --oneline 2>/dev/null || echo '<no commits yet>')"
    echo "    Nothing to do."
    echo
    echo "Done. Press any key to close."
    read -n 1 -s
    exit 0
  fi
fi

echo "==> Wiping existing .git (was vercel/ai-chatbot upstream)"
rm -rf .git

echo "==> Initializing fresh git repo"
git init -q
git branch -M main
git remote add origin git@github.com:bitsfactor/chatbot.git

echo "==> Staging all files"
git add -A

echo "==> First commit"
git -c user.name="DevChat" -c user.email="bitsfactorcom@gmail.com" \
  commit -m "Initial commit: chatbot service (forked from vercel/ai-chatbot, deploy manifest for ssl-service)" --quiet

echo "==> Done. Local repo state:"
git log -1 --oneline
git remote -v

echo
echo "Next: double-click chatbot-dev-local.command to verify pnpm install + dev,"
echo "      then chatbot-push-to-github.command to push to origin/main."
echo
echo "Press any key to close."
read -n 1 -s
