#!/bin/bash
# Stage every change inside service-source/chat, commit with the
# message I pass on the command line (or a default), then push to
# origin/main. Run on the Mac side because (a) git's tmp objects
# tangle with the sandbox mount and (b) push needs the Mac SSH agent.
set -e
cd "$(dirname "$0")/service-source/chat"

MSG="${1:-update chat deploy spec}"

git add -A

if git diff --cached --quiet; then
  echo "==> No staged changes — nothing to commit."
else
  git -c user.name="DevChat" -c user.email="bitsfactorcom@gmail.com" \
    commit -m "$MSG" --quiet
  echo "==> Committed: $(git log -1 --oneline)"
fi

echo "==> Pushing to origin/main"
git push origin main

echo
echo "Done. Press any key to close."
read -n 1 -s
