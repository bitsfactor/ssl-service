#!/bin/bash
# Re-init lobehub's git on the Mac side (sandbox can't unlink temp objects).
# After this, lobehub will have a single squashed initial commit, no remote, branch=main.
set -e
cd "$(dirname "$0")/service-source/lobehub"

echo "==> Removing existing .git (if any)"
rm -rf .git

echo "==> git init -b main"
git init -b main

echo "==> git add -A"
git add -A

echo "==> git commit"
git -c user.name="DevChat" -c user.email="bitsfactorcom@gmail.com" \
  commit -m "Initial commit: forked from lobehub@e4d5f69 for DevChat" --quiet

echo
echo "==> Result"
echo "Branch: $(git rev-parse --abbrev-ref HEAD)"
echo "Remotes: $(git remote -v | wc -l | tr -d ' ') (should be 0)"
echo "Commits: $(git rev-list --count HEAD)"
echo ".git size: $(du -sh .git | cut -f1)"
echo "Total: $(du -sh . | cut -f1)"
echo
echo "Done. Press any key to close this window."
read -n 1 -s
