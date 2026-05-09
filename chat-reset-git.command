#!/bin/bash
# Reset service-source/chat/.git from the Mac side.
# Sandbox bash can't unlink files git creates inside .git on this
# mount, so we run the reset from the host shell. After this,
# chat/ has a single squashed commit that includes the deploy files.
set -e
cd "$(dirname "$0")/service-source/chat"

echo "==> Removing existing .git"
rm -rf .git

echo "==> git init -b main"
git init -b main

echo "==> git add -A"
git add -A

echo "==> git commit"
git -c user.name="DevChat" -c user.email="bitsfactorcom@gmail.com" \
  commit -m "Initial commit: chat service (forked from lobehub@e4d5f69, deploy manifest for ssl-service)" --quiet

echo
echo "==> Result"
echo "Branch: $(git rev-parse --abbrev-ref HEAD)"
echo "Remotes: $(git remote -v | wc -l | tr -d ' ') (should be 0)"
echo "Commits: $(git rev-list --count HEAD)"
echo ".git size: $(du -sh .git | cut -f1)"
echo "Total: $(du -sh . | cut -f1)"
echo "Files in HEAD: $(git ls-tree -r HEAD | wc -l | tr -d ' ')"
echo
echo "Done. Press any key to close this window."
read -n 1 -s
