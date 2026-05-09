#!/bin/bash
# Push the chatbot repo to git@github.com:bitsfactor/chatbot.git.
# Run this once after chatbot-bootstrap.command + chatbot-dev-local.command
# verified the build is healthy. Subsequent commits go via
# chat-commit-and-push.command-style workflows once we copy that pattern.

set -e
cd "$(dirname "$0")/service-source/chatbot"

rm -f .git/index.lock || true

if ! git config remote.origin.url >/dev/null 2>&1; then
  git remote add origin git@github.com:bitsfactor/chatbot.git
fi

echo "==> Remote: $(git config remote.origin.url)"
echo "==> Pushing main"
git push -u origin main

echo
echo "Done. Press any key to close."
read -n 1 -s
