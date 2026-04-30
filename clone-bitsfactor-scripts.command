#!/usr/bin/env bash
# One-shot helper: clone bitsfactor/scripts into ~/projects/scripts so the
# admin tooling can edit upstream when needed. Re-running is safe: if the
# directory already has a git repo we just `git pull`. Window stays open
# so you can read the result.
set -uo pipefail

TARGET="$HOME/projects/scripts"
REPO="https://github.com/bitsfactor/scripts.git"

echo "================================================================"
echo "  bitsfactor/scripts -> $TARGET"
echo "================================================================"
mkdir -p "$HOME/projects"

if [ -d "$TARGET/.git" ]; then
  echo "[update] existing checkout, pulling..."
  cd "$TARGET" && git pull --ff-only
elif [ -e "$TARGET" ]; then
  echo "ERROR: $TARGET exists but is not a git checkout. Move it aside and retry."
  exit 1
else
  echo "[clone] $REPO -> $TARGET"
  git clone "$REPO" "$TARGET"
fi

echo
echo "Done. Files at: $TARGET"
ls -la "$TARGET" | head -20
echo
echo "Press any key to close this window..."
read -n 1 -s
