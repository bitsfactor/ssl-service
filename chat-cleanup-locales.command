#!/bin/bash
# Post-sed cleanup on the chat repo:
#   1. Delete the .bak files sed left behind (sandbox can't unlink them).
#   2. Delete the 16 unused locale directories — DevChat ships en-US
#      + zh-CN only. Keeps the repo small and prevents stale upstream
#      strings (with "LobeHub" still in them) from sneaking back in.
set -e
cd "$(dirname "$0")/service-source/chat"

echo "==> Removing .bak files"
find locales src -name '*.bak' -delete
echo "    done"

echo "==> Trimming locales to en-US + zh-CN"
KEEP='en-US zh-CN'
removed=0
for d in locales/*/; do
  name="$(basename "$d")"
  if [[ ! " $KEEP " =~ " $name " ]]; then
    rm -rf "$d"
    echo "    removed locales/$name"
    removed=$((removed + 1))
  fi
done
echo "==> $removed locale directories removed"

echo
echo "==> Sanity: remaining LobeHub literals"
echo "    locales/: $(grep -rE LobeHub locales 2>/dev/null | wc -l | tr -d ' ')"
echo "    src/locales/default: $(grep -rE LobeHub src/locales/default 2>/dev/null | wc -l | tr -d ' ')"

echo
echo "Done. Press any key to close."
read -n 1 -s
