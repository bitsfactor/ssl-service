#!/usr/bin/env bash
# China-side network diagnosis for chat.develop.cc.
#
# Symptom: on the same LAN, two client machines show different speed on
# the marketing-page image gallery — one loads fast, the other stalls
# until requests "all start at once". Source-station IP routing changes
# under our feet are unlikely (DNS is static), so the cause is either
# DNS-side (different IPs returned to different clients), middle-box
# QoS (per-flow shaping), MTU black hole (large packets dropped silently
# while small ones go through), or HTTP-layer (h3 UDP timeouts).
#
# Run this script on BOTH machines, save the output, and diff them.
# Each section is independent — you can re-run individual steps.
#
# Usage:
#   bash diagnose-cn-network.sh > diag-$(hostname).txt 2>&1

set -u
TARGET="${TARGET:-chat.develop.cc}"
SAMPLE_IMG="${SAMPLE_IMG:-https://${TARGET}/awesome-cases/images/case1.thumb.webp}"

hr() { printf '\n========== %s ==========\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || echo "  (skip — '$1' not installed)"; }

hr "host info"
echo "host:    $(hostname)"
echo "time:    $(date -u +%FT%TZ)"
echo "target:  ${TARGET}"
echo "sample:  ${SAMPLE_IMG}"
echo "uname:   $(uname -a)"

hr "1. DNS resolution (look for: different IPs per DNS)"
for ns in "" "@1.1.1.1" "@8.8.8.8" "@223.5.5.5"; do
  label="${ns:-system}"
  echo "-- dig ${label} --"
  if need dig; then
    dig "${TARGET}" ${ns} +short 2>&1 | sed 's/^/  /'
  fi
done

hr "2. ping + loss (10 pkts)"
ping -c 10 "${TARGET}" 2>&1 | tail -5

hr "3. mtr — per-hop loss (key: any hop with Loss%>0 in steady state)"
if command -v mtr >/dev/null 2>&1; then
  mtr -rwc 20 "${TARGET}" 2>&1
else
  echo "  mtr not installed — falling back to traceroute"
  traceroute -n -w 2 "${TARGET}" 2>&1 | head -25
fi

hr "4. curl application-layer timing (sample thumb)"
fmt='DNS:%{time_namelookup}s  CONN:%{time_connect}s  TLS:%{time_appconnect}s  TTFB:%{time_starttransfer}s  TOTAL:%{time_total}s  SIZE:%{size_download}B  HTTP:%{http_version}\n'
for i in 1 2 3; do
  echo "-- pass ${i} --"
  curl -sS -o /dev/null -w "${fmt}" "${SAMPLE_IMG}"
done

hr "5. protocol probe — h2 vs h3"
echo "-- forced http/1.1 --"
curl -sS -o /dev/null -w "TOTAL:%{time_total}s  HTTP:%{http_version}\n" --http1.1 "${SAMPLE_IMG}"
echo "-- forced http/2 --"
curl -sS -o /dev/null -w "TOTAL:%{time_total}s  HTTP:%{http_version}\n" --http2 "${SAMPLE_IMG}"
echo "-- request http/3 (may fall back) --"
if curl -V 2>/dev/null | grep -q HTTP3; then
  curl -sS -o /dev/null -w "TOTAL:%{time_total}s  HTTP:%{http_version}\n" --http3 "${SAMPLE_IMG}" 2>&1
else
  echo "  curl built without HTTP/3 — skip"
fi

hr "6. MTU black hole probe (key: large size fails but small succeeds)"
# 1500 IPv4 link MTU → 1472 payload + 28 (ICMP+IP).
for size in 1472 1452 1400 1200; do
  if ping -c 3 -M do -s ${size} "${TARGET}" >/dev/null 2>&1; then
    echo "  size=${size}: OK"
  else
    echo "  size=${size}: FAIL (likely PMTU black hole at or below ${size}+28)"
  fi
done

hr "7. browser proxy / extension hint"
echo "  (Manual check) Open chrome://net-internals/#dns and chrome://net-internals/#sockets"
echo "  Confirm BOTH machines use the same DNS over HTTPS setting."
echo "  Confirm no proxy / SwitchyOmega / corporate cert intercept on slow machine."
echo "  Try the same URL in a private window with extensions OFF."

hr "done"
