#!/usr/bin/env bash
# End-to-end live test of the new Static IPs admin channel.
# Hits the running admin at http://127.0.0.1:8088/ and logs results to
# /tmp/ssl-service-static-ips-test.log so the agent can read them back.
set -uo pipefail

LOG=/tmp/ssl-service-static-ips-test.log
HOST=http://127.0.0.1:8088
TOKEN=dev-token

cd "$(dirname "${BASH_SOURCE[0]}")"

exec > >(tee "${LOG}") 2>&1

step() { echo; echo "=========================================="; echo "STEP: $1"; echo "=========================================="; }

step "0. ping overview"
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${HOST}/api/overview" | python3 -m json.tool | head -20

step "1. wipe existing static_ips (best-effort)"
# Get all IDs and delete each
IDS=$(curl -fsS -H "Authorization: Bearer ${TOKEN}" "${HOST}/api/static-ips" | python3 -c "import json,sys; d=json.load(sys.stdin); print(' '.join(str(r['id']) for r in d.get('static_ips', [])))")
echo "existing ids: ${IDS}"
for id in ${IDS}; do
  curl -fsS -X DELETE -H "Authorization: Bearer ${TOKEN}" "${HOST}/api/static-ips/${id}" >/dev/null
done

step "2. bulk parse + commit (regex fallback, no AI key)"
curl -fsS -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  -d '{"text":"1.1.1.1:443 https Cloudflare 美国\n8.8.8.8 google US\ntrojan://abc@13.230.45.67:8443 Japan AWS\nss://def@45.32.20.10:9999 新加坡 Vultr\n[2606:4700:4700::1111]:53 Cloudflare DNS US","commit":true}' \
  "${HOST}/api/static-ips/parse" | python3 -m json.tool

step "3. list — sort=country"
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${HOST}/api/static-ips?sort=country" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['static_ips']:
    print(f\"  id={r['id']:>3} {r['ip']:<22} :{str(r['port'] or '-'):<5} {r['protocol']:<10} {r['country'] or '-':<14} {r['provider'] or '-':<14}\")
"

step "4. list — sort=provider"
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${HOST}/api/static-ips?sort=provider" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['static_ips']:
    print(f\"  id={r['id']:>3} {r['ip']:<22} :{str(r['port'] or '-'):<5} {r['protocol']:<10} {r['country'] or '-':<14} {r['provider'] or '-':<14}\")
"

step "5. test-all"
curl -fsS -X POST -H "Authorization: Bearer ${TOKEN}" "${HOST}/api/static-ips/test-all" | python3 -c "
import json, sys
r = json.load(sys.stdin)
print(f'  total={r[\"total\"]} ok={r[\"success\"]} fail={r[\"fail\"]} at={r[\"at\"]}')
for x in r['results']:
    res = x['result']
    ok = 'OK' if res['success'] else 'FAIL'
    lat = (str(res['latency_ms']) + 'ms') if res['latency_ms'] is not None else '-'
    err = (res.get('error') or '')[:60]
    print(f\"  [{ok:<4}] {x['ip']:<22} :{str(x['port'] or '-'):<5} lat={lat:<8} err={err}\")
"

step "6. single test connectivity (1.1.1.1)"
ID1=$(curl -fsS -H "Authorization: Bearer ${TOKEN}" "${HOST}/api/static-ips" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(next(r['id'] for r in d['static_ips'] if r['ip']=='1.1.1.1'))
")
curl -fsS -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  -d '{"kind":"manual"}' "${HOST}/api/static-ips/${ID1}/test" | python3 -m json.tool

step "7. probe info (1.1.1.1) — geo + streaming unlock"
curl -fsS -X POST -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  -d '{}' "${HOST}/api/static-ips/${ID1}/probe" | python3 -m json.tool | head -60

step "8. detail with recent_results"
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${HOST}/api/static-ips/${ID1}" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('  ip:', d['ip'])
print('  country:', d['country'], 'provider:', d['provider'])
print('  static_info keys:', list(d.get('static_info', {}).keys()))
print('  recent_results:', len(d.get('recent_results', [])))
for r in d.get('recent_results', [])[:5]:
    print(f\"    {r['created_at']} kind={r['test_kind']} success={r['success']} latency={r['latency_ms']} err={(r['error'] or '')[:50]}\")
"

step "9. update IP (set notes)"
curl -fsS -X PATCH -H "Authorization: Bearer ${TOKEN}" -H 'Content-Type: application/json' \
  -d '{"notes":"Cloudflare public DNS","label":"cf-1111","loop_test_seconds":15}' \
  "${HOST}/api/static-ips/${ID1}" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('  notes:', d['notes'])
print('  label:', d['label'])
print('  loop_test_seconds:', d['loop_test_seconds'])
"

step "10. results history"
curl -fsS -H "Authorization: Bearer ${TOKEN}" "${HOST}/api/static-ips/${ID1}/results?limit=20" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'  {len(d[\"results\"])} results')
for r in d['results'][:10]:
    print(f\"    {r['created_at']} kind={r['test_kind']} success={r['success']} latency={r['latency_ms']}\")
"

echo
echo "ALL TESTS COMPLETE — log: ${LOG}"
echo "Press Cmd-W to close this window."
