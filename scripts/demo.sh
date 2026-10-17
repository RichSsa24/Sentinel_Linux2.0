#!/usr/bin/env bash
# Trigger real, harmless host activity that a running Sentinel stack detects,
# then print the alerts it raised. Everything is cleaned up on exit.
#
#   docker compose -f deploy/docker-compose.yml up -d   # start the stack first
#   sudo scripts/demo.sh                                 # root only for step 3
#
# For a self-contained replay that needs no stack and no root: `sentinel demo`.
set -euo pipefail

API="${SENTINEL_API:-http://127.0.0.1:8000}"
ENV_FILE="$(dirname "$0")/../deploy/.env"
KEY="${SENTINEL_API_KEY:-$(sed -n 's/^SENTINEL_API_KEY=//p' "$ENV_FILE" 2>/dev/null || true)}"
CRON_FILE=/etc/cron.d/sentinel-demo
LISTENER_PID=""

cleanup() {
    [[ -n "$LISTENER_PID" ]] && kill "$LISTENER_PID" 2>/dev/null || true
    [[ -f "$CRON_FILE" ]] && rm -f "$CRON_FILE"
    return 0
}
trap cleanup EXIT

if [[ -z "$KEY" ]]; then
    echo "set SENTINEL_API_KEY (or create deploy/.env) so the alerts can be fetched" >&2
    exit 1
fi

echo "[1/3] base64-decoding pipeline (rule: base64-execution, T1027)"
# The sleep comes first so this shell stays alive across a poll: bash would
# exec its *last* command in place, replacing the command line we want seen.
bash -c 'sleep 4; echo ZGF0ZQo= | base64 -d >/dev/null' &

echo "[2/3] listener on unexpected port 4444 (rule: new-listening-service, T1571)"
python3 -m http.server 4444 --bind 127.0.0.1 >/dev/null 2>&1 &
LISTENER_PID=$!

if [[ $EUID -eq 0 ]]; then
    echo "[3/3] cron drop in /etc/cron.d (rule: cron-persistence, T1053.003)"
    printf '# sentinel demo — removed automatically\n' > "$CRON_FILE"
else
    echo "[3/3] skipped: writing to /etc/cron.d needs root"
fi

echo "waiting for the collectors' next polls ..."
sleep 8

echo
echo "Alerts raised:"
PRINT_ALERTS=$(cat <<'PY'
import json, sys
for a in json.load(sys.stdin)["data"]:
    print(f"  {a['occurred_at']}  {a['rule_id']:<24} {','.join(a['attack']):<12} {a['host']}")
PY
)
curl -fsS -H "Authorization: Bearer $KEY" "$API/alerts?limit=20" | python3 -c "$PRINT_ALERTS"
