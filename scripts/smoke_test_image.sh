#!/usr/bin/env bash
# Smoke-test a built image under the same hardening the Compose stack uses:
# read-only root filesystem, no capabilities, no-new-privileges, host mounted
# read-only under /host. Fails unless the service becomes ready, enforces auth
# on /metrics, exports runtime metrics, and shuts down cleanly on SIGTERM.
#
#   scripts/smoke_test_image.sh sentinel-linux:local
set -euo pipefail

IMAGE="${1:?usage: $0 IMAGE}"
NAME="sentinel-smoke-$$"
PORT="${SMOKE_PORT:-18080}"
# Exported, not passed as `-e NAME=value`: argv is readable by every local user.
export SENTINEL_API_KEY="smoke-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
BASE="http://127.0.0.1:${PORT}"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# The service account's ids are allocated at build time (useradd --system), so
# ask the image rather than assuming them; the tmpfs must be writable by it.
OWNER=$(docker run --rm --entrypoint sh "$IMAGE" -c 'printf "%s:%s" "$(id -u)" "$(id -g)"')
SVC_UID=${OWNER%%:*}
SVC_GID=${OWNER##*:}

docker run -d --name "$NAME" \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --tmpfs "/data:uid=${SVC_UID},gid=${SVC_GID},mode=0700" \
    -v /etc:/host/etc:ro -v /proc:/host/proc:ro \
    -e SENTINEL_HOST_ROOT=/host \
    -e SENTINEL_API_KEY \
    -e SENTINEL_DATABASE_URL=sqlite+aiosqlite:////data/sentinel.db \
    -p "127.0.0.1:${PORT}:8000" \
    "$IMAGE" >/dev/null

echo "waiting for /readyz ..."
for _ in $(seq 1 60); do
    curl -fsS "$BASE/readyz" >/dev/null 2>&1 && break
    sleep 1
done
curl -fsS "$BASE/readyz"
echo

status=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/metrics")
[[ "$status" == "401" ]] || { echo "expected 401 without a token, got $status" >&2; exit 1; }
echo "anonymous /metrics -> 401"

printf 'Authorization: Bearer %s\n' "$SENTINEL_API_KEY" \
    | curl -fsS -H @- "$BASE/metrics" | grep -E '^sentinel_(queue_depth|events_ingested_total) '

docker stop -t 20 "$NAME" >/dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$NAME")
[[ "$code" == "0" ]] || { echo "unclean exit code $code" >&2; docker logs "$NAME" | tail -20; exit 1; }
docker logs "$NAME" 2>&1 | grep -q '"pipeline.stopped"' || { echo "pipeline did not drain" >&2; exit 1; }
echo "graceful shutdown: exit 0, pipeline drained"
echo "smoke test passed"
