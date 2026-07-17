#!/bin/bash
# DB outage drill: readiness should fail during outage and recover afterwards.

set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
if [[ "$BASE_URL" != "http://127.0.0.1:3000" ]]; then
  echo "ERROR: BASE_URL must be the loopback-only Secure Learn endpoint http://127.0.0.1:3000." >&2
  exit 64
fi

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
if [[ "$SCRIPT_DIR" == "$SCRIPT_PATH" ]]; then
  SCRIPT_DIR=.
fi
unset COMPOSE_PROJECT_DIR
readonly COMPOSE_PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
REPORT_DIR="${REPORT_DIR:-reports/chaos_hands_on_$(date +%Y%m%d_%H%M%S)}"

mkdir -p "$REPORT_DIR"
summary_file="$REPORT_DIR/summary.md"

cleanup() {
  docker compose -f "$COMPOSE_PROJECT_DIR/docker-compose.yml" unpause db >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_status() {
  local expected="$1"
  local attempts="${2:-20}"
  local code

  for _ in $(seq "$attempts"); do
    code=$(curl -sS -o "$REPORT_DIR/response.json" -w '%{http_code}' "$BASE_URL/health/ready" || true)
    if [ "$code" = "$expected" ]; then
      return 0
    fi
    sleep 1
  done

  echo "$code"
  return 1
}

echo "============================================"
echo "Secure Learn Chaos Hands-on Tests"
echo "============================================"
echo "Base URL: $BASE_URL"
echo "Report: $summary_file"
echo

if ! docker compose -f "$COMPOSE_PROJECT_DIR/docker-compose.yml" ps db >/dev/null 2>&1; then
  echo "Docker Compose db service is not available."
  exit 1
fi

if ! wait_for_status 200 10; then
  echo "Readiness did not start healthy."
  exit 1
fi

docker compose -f "$COMPOSE_PROJECT_DIR/docker-compose.yml" pause db >/dev/null

if wait_for_status 503 10; then
  outage_status="PASS"
else
  outage_status="FAIL"
fi

docker compose -f "$COMPOSE_PROJECT_DIR/docker-compose.yml" unpause db >/dev/null

if wait_for_status 200 20; then
  recovery_status="PASS"
else
  recovery_status="FAIL"
fi

cat > "$summary_file" << EOF
# Chaos Hands-on Test Report

- Date: $(date -Iseconds)
- Base URL: $BASE_URL
- Fault: pause docker compose db service
- Readiness during outage: $outage_status
- Readiness after recovery: $recovery_status
EOF

echo "Readiness during outage: $outage_status"
echo "Readiness after recovery: $recovery_status"
echo "Report: $summary_file"

if [ "$outage_status" != "PASS" ] || [ "$recovery_status" != "PASS" ]; then
  exit 1
fi
