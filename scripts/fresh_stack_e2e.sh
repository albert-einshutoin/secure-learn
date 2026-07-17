#!/bin/bash
# Build a new Compose project with empty volumes and verify the public learning
# outcome end to end. Existing SOC-Lab containers are never reused or removed.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-secure-learn-e2e-${GITHUB_RUN_ID:-$$}}"
COMPOSE=(docker compose --project-name "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.yml")
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT_DIR/reports/fresh-stack}"
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-360}"

mkdir -p "$EVIDENCE_DIR"

fail() {
  echo "fresh-stack E2E failed: $*" >&2
  return 1
}

collect_and_clean() {
  local status=$?
  set +e
  "${COMPOSE[@]}" ps -a > "$EVIDENCE_DIR/compose-ps.txt" 2>&1
  "${COMPOSE[@]}" logs --no-color > "$EVIDENCE_DIR/compose.log" 2>&1
  "${COMPOSE[@]}" down --volumes --remove-orphans > "$EVIDENCE_DIR/cleanup.log" 2>&1
  exit "$status"
}
trap collect_and_clean EXIT INT TERM

wait_for_url() {
  local url="$1"
  local label="$2"
  local deadline=$((SECONDS + STARTUP_TIMEOUT))

  while ((SECONDS < deadline)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "[PASS] $label is ready."
      return 0
    fi
    sleep 3
  done
  fail "$label did not become ready at $url"
}

wait_for_siem_setup() {
  local container_id
  local state
  local exit_code
  local deadline=$((SECONDS + STARTUP_TIMEOUT))

  container_id="$("${COMPOSE[@]}" ps -a -q siem-setup)"
  [[ -n "$container_id" ]] || fail "siem-setup container was not created"

  while ((SECONDS < deadline)); do
    state="$(docker inspect -f '{{.State.Status}}' "$container_id")"
    if [[ "$state" == "exited" ]]; then
      exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$container_id")"
      [[ "$exit_code" == "0" ]] || fail "siem-setup exited with $exit_code"
      echo "[PASS] SIEM bootstrap completed."
      return 0
    fi
    sleep 3
  done
  fail "siem-setup did not complete"
}

existing_containers="$(docker ps -a --format '{{.Names}}' | grep '^soc-lab-' || true)"
if [[ -n "$existing_containers" ]]; then
  fail "existing SOC-Lab containers must be stopped and removed before the destructive fresh-stack gate: $existing_containers"
fi

echo "Starting fresh Compose project $PROJECT_NAME..."
"${COMPOSE[@]}" up -d --build

wait_for_url http://127.0.0.1:3000/health "Application"
wait_for_url 'http://127.0.0.1:9200/_cluster/health?wait_for_status=yellow' "Elasticsearch"
wait_for_url http://127.0.0.1:5601/api/status "Kibana"
wait_for_siem_setup

COMPOSE_PROJECT_NAME="$PROJECT_NAME" WAIT_SECONDS=120 "$ROOT_DIR/scripts/scenario_e2e_check.sh" S3
MAX_ATTEMPTS=45 WAIT_SECONDS=2 "$ROOT_DIR/scripts/siem_e2e_check.sh"

curl -fsS http://127.0.0.1:3000/health > "$EVIDENCE_DIR/app-health.json"
curl -fsS http://127.0.0.1:9200/_cluster/health > "$EVIDENCE_DIR/elasticsearch-health.json"
curl -fsS 'http://127.0.0.1:9200/soc-lab-*/_count' > "$EVIDENCE_DIR/event-count.json"

echo "Fresh-stack E2E verification passed."
