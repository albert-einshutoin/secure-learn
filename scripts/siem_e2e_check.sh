#!/bin/bash
# Verify the user-visible SIEM outcome, not only container health.

set -euo pipefail

ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
KIBANA_URL="${KIBANA_URL:-http://127.0.0.1:5601}"
EXPECTED_DASHBOARDS="${EXPECTED_DASHBOARDS:-4}"
EXPECTED_DATA_VIEWS="${EXPECTED_DATA_VIEWS:-5}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
WAIT_SECONDS="${WAIT_SECONDS:-2}"

json_number() {
  local field="$1"
  python3 -c 'import json, sys; print(int(json.load(sys.stdin)[sys.argv[1]]))' "$field"
}

wait_for_url() {
  local url="$1"
  local label="$2"
  local attempt=1

  while (( attempt <= MAX_ATTEMPTS )); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    printf 'Waiting for %s (%d/%d)...\n' "$label" "$attempt" "$MAX_ATTEMPTS"
    attempt=$((attempt + 1))
    sleep "$WAIT_SECONDS"
  done

  echo "$label did not become ready at $url" >&2
  return 1
}

wait_for_event_count() {
  local attempt=1
  local response
  local count

  # Filebeat publishes asynchronously after service health is green. Waiting
  # here verifies the user-visible outcome without making fresh starts flaky.
  while (( attempt <= MAX_ATTEMPTS )); do
    response="$(curl -sS "$ELASTICSEARCH_URL/soc-lab-*/_count" 2>/dev/null || true)"
    if count="$(printf '%s' "$response" | json_number count 2>/dev/null)" \
      && (( count >= 1 )); then
      printf '%d\n' "$count"
      return 0
    fi
    printf 'Waiting for indexed SOC events (%d/%d)...\n' "$attempt" "$MAX_ATTEMPTS" >&2
    attempt=$((attempt + 1))
    sleep "$WAIT_SECONDS"
  done

  echo "No SOC events were indexed before the timeout" >&2
  return 1
}

assert_at_least() {
  local actual="$1"
  local expected="$2"
  local label="$3"

  if (( actual < expected )); then
    echo "$label: expected at least $expected, found $actual" >&2
    return 1
  fi
  printf '%s: %d (expected >= %d)\n' "$label" "$actual" "$expected"
}

wait_for_url "$ELASTICSEARCH_URL/_cluster/health?wait_for_status=yellow" Elasticsearch
wait_for_url "$KIBANA_URL/api/status" Kibana

curl -fsS "$ELASTICSEARCH_URL/_ilm/policy/soc-lab-policy" >/dev/null
for dataset in suricata nestjs fail2ban auditd; do
  curl -fsS "$ELASTICSEARCH_URL/_index_template/soc-lab-$dataset-template" >/dev/null
done

event_count="$(wait_for_event_count)"
data_view_count="$(curl -fsS -H 'kbn-xsrf: secure-learn-check' \
  "$KIBANA_URL/api/saved_objects/_find?type=index-pattern&per_page=100" | json_number total)"
dashboard_count="$(curl -fsS -H 'kbn-xsrf: secure-learn-check' \
  "$KIBANA_URL/api/saved_objects/_find?type=dashboard&per_page=100" | json_number total)"

assert_at_least "$event_count" 1 'Indexed SOC events'
assert_at_least "$data_view_count" "$EXPECTED_DATA_VIEWS" 'Kibana data views'
assert_at_least "$dashboard_count" "$EXPECTED_DASHBOARDS" 'Kibana dashboards'

echo 'SIEM end-to-end check passed.'
