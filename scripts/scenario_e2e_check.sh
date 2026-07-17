#!/bin/bash
# Execute one Docker-backed attack scenario and prove that each telemetry layer
# observed the new event. A scenario is complete only when these checks pass.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT_DIR/docker-compose.yml")
ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
WAIT_SECONDS="${WAIT_SECONDS:-90}"
SCENARIO="$(printf '%s' "${1:-S3}" | tr '[:lower:]' '[:upper:]')"

fail() {
  echo "scenario E2E failed: $*" >&2
  exit 1
}

app_event_count() {
  local pattern="$1"
  "${COMPOSE[@]}" exec -T -e "PATTERN=$pattern" app sh -c \
    'grep -h -F -- "$PATTERN" /var/log/app/*.log 2>/dev/null | wc -l' | tr -d '[:space:]'
}

suricata_event_count() {
  local pattern="$1"
  "${COMPOSE[@]}" exec -T -e "PATTERN=$pattern" suricata sh -c \
    'grep -h -F -- "$PATTERN" /var/log/suricata/eve-*.json 2>/dev/null | wc -l' | tr -d '[:space:]'
}

verify_application_event() {
  local pattern="$1"
  local baseline="$2"
  local deadline=$((SECONDS + WAIT_SECONDS))
  local current

  while ((SECONDS < deadline)); do
    current="$(app_event_count "$pattern")"
    if ((current > baseline)); then
      echo "[PASS] Application log recorded a new '$pattern' event ($baseline -> $current)."
      return 0
    fi
    sleep 2
  done
  return 1
}

verify_suricata_event() {
  local pattern="$1"
  local baseline="$2"
  local deadline=$((SECONDS + WAIT_SECONDS))
  local current

  while ((SECONDS < deadline)); do
    current="$(suricata_event_count "$pattern")"
    if ((current > baseline)); then
      echo "[PASS] Suricata recorded a new '$pattern' event ($baseline -> $current)."
      return 0
    fi
    sleep 2
  done
  return 1
}

verify_elasticsearch_event() {
  local query="$1"
  local started_at="$2"
  local deadline=$((SECONDS + WAIT_SECONDS))
  local response
  local bounded_query="($query) AND @timestamp:[\"$started_at\" TO *]"

  while ((SECONDS < deadline)); do
    response="$(curl -fsS --get "$ELASTICSEARCH_URL/soc-lab-*/_count" \
      --data-urlencode "q=$bounded_query" 2>/dev/null || true)"
    if jq -e '.count > 0' >/dev/null 2>&1 <<<"$response"; then
      echo "[PASS] Elasticsearch indexed scenario telemetry after $started_at."
      return 0
    fi
    sleep 3
  done
  return 1
}

case "$SCENARIO" in
  S1)
    attack_script=/scripts/s1_portscan.sh
    app_pattern=
    suricata_pattern=SCAN
    elasticsearch_query='rule.name:*SCAN*'
    ;;
  S2)
    attack_script=/scripts/s2_bruteforce.sh
    app_pattern='"event.action":"login_failed"'
    suricata_pattern=BRUTEFORCE
    elasticsearch_query='event.action:login_failed OR rule.name:*BRUTEFORCE*'
    ;;
  S3)
    attack_script=/scripts/s3_sqli.sh
    app_pattern='"event.action":"sqli_attempt"'
    suricata_pattern=SQLI
    elasticsearch_query='event.action:sqli_attempt OR rule.name:*SQLI*'
    ;;
  S4)
    attack_script=/scripts/s4_dos.sh
    app_pattern='"event.action":"access"'
    suricata_pattern=DOS
    elasticsearch_query='rule.name:*DOS*'
    ;;
  S7)
    attack_script=/scripts/s7_lateral.sh
    app_pattern='"event.action":"sqli_attempt"'
    suricata_pattern=SQLI
    elasticsearch_query='event.action:sqli_attempt OR rule.name:*SQLI*'
    ;;
  *)
    fail "unsupported automated telemetry scenario '$SCENARIO' (supported: S1, S2, S3, S4, S7)"
    ;;
esac

for service in app kali suricata filebeat elasticsearch; do
  "${COMPOSE[@]}" ps --status running --services | grep -Fxq "$service" \
    || fail "service '$service' is not running"
done

curl -fsS "$ELASTICSEARCH_URL/_cluster/health" >/dev/null \
  || fail "Elasticsearch is not reachable at $ELASTICSEARCH_URL"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
app_baseline=0
if [[ -n "$app_pattern" ]]; then
  app_baseline="$(app_event_count "$app_pattern")"
fi
suricata_baseline="$(suricata_event_count "$suricata_pattern")"

echo "Running $SCENARIO at $started_at..."
"${COMPOSE[@]}" exec -T kali env DELAY=0 REQUESTS="${SCENARIO_REQUESTS:-150}" \
  "$attack_script"

if [[ -n "$app_pattern" ]]; then
  verify_application_event "$app_pattern" "$app_baseline" \
    || fail "application log did not record '$app_pattern'"
fi
verify_suricata_event "$suricata_pattern" "$suricata_baseline" \
  || fail "Suricata did not record '$suricata_pattern'"
verify_elasticsearch_event "$elasticsearch_query" "$started_at" \
  || fail "Elasticsearch did not index '$elasticsearch_query'"

echo "Scenario $SCENARIO E2E verification passed."
