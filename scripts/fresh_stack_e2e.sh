#!/bin/bash
# Build a new Compose project with empty volumes and verify the public learning
# outcome end to end. Existing SOC-Lab containers are never reused or removed.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-secure-learn-e2e-${GITHUB_RUN_ID:-$$}}"
COMPOSE=(docker compose --project-name "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.yml")
COMPOSE_LEARNING=(docker compose --project-name "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.learning.yml")
COMPOSE_IPS=(docker compose --project-name "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.ips.yml")
EVIDENCE_DIR="${EVIDENCE_DIR:-$ROOT_DIR/reports/fresh-stack}"
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-360}"
CONNECTION_PROBE_PID=""

mkdir -p "$EVIDENCE_DIR"

fail() {
  echo "fresh-stack E2E failed: $*" >&2
  return 1
}

collect_and_clean() {
  local status=$?
  set +e
  if [[ -n "$CONNECTION_PROBE_PID" ]]; then
    kill "$CONNECTION_PROBE_PID" 2>/dev/null || true
    wait "$CONNECTION_PROBE_PID" 2>/dev/null || true
  fi
  "${COMPOSE[@]}" ps -a > "$EVIDENCE_DIR/compose-ps.txt" 2>&1
  "${COMPOSE[@]}" logs --no-color > "$EVIDENCE_DIR/compose.log" 2>&1
  "${COMPOSE_LEARNING[@]}" --profile phase11-network-edge --profile phase8-distributed down --volumes --remove-orphans > "$EVIDENCE_DIR/learning-cleanup.log" 2>&1
  "${COMPOSE[@]}" down --volumes --remove-orphans > "$EVIDENCE_DIR/cleanup.log" 2>&1
  exit "$status"
}

wait_for_tcp() {
  local host="$1"
  local port="$2"
  local label="$3"
  local deadline=$((SECONDS + STARTUP_TIMEOUT))

  while ((SECONDS < deadline)); do
    if nc -z -w 2 "$host" "$port" >/dev/null 2>&1; then
      echo "[PASS] $label is ready."
      return 0
    fi
    sleep 2
  done
  fail "$label did not become ready at $host:$port"
}

assert_no_connectivity() {
  local service="$1"
  local command="$2"
  local label="$3"

  if "${COMPOSE[@]}" exec -T "$service" sh -c "$command" >/dev/null 2>&1; then
    fail "$label unexpectedly succeeded"
  fi
  echo "[PASS] $label is blocked."
}

assert_publisher_hardening() {
  local service="$1"
  local container_id
  container_id="$("${COMPOSE[@]}" ps -q "$service")"
  [[ -n "$container_id" ]] || fail "$service container was not created"
  [[ "$(docker inspect -f '{{.Config.User}}' "$container_id")" == "65532:65532" ]] || fail "$service is not non-root"
  [[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$container_id")" == "true" ]] || fail "$service root filesystem is writable"
  [[ "$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$container_id")" == '["ALL"]' ]] || fail "$service does not drop all capabilities"
  [[ "$(docker inspect -f '{{index .HostConfig.Sysctls "net.ipv4.ip_forward"}}' "$container_id")" == "0" ]] || fail "$service enables IP forwarding"
  [[ "$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$container_id")" == '["no-new-privileges:true"]' ]] || fail "$service permits privilege escalation"
  [[ "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$container_id")" == "80" ]] || fail "$service does not enforce its PID limit"
  echo "[PASS] $service runtime hardening is intact."
}

count_suricata_http_events() {
  "${COMPOSE[@]}" exec -T suricata sh -c \
    'grep -h '\''"event_type":"http"'\'' /var/log/suricata/eve*.json 2>/dev/null | wc -l' | tr -d '[:space:]'
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
wait_for_tcp 127.0.0.1 15432 "PostgreSQL publisher"
wait_for_url 'http://127.0.0.1:9200/_cluster/health?wait_for_status=yellow' "Elasticsearch"
wait_for_url http://127.0.0.1:5601/api/status "Kibana"
wait_for_siem_setup

# The attack container may reach only the monitored application. Neither its
# own route table nor a manually-added route through a publisher/target may
# turn a learning request into host or Internet access.
"${COMPOSE[@]}" exec -T kali curl -fsS --max-time 3 http://172.23.0.20:3000/health >/dev/null
assert_no_connectivity kali 'nc -z -w 2 172.25.0.40 5432' "Kali to data network"
assert_no_connectivity kali 'curl -fsS --max-time 2 http://1.1.1.1' "Kali external IP egress"
assert_no_connectivity kali 'curl -fsS --max-time 2 http://example.com' "Kali external DNS/HTTP egress"
assert_no_connectivity app 'wget -q -T 2 -O- http://1.1.1.1' "Application external IP egress"
assert_no_connectivity app 'wget -q -T 2 -O- http://example.com' "Application external DNS/HTTP egress"

for gateway in 172.23.0.20 172.23.0.10; do
  "${COMPOSE[@]}" exec -T kali ip route add default via "$gateway"
  assert_no_connectivity kali 'curl -fsS --max-time 2 http://1.1.1.1' "Kali route bypass via $gateway"
  "${COMPOSE[@]}" exec -T kali ip route del default
done

assert_publisher_hardening app-publisher
assert_publisher_hardening db-publisher

# Open all sockets from one Bash process inside Kali. This bypasses Docker
# Desktop's host-forwarding backlog without forking one client per connection.
pressure_status="$EVIDENCE_DIR/publisher-pressure.tmp"
"${COMPOSE[@]}" exec -T kali bash -c '
  set -euo pipefail
  requested=70
  declare -a descriptors=()
  cleanup_fds() {
    local descriptor
    for descriptor in "${descriptors[@]}"; do
      socket_fd="$descriptor"
      exec {socket_fd}>&-
    done
  }
  trap cleanup_fds EXIT INT TERM
  for ((index = 0; index < requested; index += 1)); do
    if exec {socket_fd}<>/dev/tcp/172.23.0.10/3000; then
      descriptors+=("$socket_fd")
    else
      break
    fi
  done
  printf "requested=%d opened=%d\n" "$requested" "${#descriptors[@]}"
  sleep 10
' > "$pressure_status" &
CONNECTION_PROBE_PID=$!

pressure_deadline=$((SECONDS + 10))
while [[ ! -s "$pressure_status" ]] && ((SECONDS < pressure_deadline)); do
  sleep 1
done
[[ -s "$pressure_status" ]] || fail "Kali publisher pressure probe did not report readiness"
IFS=' =' read -r requested_label requested_connections opened_label opened_connections < "$pressure_status"
[[ "$requested_label" == "requested" && "$opened_label" == "opened" ]] \
  || fail "Kali publisher pressure probe returned malformed evidence"
[[ "$requested_connections" =~ ^[0-9]+$ && "$opened_connections" =~ ^[0-9]+$ ]] \
  || fail "Kali publisher pressure probe returned non-numeric evidence"
((requested_connections == 70)) || fail "Kali publisher pressure request changed"
((opened_connections >= 65)) || fail "Kali publisher pressure opened only $opened_connections connections"
kill -0 "$CONNECTION_PROBE_PID" 2>/dev/null || fail "Kali publisher pressure probe exited early"

container_id="$("${COMPOSE[@]}" ps -q app-publisher)"
[[ -n "$container_id" ]] || fail "app-publisher container was not created"
samples_json=""
max_publisher_pids=0
max_publisher_children=0
for sample_index in $(seq 1 5); do
  top_output="$(docker top "$container_id" -eo pid,ppid,comm)" \
    || fail "docker top failed for app-publisher"
  process_counts="$(printf '%s\n' "$top_output" | "$ROOT_DIR/scripts/lib/count_publisher_processes.sh")" \
    || fail "docker top returned malformed app-publisher evidence"
  read -r publisher_pid_count publisher_child_count <<< "$process_counts"
  ((publisher_pid_count <= 80)) || fail "app-publisher exceeded its 80 PID limit: $publisher_pid_count"
  ((publisher_child_count <= 64)) || fail "app-publisher exceeded its 64 child limit: $publisher_child_count"
  ((publisher_pid_count > max_publisher_pids)) && max_publisher_pids=$publisher_pid_count
  ((publisher_child_count > max_publisher_children)) && max_publisher_children=$publisher_child_count
  [[ "$(docker inspect -f '{{.State.Running}}' "$container_id")" == "true" ]] \
    || fail "app-publisher stopped under bounded connection pressure"
  [[ -z "$samples_json" ]] || samples_json+=','
  samples_json+="{\"index\":$sample_index,\"pids\":$publisher_pid_count,\"children\":$publisher_child_count}"
  sleep 1
done
((max_publisher_pids <= 80)) || fail "app-publisher sampled PID maximum exceeded 80"
((max_publisher_children <= 64)) || fail "app-publisher sampled child maximum exceeded 64"
((max_publisher_children >= 10)) || fail "publisher pressure did not create enough children: $max_publisher_children"

wait "$CONNECTION_PROBE_PID"
CONNECTION_PROBE_PID=""
wait_for_url http://127.0.0.1:3000/health "Application after publisher pressure"
printf '{"requested":%d,"opened":%d,"samples":[%s],"max_pids":%d,"max_children":%d,"limits":{"pids":80,"children":64},"recovered":true}\n' \
  "$requested_connections" "$opened_connections" "$samples_json" \
  "$max_publisher_pids" "$max_publisher_children" \
  > "$EVIDENCE_DIR/publisher-connection-limit.json"
rm -f "$pressure_status"
echo "[PASS] app-publisher stays within PID/child limits and recovers (max_pids=$max_publisher_pids, max_children=$max_publisher_children)."

# A Kali request must still cross eth0 in the shared target namespace after
# the data network was split out; otherwise the lab would silently bypass IDS.
before_http_events="$(count_suricata_http_events)"
"${COMPOSE[@]}" exec -T kali curl -fsS --max-time 3 http://172.23.0.20:3000/health >/dev/null
for _ in $(seq 1 15); do
  after_http_events="$(count_suricata_http_events)"
  if ((after_http_events > before_http_events)); then
    break
  fi
  sleep 1
done
((after_http_events > before_http_events)) || fail "Suricata did not observe Kali HTTP traffic"
"${COMPOSE[@]}" exec -T suricata sh -c \
  'grep -h '\''"event_type":"http"'\'' /var/log/suricata/eve*.json | grep -q '\''"in_iface":"eth0"'\''' \
  || fail "Suricata HTTP events are not captured on eth0"
echo "[PASS] Suricata observes the isolated attack path on eth0."

# Exercise the two learning-only publishers without starting unrelated phase
# services. They reuse the already-built immutable publisher image.
"${COMPOSE_LEARNING[@]}" --profile phase11-network-edge up -d learning-edge-publisher
wait_for_url http://127.0.0.1:8080/health "Learning edge publisher"
"${COMPOSE_LEARNING[@]}" --profile phase8-distributed up -d learning-redis-publisher
wait_for_tcp 127.0.0.1 6380 "Learning Redis publisher"

# The privileged IPS helper has its own bounded, networkless runtime contract.
"${COMPOSE_IPS[@]}" build ips-iptables
"$ROOT_DIR/scripts/verify_ips_helper.sh" secure-learn-ips-iptables:local

COMPOSE_PROJECT_NAME="$PROJECT_NAME" WAIT_SECONDS=120 "$ROOT_DIR/scripts/scenario_e2e_check.sh" S3
MAX_ATTEMPTS=45 WAIT_SECONDS=2 "$ROOT_DIR/scripts/siem_e2e_check.sh"

curl -fsS http://127.0.0.1:3000/health > "$EVIDENCE_DIR/app-health.json"
curl -fsS http://127.0.0.1:9200/_cluster/health > "$EVIDENCE_DIR/elasticsearch-health.json"
curl -fsS 'http://127.0.0.1:9200/soc-lab-*/_count' > "$EVIDENCE_DIR/event-count.json"

echo "Fresh-stack E2E verification passed."
