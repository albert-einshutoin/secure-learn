#!/bin/bash
# Local quality gate that mirrors the CI checks plus Suricata parser validation.

set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
if [[ "$SCRIPT_DIR" == "$SCRIPT_PATH" ]]; then
  SCRIPT_DIR=.
fi
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
source "$ROOT_DIR/scripts/lib/target_guard.sh"

APP_BASE_URL="${APP_BASE_URL:-http://127.0.0.1:3000}"
APP_HEALTH_URL="${APP_HEALTH_URL:-${APP_BASE_URL}/health}"
ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
KIBANA_URL="${KIBANA_URL:-http://127.0.0.1:5601}"

secure_learn_validate_exact_loopback_endpoint APP_BASE_URL "$APP_BASE_URL" "http://127.0.0.1:3000"
secure_learn_validate_exact_loopback_endpoint APP_HEALTH_URL "$APP_HEALTH_URL" "http://127.0.0.1:3000/health"
secure_learn_validate_exact_loopback_endpoint ELASTICSEARCH_URL "$ELASTICSEARCH_URL" "http://127.0.0.1:9200"
secure_learn_validate_exact_loopback_endpoint KIBANA_URL "$KIBANA_URL" "http://127.0.0.1:5601"

REQUIRE_RUNTIME="${REQUIRE_RUNTIME:-0}"

verify_generator_idempotency() {
  local generated_dir="$1"
  shift
  local snapshot
  snapshot="$(mktemp -d)"

  # Compare the generated tree to its immediate pre-run state so this gate is
  # valid on an uncommitted feature branch as well as on a clean CI checkout.
  cp -R "$generated_dir/." "$snapshot/"
  "$@"
  if ! diff -r "$snapshot" "$generated_dir"; then
    rm -rf "$snapshot"
    echo "Generated output is not reproducible: $generated_dir" >&2
    return 1
  fi
  rm -rf "$snapshot"
}

echo "============================================"
echo "Secure Learn Lab Quality Gate"
echo "============================================"
echo "Root: $ROOT_DIR"
echo

echo "[1/12] Root product and curriculum contract tests"
(
  cd "$ROOT_DIR"
  node --test test/*.test.js
)

echo
echo "[2/12] App install/build/unit tests/audit"
(
  cd "$ROOT_DIR/app"
  npm ci
  npm test
  npm audit --omit=dev --audit-level=high
)

echo
echo
echo "[3/12] Curriculum manifest and coverage contracts"
"$ROOT_DIR/scripts/curriculum_check.sh"

echo
echo "[4/12] App Docker image build"
docker build -t secure-learn-app-quality "$ROOT_DIR/app"

echo
echo "[5/12] Compose validation"
docker compose -f "$ROOT_DIR/docker-compose.yml" config -q
docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.alerting.yml" config -q
docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.ips.yml" config -q
docker compose -f "$ROOT_DIR/docker-compose.exercise.yml" config -q

echo
echo "[6/12] Learning Docker phases"
node --check "$ROOT_DIR/scripts/generate_learning_phase_html.js"
verify_generator_idempotency \
  "$ROOT_DIR/docs/learning-phases" \
  node "$ROOT_DIR/scripts/generate_learning_phase_html.js"
"$ROOT_DIR/scripts/learning_phase_check.sh"

echo
echo "[7/12] Bash syntax"
find "$ROOT_DIR/attack/scripts" "$ROOT_DIR/scripts" "$ROOT_DIR/elk" -type f -name '*.sh' -print0 | xargs -0 bash -n

echo
echo "[8/12] Suricata rule parser"
docker build -t secure-learn-suricata-quality "$ROOT_DIR/suricata"
docker run --rm secure-learn-suricata-quality -T -c /opt/soc-lab/suricata.yaml
docker run --rm secure-learn-suricata-quality -T -c /opt/soc-lab/suricata-ips.yaml

echo
echo "[9/12] Kubernetes static check"
"$ROOT_DIR/scripts/k8s_static_check.sh"

echo
echo "[10/12] Scenario HTML guides"
node --check "$ROOT_DIR/scripts/generate_scenario_html.js"
verify_generator_idempotency \
  "$ROOT_DIR/docs/scenario-guides" \
  node "$ROOT_DIR/scripts/generate_scenario_html.js"
"$ROOT_DIR/scripts/scenario_html_check.sh"

echo
echo "[11/12] Git whitespace check"
git -C "$ROOT_DIR" diff --check

echo
echo "[12/12] Optional runtime smoke"
if curl -fsS "$APP_HEALTH_URL" >/dev/null 2>&1; then
  APP_URL="$APP_HEALTH_URL" "$ROOT_DIR/scripts/sre_smoke.sh"
  BASE_URL="$APP_BASE_URL" "$ROOT_DIR/scripts/backend_hands_on_tests.sh"
  BASE_URL="$APP_BASE_URL" REQUESTS=10 CONCURRENCY=2 "$ROOT_DIR/scripts/load_hands_on_tests.sh"
else
  if [[ "$REQUIRE_RUNTIME" == "1" ]]; then
    echo "Runtime verification is required, but App is not running at $APP_HEALTH_URL." >&2
    exit 1
  fi
  echo "App is not running at $APP_HEALTH_URL; skipping SRE smoke."
fi

if curl -fsS "$ELASTICSEARCH_URL/_cluster/health" >/dev/null 2>&1 \
  && curl -fsS "$KIBANA_URL/api/status" >/dev/null 2>&1; then
  "$ROOT_DIR/scripts/siem_e2e_check.sh"
else
  if [[ "$REQUIRE_RUNTIME" == "1" ]]; then
    echo "Runtime verification is required, but Elasticsearch/Kibana are unavailable." >&2
    exit 1
  fi
  echo "Elasticsearch/Kibana are not running; skipping SIEM E2E check."
fi

echo
echo "Quality gate passed."
