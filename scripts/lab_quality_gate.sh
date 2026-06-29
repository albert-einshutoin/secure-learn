#!/bin/bash
# Local quality gate that mirrors the CI checks plus Suricata parser validation.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "============================================"
echo "Secure Learn Lab Quality Gate"
echo "============================================"
echo "Root: $ROOT_DIR"
echo

echo "[1/9] App install/build/unit tests/audit"
(
  cd "$ROOT_DIR/app"
  npm ci
  npm test
  npm audit --omit=dev --audit-level=high
)

echo
echo
echo "[2/9] App Docker image build"
docker build -t secure-learn-app-quality "$ROOT_DIR/app"

echo
echo "[3/9] Compose validation"
docker compose -f "$ROOT_DIR/docker-compose.yml" config -q
docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.alerting.yml" config -q
docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.ips.yml" config -q
docker compose -f "$ROOT_DIR/docker-compose.exercise.yml" config -q

echo
echo "[4/9] Bash syntax"
find "$ROOT_DIR/attack/scripts" "$ROOT_DIR/scripts" -type f -name '*.sh' -print0 | xargs -0 bash -n

echo
echo "[5/9] Suricata rule parser"
docker build -t secure-learn-suricata-quality "$ROOT_DIR/suricata"
docker run --rm secure-learn-suricata-quality -T -c /opt/soc-lab/suricata.yaml
docker run --rm secure-learn-suricata-quality -T -c /opt/soc-lab/suricata-ips.yaml

echo
echo "[6/9] Kubernetes static check"
"$ROOT_DIR/scripts/k8s_static_check.sh"

echo
echo "[7/9] Scenario HTML guides"
node --check "$ROOT_DIR/scripts/generate_scenario_html.js"
node "$ROOT_DIR/scripts/generate_scenario_html.js"
"$ROOT_DIR/scripts/scenario_html_check.sh"
git -C "$ROOT_DIR" diff --exit-code -- docs/scenario-guides

echo
echo "[8/9] Git whitespace check"
git -C "$ROOT_DIR" diff --check

echo
echo "[9/9] Optional runtime smoke"
APP_BASE_URL="${APP_BASE_URL:-http://localhost:3000}"
APP_HEALTH_URL="${APP_HEALTH_URL:-${APP_BASE_URL%/}/health}"
if curl -fsS "$APP_HEALTH_URL" >/dev/null 2>&1; then
  APP_URL="$APP_HEALTH_URL" "$ROOT_DIR/scripts/sre_smoke.sh"
  BASE_URL="$APP_BASE_URL" "$ROOT_DIR/scripts/backend_hands_on_tests.sh"
  BASE_URL="$APP_BASE_URL" REQUESTS=10 CONCURRENCY=2 "$ROOT_DIR/scripts/load_hands_on_tests.sh"
else
  echo "App is not running at $APP_HEALTH_URL; skipping SRE smoke."
fi

echo
echo "Quality gate passed."
