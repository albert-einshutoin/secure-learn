#!/bin/bash
# Local quality gate that mirrors the CI checks plus Suricata parser validation.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "============================================"
echo "Secure Learn Lab Quality Gate"
echo "============================================"
echo "Root: $ROOT_DIR"
echo

echo "[1/6] App install/build/unit tests/audit"
(
  cd "$ROOT_DIR/app"
  npm ci
  npm test
  npm audit --omit=dev --audit-level=high
)

echo
echo "[2/6] Compose validation"
docker compose -f "$ROOT_DIR/docker-compose.yml" config -q
docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.alerting.yml" config -q
docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.ips.yml" config -q
docker compose -f "$ROOT_DIR/docker-compose.exercise.yml" config -q

echo
echo "[3/6] Bash syntax"
find "$ROOT_DIR/attack/scripts" "$ROOT_DIR/scripts" -type f -name '*.sh' -print0 | xargs -0 bash -n

echo
echo "[4/6] Suricata rule parser"
docker build -t secure-learn-suricata-quality "$ROOT_DIR/suricata"
docker run --rm secure-learn-suricata-quality -T -c /opt/soc-lab/suricata.yaml
docker run --rm secure-learn-suricata-quality -T -c /opt/soc-lab/suricata-ips.yaml

echo
echo "[5/6] Git whitespace check"
git -C "$ROOT_DIR" diff --check

echo
echo "[6/6] Optional SRE smoke"
APP_BASE_URL="${APP_BASE_URL:-http://localhost:3000}"
APP_HEALTH_URL="${APP_HEALTH_URL:-${APP_BASE_URL%/}/health}"
if curl -fsS "$APP_HEALTH_URL" >/dev/null 2>&1; then
  APP_URL="$APP_HEALTH_URL" "$ROOT_DIR/scripts/sre_smoke.sh"
else
  echo "App is not running at $APP_HEALTH_URL; skipping SRE smoke."
fi

echo
echo "Quality gate passed."
