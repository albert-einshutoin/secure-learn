#!/bin/bash
# Bundles backend, load, and optional chaos checks into one evidence directory.

set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
if [[ "$BASE_URL" != "http://127.0.0.1:3000" ]]; then
  echo "ERROR: BASE_URL must be the loopback-only Secure Learn endpoint http://127.0.0.1:3000." >&2
  exit 64
fi

# Child drills derive Compose paths from their own repository location. Removing
# this override prevents callers from redirecting chaos operations to a different
# Compose project.
unset COMPOSE_PROJECT_DIR

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="${SCRIPT_PATH%/*}"
if [[ "$SCRIPT_DIR" == "$SCRIPT_PATH" ]]; then
  SCRIPT_DIR=.
fi
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
REPORT_DIR="${REPORT_DIR:-reports/incident_drill_$(date +%Y%m%d_%H%M%S)}"
RUN_CHAOS="${RUN_CHAOS:-0}"

mkdir -p "$REPORT_DIR"

echo "============================================"
echo "Secure Learn Incident Drill"
echo "============================================"
echo "Base URL: $BASE_URL"
echo "Report dir: $REPORT_DIR"
echo

BASE_URL="$BASE_URL" REPORT_DIR="$REPORT_DIR/backend" "$ROOT_DIR/scripts/backend_hands_on_tests.sh"
BASE_URL="$BASE_URL" REPORT_DIR="$REPORT_DIR/load" "$ROOT_DIR/scripts/load_hands_on_tests.sh"

if [ "$RUN_CHAOS" = "1" ]; then
  BASE_URL="$BASE_URL" REPORT_DIR="$REPORT_DIR/chaos" "$ROOT_DIR/scripts/chaos_hands_on_tests.sh"
else
  echo "Skipping chaos drill. Set RUN_CHAOS=1 to pause and recover the db service."
fi

cat > "$REPORT_DIR/summary.md" << EOF
# Incident Drill Summary

- Date: $(date -Iseconds)
- Base URL: $BASE_URL
- Backend evidence: backend/summary.md
- Load evidence: load/summary.md
- Chaos evidence: $(if [ "$RUN_CHAOS" = "1" ]; then echo "chaos/summary.md"; else echo "skipped"; fi)

## Operator Notes

1. Confirm alert/log evidence in Kibana or log files.
2. Record impact, timeline, mitigation, and follow-up actions in docs/templates/postmortem.md.
3. Link this evidence directory from the remediation PR or incident report.
EOF

echo
echo "Incident drill passed. Summary: $REPORT_DIR/summary.md"
