#!/bin/sh
# Import the bundled data views, saved searches, and dashboards idempotently.

set -eu

KIBANA_HOST="${KIBANA_HOST:-http://localhost:5601}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
EXPORTS_DIR="$SCRIPT_DIR/exports"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-60}"
WAIT_SECONDS="${WAIT_SECONDS:-5}"

wait_for_kibana() {
  attempt=1
  while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
    status="$(curl -fsS "$KIBANA_HOST/api/status" 2>/dev/null || true)"
    if printf '%s' "$status" | grep -q '"level":"available"'; then
      return 0
    fi
    echo "Waiting for Kibana ($attempt/$MAX_ATTEMPTS)..."
    attempt=$((attempt + 1))
    sleep "$WAIT_SECONDS"
  done

  echo "Kibana did not become ready: $KIBANA_HOST" >&2
  return 1
}

import_objects() {
  file="$1"
  response="$(curl -fsS -X POST "$KIBANA_HOST/api/saved_objects/_import?overwrite=true" \
    -H 'kbn-xsrf: secure-learn-bootstrap' \
    --form "file=@$EXPORTS_DIR/$file")"

  if ! printf '%s' "$response" | grep -q '"success":true'; then
    echo "Kibana import failed for $file: $response" >&2
    return 1
  fi
}

wait_for_kibana
import_objects data-views.ndjson
import_objects saved-searches.ndjson
import_objects dashboards.ndjson
import_objects kpi-dashboard.ndjson

echo "Kibana data views, searches, and dashboards are ready."
