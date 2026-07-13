#!/bin/sh
# Single idempotent entrypoint used by Compose to make the SIEM useful after a
# fresh `docker compose up`, without requiring hidden manual setup steps.

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-http://elasticsearch:9200}" \
  sh "$SCRIPT_DIR/setup-ilm.sh"
KIBANA_HOST="${KIBANA_HOST:-http://kibana:5601}" \
  sh "$SCRIPT_DIR/kibana/import-objects.sh"

echo "SOC-Lab SIEM bootstrap completed."
