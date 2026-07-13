#!/bin/sh
# Install the lifecycle policy and regular-index templates used by Filebeat.

set -eu

ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-http://localhost:9200}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-60}"
WAIT_SECONDS="${WAIT_SECONDS:-5}"

wait_for_elasticsearch() {
  attempt=1
  while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
    if curl -fsS "$ELASTICSEARCH_HOST/_cluster/health?wait_for_status=yellow" >/dev/null; then
      return 0
    fi
    echo "Waiting for Elasticsearch ($attempt/$MAX_ATTEMPTS)..."
    attempt=$((attempt + 1))
    sleep "$WAIT_SECONDS"
  done

  echo "Elasticsearch did not become ready: $ELASTICSEARCH_HOST" >&2
  return 1
}

wait_for_elasticsearch

curl -fsS -X PUT "$ELASTICSEARCH_HOST/_ilm/policy/soc-lab-policy" \
  -H 'Content-Type: application/json' \
  --data-binary "@$SCRIPT_DIR/ilm-policy.json" >/dev/null

for dataset in suricata nestjs fail2ban auditd; do
  # Filebeat writes explicit daily indices, so these templates intentionally do
  # not declare data_stream or a rollover alias.
  curl -fsS -X PUT "$ELASTICSEARCH_HOST/_index_template/soc-lab-$dataset-template" \
    -H 'Content-Type: application/json' \
    --data-binary @- >/dev/null <<EOF
{
  "index_patterns": ["soc-lab-$dataset-*"],
  "priority": 200,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "soc-lab-policy"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "source.ip": { "type": "ip", "ignore_malformed": true },
        "destination.ip": { "type": "ip", "ignore_malformed": true },
        "source.port": { "type": "integer", "ignore_malformed": true },
        "destination.port": { "type": "integer", "ignore_malformed": true },
        "event.module": { "type": "keyword" },
        "event.dataset": { "type": "keyword" },
        "event.category": { "type": "keyword" },
        "event.type": { "type": "keyword" },
        "event.action": { "type": "keyword" },
        "event.outcome": { "type": "keyword" },
        "rule.name": { "type": "keyword" },
        "rule.id": { "type": "keyword" },
        "user.name": { "type": "keyword" },
        "url.path": { "type": "keyword" },
        "http.request.method": { "type": "keyword" },
        "http.response.status_code": { "type": "integer" },
        "message": { "type": "text" }
      }
    }
  }
}
EOF
done

echo "Elasticsearch lifecycle policy and index templates are ready."
