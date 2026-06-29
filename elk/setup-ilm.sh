#!/bin/bash
# SOC-Lab ILM Policy Setup Script

ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-http://localhost:9200}"

echo "Setting up SOC-Lab ILM Policy..."

# Wait for Elasticsearch to be ready
until curl -s "$ELASTICSEARCH_HOST/_cluster/health" | grep -q '"status":"green"\|"status":"yellow"'; do
  echo "Waiting for Elasticsearch..."
  sleep 5
done

echo "Elasticsearch is ready."

# Create ILM Policy
curl -X PUT "$ELASTICSEARCH_HOST/_ilm/policy/soc-lab-policy" \
  -H "Content-Type: application/json" \
  -d @- << 'EOF'
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_primary_shard_size": "1gb",
            "max_age": "1d"
          }
        }
      },
      "delete": {
        "min_age": "7d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
EOF

echo ""
echo "ILM Policy created."

# Create Index Templates
for index in suricata nestjs fail2ban auditd; do
  echo "Creating template for soc-lab-$index..."
  curl -X PUT "$ELASTICSEARCH_HOST/_index_template/soc-lab-$index-template" \
    -H "Content-Type: application/json" \
    -d @- << EOF
{
  "index_patterns": ["soc-lab-$index-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "soc-lab-policy"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "source.ip": { "type": "ip" },
        "destination.ip": { "type": "ip" },
        "source.port": { "type": "integer" },
        "destination.port": { "type": "integer" },
        "event.module": { "type": "keyword" },
        "event.category": { "type": "keyword" },
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
  },
  "priority": 200
}
EOF
  echo ""
done

echo "Index templates created."
echo "SOC-Lab ILM setup complete!"

