#!/bin/bash
# SOC-Lab Kibana Objects Import Script

KIBANA_HOST="${KIBANA_HOST:-http://localhost:5601}"
EXPORTS_DIR="$(dirname "$0")/exports"

echo "Importing Kibana objects to $KIBANA_HOST..."

# Wait for Kibana to be ready
until curl -s "$KIBANA_HOST/api/status" | grep -q '"level":"available"'; do
  echo "Waiting for Kibana..."
  sleep 5
done

echo "Kibana is ready."

# Import Data Views
echo "Importing Data Views..."
curl -X POST "$KIBANA_HOST/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: multipart/form-data" \
  --form file=@"$EXPORTS_DIR/data-views.ndjson"

echo ""

# Import Saved Searches
echo "Importing Saved Searches..."
curl -X POST "$KIBANA_HOST/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: multipart/form-data" \
  --form file=@"$EXPORTS_DIR/saved-searches.ndjson"

echo ""

# Import Dashboards
echo "Importing Dashboards..."
curl -X POST "$KIBANA_HOST/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: multipart/form-data" \
  --form file=@"$EXPORTS_DIR/dashboards.ndjson"

echo ""

# Note: Detection rules need to be imported via Security API
echo "Note: Detection rules should be imported via Kibana Security UI or API."
echo ""

echo "Kibana objects import complete!"
echo ""
echo "Available dashboards:"
echo "  - SOC-Overview: $KIBANA_HOST/app/dashboards#/view/soc-lab-dashboard-overview"
echo "  - Attack-Timeline: $KIBANA_HOST/app/dashboards#/view/soc-lab-dashboard-timeline"
echo "  - Layer-Analysis: $KIBANA_HOST/app/dashboards#/view/soc-lab-dashboard-layer"

