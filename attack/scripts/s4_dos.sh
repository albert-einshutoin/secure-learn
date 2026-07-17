#!/bin/bash
# SOC-Lab Attack Script: S4 - DoS Attack
# Purpose: Demonstrate denial of service detection

set -e

# Configuration
TARGET="${TARGET:-app}"
TARGET_IP="${TARGET_IP:-172.23.0.20}"
TARGET_PORT="${TARGET_PORT:-3000}"
CONCURRENT="${CONCURRENT:-50}"
REQUESTS="${REQUESTS:-500}"
OUTPUT_DIR="/results"

echo "============================================"
echo "SOC-Lab Scenario S4: DoS Attack"
echo "============================================"
echo ""
echo "Target: http://$TARGET:$TARGET_PORT/"
echo "Concurrent connections: $CONCURRENT"
echo "Total requests: $REQUESTS"
echo "Time: $(date -Iseconds)"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s4_dos_$(date +%Y%m%d_%H%M%S).txt"

# Check if target is reachable
echo "Checking target connectivity..."
start_response=$(curl -s --connect-timeout 5 -o /dev/null -w "%{http_code}" "http://$TARGET:$TARGET_PORT/" || echo "000")
if [ "$start_response" = "000" ]; then
    echo "ERROR: Target is not reachable at http://$TARGET:$TARGET_PORT"
    exit 1
fi
echo "Target is reachable (HTTP $start_response)."
echo ""

echo "============================================"
echo "Phase 1: Baseline Performance"
echo "============================================"

# Get baseline response time
echo "Measuring baseline response time..."
for i in 1 2 3; do
    baseline=$(curl -s -o /dev/null -w "%{time_total}" "http://$TARGET:$TARGET_PORT/")
    echo "  Request $i: ${baseline}s"
done
echo ""

echo "============================================"
echo "Phase 2: High-Frequency Requests (Bash)"
echo "============================================"

echo "Sending $REQUESTS rapid requests..."
success_count=0
fail_count=0
rate_limited=0

for i in $(seq 1 $REQUESTS); do
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://$TARGET:$TARGET_PORT/" 2>/dev/null || echo "000")
    
    case $response in
        200) ((success_count += 1)) ;;
        429) ((rate_limited += 1)) ;;
        *) ((fail_count += 1)) ;;
    esac
    
    # Progress indicator
    if [ $((i % 50)) -eq 0 ]; then
        echo "  Progress: $i/$REQUESTS (OK:$success_count, 429:$rate_limited, Fail:$fail_count)"
    fi
done

echo ""
echo "Results:"
echo "  Successful (200): $success_count"
echo "  Rate Limited (429): $rate_limited"
echo "  Failed/Timeout: $fail_count"

echo ""
echo "============================================"
echo "Phase 3: Parallel Attack"
echo "============================================"

echo "Sending parallel requests ($CONCURRENT concurrent)..."

# Use background processes for parallel requests
parallel_results="$OUTPUT_DIR/s4_parallel_results.txt"
> "$parallel_results"

for i in $(seq 1 100); do
    (
        response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://$TARGET:$TARGET_PORT/" 2>/dev/null || echo "000")
        echo "$response" >> "$parallel_results"
    ) &
    
    # Limit concurrent background jobs
    if [ $(jobs -r | wc -l) -ge $CONCURRENT ]; then
        wait -n
    fi
done

# Wait for all background jobs to complete
wait

# Count results
p_success=$(grep -c "200" "$parallel_results" 2>/dev/null || echo "0")
p_limited=$(grep -c "429" "$parallel_results" 2>/dev/null || echo "0")
p_fail=$(grep -c -v "200\|429" "$parallel_results" 2>/dev/null || echo "0")

echo ""
echo "Parallel Attack Results:"
echo "  Successful (200): $p_success"
echo "  Rate Limited (429): $p_limited"
echo "  Failed/Timeout: $p_fail"

echo ""
echo "============================================"
echo "Phase 4: Check Detection Status"
echo "============================================"

# Wait a moment for detection
sleep 2

# Check if we're banned or rate limited
echo "Checking current status..."
final_response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://$TARGET:$TARGET_PORT/" 2>/dev/null || echo "000")

case $final_response in
    200) echo "  Status: Normal (200 OK)" ;;
    429) echo "  [PASS] Rate limited (429 Too Many Requests)" ;;
    000) echo "  [PASS] Banned/Blocked (Connection refused)" ;;
    *) echo "  Status: HTTP $final_response" ;;
esac

echo ""
echo "============================================"
echo "Attack Complete"
echo "============================================"
echo ""
echo "Check the following for detection:"
echo ""
echo "1. Suricata logs:"
echo "   docker exec soc-lab-suricata grep DOS /var/log/suricata/fast.log"
echo ""
echo "2. Application access logs:"
echo "   docker exec soc-lab-app cat /var/log/app/access.log | tail -50"
echo ""
echo "3. Fail2ban status:"
echo "   docker exec soc-lab-fail2ban fail2ban-client status nestjs-dos"
echo ""
echo "4. Kibana:"
echo "   - Search: rule.name:*DOS*"
echo "   - Dashboard: Attack-Timeline"
echo ""
echo "Verification still required:"
echo "  [ ] Rate limiting or service protection is observed"
echo "  [ ] Suricata detects DOS alerts"
echo "  [ ] Events are indexed in Elasticsearch"
echo "Run on the host: scripts/scenario_e2e_check.sh S4"
