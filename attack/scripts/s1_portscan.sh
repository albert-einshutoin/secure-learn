#!/bin/bash
# SOC-Lab Attack Script: S1 - Port Scan
# Purpose: Demonstrate network reconnaissance detection

set -e

# Configuration
TARGET="${TARGET:-app}"
TARGET_IP="${TARGET_IP:-172.23.0.20}"
OUTPUT_DIR="/results"

echo "============================================"
echo "SOC-Lab Scenario S1: Port Scan"
echo "============================================"
echo ""
echo "Target: $TARGET ($TARGET_IP)"
echo "Time: $(date -Iseconds)"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to run scan and save results
run_scan() {
    local scan_name=$1
    shift
    local output_file="$OUTPUT_DIR/s1_${scan_name}_$(date +%Y%m%d_%H%M%S).txt"
    local command_display

    # Keep the executable and every argument as distinct values. This prevents
    # learner-controlled target text from being interpreted as shell syntax.
    printf -v command_display '%q ' "$@"
    
    echo "[$scan_name] Running: ${command_display% }"
    echo "  Output: $output_file"
    
    if ! "$@" > "$output_file" 2>&1; then
        echo "  ERROR: scan failed; see $output_file" >&2
        return 1
    fi
    
    echo "  Done."
    echo ""
}

echo "============================================"
echo "Phase 1: SYN Scan (Default)"
echo "============================================"
run_scan "syn_scan" nmap -sS -p 1-1000 "$TARGET_IP"

echo "============================================"
echo "Phase 2: Service Detection"
echo "============================================"
run_scan "service_scan" nmap -sV -p 80,3000,5432,9200 "$TARGET_IP"

echo "============================================"
echo "Phase 3: Aggressive Scan (OS + Version)"
echo "============================================"
run_scan "aggressive_scan" nmap -A -p 3000 "$TARGET_IP"

echo "============================================"
echo "Phase 4: Full Port Scan (Slow)"
echo "============================================"
run_scan "full_scan" nmap -sS -p- --max-rate 1000 "$TARGET_IP"

echo "============================================"
echo "Attack Complete"
echo "============================================"
echo ""
echo "Check the following for detection:"
echo ""
echo "1. Suricata logs:"
echo "   docker exec soc-lab-suricata cat /var/log/suricata/fast.log"
echo "   docker exec soc-lab-suricata jq 'select(.alert)' /var/log/suricata/eve.json"
echo ""
echo "2. Kibana:"
echo "   - Open http://localhost:5601"
echo "   - Search: event.module:suricata AND rule.name:*SCAN*"
echo ""
echo "Verification still required:"
echo "  [ ] Suricata detects SCAN alerts"
echo "  [ ] source.ip is correctly identified"
echo "  [ ] Events are indexed in Elasticsearch"
echo "Run on the host: scripts/scenario_e2e_check.sh S1"
