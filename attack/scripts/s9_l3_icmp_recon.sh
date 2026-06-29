#!/bin/bash
# SOC-Lab Attack Script: S9 - L3 ICMP Recon
# Purpose: Exercise IP reachability checks and ICMP detection.

set -euo pipefail

TARGET="${TARGET:-app}"
OUTPUT_DIR="${OUTPUT_DIR:-/results}"
PING_COUNT="${PING_COUNT:-6}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s9_l3_icmp_recon_$(date +%Y%m%d_%H%M%S).txt"

resolve_target_ip() {
    getent hosts "$TARGET" | awk '{print $1; exit}'
}

TARGET_IP="${TARGET_IP:-$(resolve_target_ip)}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: Could not resolve target: $TARGET" >&2
    exit 1
fi

{
    echo "============================================"
    echo "SOC-Lab Scenario S9: L3 ICMP Recon"
    echo "============================================"
    echo "Target: $TARGET ($TARGET_IP)"
    echo "Time: $(date -Iseconds)"
    echo ""

    echo "Phase 1: ICMP echo"
    ping -c "$PING_COUNT" -W 2 "$TARGET_IP" || true
    echo ""

    echo "Phase 2: Route observation"
    # Docker bridge paths are short, but traceroute still teaches the difference
    # between IP reachability and application-layer health.
    traceroute -n "$TARGET_IP" || true
    echo ""

    echo "Phase 3: Host discovery"
    nmap -sn "$TARGET_IP" || true
    echo ""

    echo "Check detection:"
    echo "  docker exec soc-lab-suricata grep -E 'L3|ICMP' /var/log/suricata/fast.log || true"
    echo "  Kibana KQL: event.module:suricata AND rule.name:*L3*"
} | tee "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"

