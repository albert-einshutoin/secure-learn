#!/bin/bash
# SOC-Lab Attack Script: S10 - L4 TCP State
# Purpose: Compare TCP flag scans and connection-state visibility.

set -euo pipefail

TARGET="${TARGET:-app}"
TARGET_PORT="${TARGET_PORT:-3000}"
SCAN_PORTS="${SCAN_PORTS:-1-128,3000}"
OUTPUT_DIR="${OUTPUT_DIR:-/results}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s10_l4_tcp_state_$(date +%Y%m%d_%H%M%S).txt"

resolve_target_ip() {
    getent hosts "$TARGET" | awk '{print $1; exit}'
}

TARGET_IP="${TARGET_IP:-$(resolve_target_ip)}"

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: Could not resolve target: $TARGET" >&2
    exit 1
fi

run_scan() {
    local label="$1"
    shift

    echo "---- $label ----"
    "$@" || true
    echo ""
}

{
    echo "============================================"
    echo "SOC-Lab Scenario S10: L4 TCP State"
    echo "============================================"
    echo "Target: $TARGET ($TARGET_IP:$TARGET_PORT)"
    echo "Scan ports: $SCAN_PORTS"
    echo "Time: $(date -Iseconds)"
    echo ""

    run_scan "TCP connect baseline" nc -vz -w 3 "$TARGET" "$TARGET_PORT"
    run_scan "SYN scan" nmap -sS -p "$SCAN_PORTS" "$TARGET_IP"
    run_scan "TCP connect scan" nmap -sT -p "$SCAN_PORTS" "$TARGET_IP"
    run_scan "FIN scan" nmap -sF -p "$SCAN_PORTS" "$TARGET_IP"
    run_scan "NULL scan" nmap -sN -p "$SCAN_PORTS" "$TARGET_IP"
    run_scan "XMAS scan" nmap -sX -p "$SCAN_PORTS" "$TARGET_IP"

    echo "Check detection:"
    echo "  docker exec soc-lab-suricata grep -E 'L4|SCAN' /var/log/suricata/fast.log || true"
    echo "  docker exec soc-lab-app tail -50 /var/log/app/access.log"
} | tee "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"
