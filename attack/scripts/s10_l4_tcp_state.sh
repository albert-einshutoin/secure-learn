#!/bin/bash
# SOC-Lab Attack Script: S10 - L4 TCP State
# Purpose: Compare TCP flag scans and connection-state visibility.

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

SCAN_PORTS="${SCAN_PORTS:-1-128,3000}"
OUTPUT_DIR="${OUTPUT_DIR:-/results}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s10_l4_tcp_state_$(date +%Y%m%d_%H%M%S).txt"

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

    run_scan "TCP connect baseline" nc -vz -w 3 "$TARGET_IP" "$TARGET_PORT"
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
