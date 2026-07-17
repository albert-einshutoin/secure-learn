#!/bin/bash
# SOC-Lab Attack Script: S9 - L3 ICMP Recon
# Purpose: Exercise IP reachability checks and ICMP detection.

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

OUTPUT_DIR="${OUTPUT_DIR:-/results}"
PING_COUNT="${PING_COUNT:-6}"

secure_learn_validate_bounded_decimal PING_COUNT "$PING_COUNT" 1 20

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s9_l3_icmp_recon_$(date +%Y%m%d_%H%M%S).txt"

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
