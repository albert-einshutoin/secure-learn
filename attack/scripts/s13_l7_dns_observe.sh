#!/bin/bash
# SOC-Lab Attack Script: S13 - L7 DNS Observation
# Purpose: Observe Docker service discovery through DNS queries.

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

COUNT="${COUNT:-12}"
OUTPUT_DIR="${OUTPUT_DIR:-/results}"

secure_learn_validate_bounded_decimal COUNT "$COUNT" 1 20

resolved_target_ip="$(getent ahostsv4 "$TARGET" | awk 'NR == 1 { print $1; exit }')"
if [[ "$resolved_target_ip" != "$TARGET_IP" ]]; then
    echo "ERROR: $TARGET resolved outside its enumerated target profile." >&2
    exit 64
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s13_l7_dns_observe_$(date +%Y%m%d_%H%M%S).txt"

{
    echo "============================================"
    echo "SOC-Lab Scenario S13: L7 DNS Observation"
    echo "============================================"
    echo "Target service name: $TARGET"
    echo "Time: $(date -Iseconds)"
    echo ""

    echo "Phase 1: Resolver configuration"
    cat /etc/resolv.conf
    echo ""

    echo "Phase 2: Service name resolution"
    getent hosts "$TARGET" || true
    dig +short "$TARGET" || true
    echo ""

    echo "Phase 3: Repeated service discovery queries"
    # Repeated lookups model benign service discovery and give the detector a
    # small burst to observe without generating internet-bound DNS traffic.
    for i in $(seq 1 "$COUNT"); do
        dig +time=1 +tries=1 "$TARGET" >/dev/null || true
        if [ $((i % 4)) -eq 0 ]; then
            echo "  query $i/$COUNT"
        fi
    done
    echo ""

    echo "Check observation:"
    echo "  Docker embedded DNS is reached at 127.0.0.11 from this container."
    echo "  Because that resolver path is local to the container, Suricata on eth0 is not a stable DNS source for this scenario."
} | tee "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"
