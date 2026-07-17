#!/bin/bash
# SOC-Lab Attack Script: S12 - L6 TLS Boundary
# Purpose: Show what happens when TLS is attempted against a plaintext service.

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

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s12_l6_tls_boundary_$(date +%Y%m%d_%H%M%S).txt"

{
    echo "============================================"
    echo "SOC-Lab Scenario S12: L6 TLS Boundary"
    echo "============================================"
    echo "Target: $TARGET:$TARGET_PORT"
    echo "Time: $(date -Iseconds)"
    echo ""

    echo "Phase 1: Plain HTTP baseline"
    curl -sS -H "Host: $TARGET" -o /dev/null -w 'HTTP %{http_code}, time %{time_total}s\n' "http://$TARGET_IP:$TARGET_PORT/health" || true
    echo ""

    echo "Phase 2: TLS ClientHello to plaintext HTTP port"
    # The expected failure is the lesson: without TLS termination, IDS and app
    # logs see a malformed connection rather than decrypted HTTP content.
    timeout 8 openssl s_client -connect "$TARGET_IP:$TARGET_PORT" -servername "$TARGET" -brief </dev/null || true
    echo ""

    echo "Phase 3: HTTPS curl to plaintext HTTP port"
    curl -vk --max-time 8 -H "Host: $TARGET" "https://$TARGET_IP:$TARGET_PORT/health" || true
    echo ""

    echo "Check detection:"
    echo "  docker exec soc-lab-suricata tail -50 /var/log/suricata/fast.log"
    echo "  Compare what is visible before and after TLS termination."
} | tee "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"
