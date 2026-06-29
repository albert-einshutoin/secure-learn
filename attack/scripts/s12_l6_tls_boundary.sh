#!/bin/bash
# SOC-Lab Attack Script: S12 - L6 TLS Boundary
# Purpose: Show what happens when TLS is attempted against a plaintext service.

set -euo pipefail

TARGET="${TARGET:-app}"
TARGET_PORT="${TARGET_PORT:-3000}"
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
    curl -sS -o /dev/null -w 'HTTP %{http_code}, time %{time_total}s\n' "http://$TARGET:$TARGET_PORT/health" || true
    echo ""

    echo "Phase 2: TLS ClientHello to plaintext HTTP port"
    # The expected failure is the lesson: without TLS termination, IDS and app
    # logs see a malformed connection rather than decrypted HTTP content.
    timeout 8 openssl s_client -connect "$TARGET:$TARGET_PORT" -servername "$TARGET" -brief </dev/null || true
    echo ""

    echo "Phase 3: HTTPS curl to plaintext HTTP port"
    curl -vk --max-time 8 "https://$TARGET:$TARGET_PORT/health" || true
    echo ""

    echo "Check detection:"
    echo "  docker exec soc-lab-suricata tail -50 /var/log/suricata/fast.log"
    echo "  Compare what is visible before and after TLS termination."
} | tee "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"

