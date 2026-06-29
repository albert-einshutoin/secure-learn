#!/bin/bash
# Secure Learn SRE smoke gate.
# Purpose: fail fast when the lab is not healthy enough for hands-on exercises.

set -euo pipefail

APP_URL="${APP_URL:-http://localhost:3000/health}"
SAMPLES="${SAMPLES:-5}"
SLO_MS="${SLO_MS:-500}"

failures=0
max_ms=0
total_ms=0

echo "============================================"
echo "Secure Learn SRE Smoke Gate"
echo "============================================"
echo "URL: $APP_URL"
echo "Samples: $SAMPLES"
echo "Per-sample SLO: ${SLO_MS}ms"
echo "Time: $(date -Iseconds)"
echo ""

for i in $(seq 1 "$SAMPLES"); do
    metrics=$(curl -sS -o /dev/null -w '%{http_code} %{time_total}' --max-time 5 "$APP_URL" || echo "000 0")
    http_code=$(echo "$metrics" | awk '{print $1}')
    seconds=$(echo "$metrics" | awk '{print $2}')
    elapsed_ms=$(awk -v value="$seconds" 'BEGIN { printf "%d", value * 1000 }')

    total_ms=$((total_ms + elapsed_ms))
    if [ "$elapsed_ms" -gt "$max_ms" ]; then
        max_ms="$elapsed_ms"
    fi

    if [ "$http_code" != "200" ] || [ "$elapsed_ms" -gt "$SLO_MS" ]; then
        failures=$((failures + 1))
    fi

    printf 'sample=%s status=%s latency_ms=%s\n' "$i" "$http_code" "$elapsed_ms"
done

avg_ms=$((total_ms / SAMPLES))

echo ""
echo "Summary:"
echo "  avg_latency_ms=$avg_ms"
echo "  max_latency_ms=$max_ms"
echo "  failures=$failures"

if command -v docker >/dev/null 2>&1; then
    echo ""
    echo "Compose status:"
    # Compose status is advisory here. Health/SLO failure should drive the exit
    # code, while missing Docker output should not hide the app-level signal.
    docker compose ps || true
fi

if [ "$failures" -gt 0 ]; then
    echo ""
    echo "SLO gate failed: at least one sample was non-200 or slower than ${SLO_MS}ms." >&2
    exit 1
fi

echo ""
echo "SLO gate passed."

