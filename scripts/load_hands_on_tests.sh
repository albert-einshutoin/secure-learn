#!/bin/bash
# Lightweight load gate for SRE hands-on practice.

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:3000}"
REQUESTS="${REQUESTS:-50}"
CONCURRENCY="${CONCURRENCY:-5}"
SLO_MS="${SLO_MS:-500}"
REPORT_DIR="${REPORT_DIR:-reports/load_hands_on_$(date +%Y%m%d_%H%M%S)}"

mkdir -p "$REPORT_DIR"
raw_file="$REPORT_DIR/raw.tsv"
summary_file="$REPORT_DIR/summary.md"

echo "============================================"
echo "Secure Learn Load Hands-on Tests"
echo "============================================"
echo "Base URL: $BASE_URL"
echo "Requests: $REQUESTS"
echo "Concurrency: $CONCURRENCY"
echo "SLO: p95 <= ${SLO_MS}ms with zero failures"
echo

seq "$REQUESTS" | xargs -P "$CONCURRENCY" -I{} sh -c '
  result=$(curl -sS -o /dev/null -w "%{http_code}\t%{time_total}" "$1/health" || printf "000\t999")
  printf "%s\n" "$result"
' _ "$BASE_URL" > "$raw_file"

failures=$(awk '$1 != 200 { count++ } END { print count + 0 }' "$raw_file")
latency_file="$REPORT_DIR/latency_ms.txt"
awk '{ print int($2 * 1000) }' "$raw_file" | sort -n > "$latency_file"
p95_rank=$(awk -v total="$REQUESTS" 'BEGIN { rank = int(total * 0.95); if (rank < 1) rank = 1; print rank }')
p95_ms=$(awk -v rank="$p95_rank" 'NR == rank { print; found = 1 } END { if (!found) print 0 }' "$latency_file")
avg_ms=$(awk '{ total += $1 } END { if (NR == 0) print 0; else print int(total / NR) }' "$latency_file")

cat > "$summary_file" << EOF
# Load Hands-on Test Report

- Date: $(date -Iseconds)
- Base URL: $BASE_URL
- Requests: $REQUESTS
- Concurrency: $CONCURRENCY
- Average latency ms: $avg_ms
- P95 latency ms: $p95_ms
- Failures: $failures
- SLO: p95 <= ${SLO_MS}ms with zero failures
EOF

echo "Average latency: ${avg_ms}ms"
echo "P95 latency: ${p95_ms}ms"
echo "Failures: $failures"
echo "Report: $summary_file"

if [ "$failures" -ne 0 ] || [ "$p95_ms" -gt "$SLO_MS" ]; then
  echo "Load gate failed."
  exit 1
fi

echo "Load gate passed."
