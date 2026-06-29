#!/bin/bash
# Static coverage gate for the world-class curriculum and generated HTML.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "world-class curriculum check failed: $*" >&2
  exit 1
}

node --check "$ROOT_DIR/scripts/generate_scenario_html.js"
node --check "$ROOT_DIR/scripts/generate_learning_phase_html.js"

phase_count=$(python3 - "$ROOT_DIR/learning/phases.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    print(len(json.load(fh)))
PY
)
[[ "$phase_count" -ge 20 ]] || fail "expected at least 20 learning phases, found $phase_count"

scenario_count=$(find "$ROOT_DIR/docs/scenario-guides" -maxdepth 1 -type f -name 's*.html' | wc -l | tr -d ' ')
[[ "$scenario_count" -ge 33 ]] || fail "expected at least 33 scenario guides, found $scenario_count"

required_terms=(
  'cgroups'
  'seccomp'
  'eBPF'
  'SYN backlog'
  'mTLS'
  'BGP'
  'QUIC'
  'Helm'
  'Admission Controller'
  'AWS IAM'
  'KMS'
  'Terraform'
  'OPA'
  'burn-rate'
  'OpenTelemetry'
  'Kafka'
  'Temporal'
  'schema migration'
  'SSRF'
  'BOLA'
  'SBOM'
  'SAST'
  'Sigma'
  'YARA'
  'Sysmon'
  'flamegraph'
  'feature flag'
  'CVE'
  'CVSS'
)

for term in "${required_terms[@]}"; do
  grep -R -F -q "$term" "$ROOT_DIR/learning/phases.json" "$ROOT_DIR/scripts/generate_scenario_html.js" "$ROOT_DIR/docs" || fail "missing required curriculum term: $term"
done

for file in "$ROOT_DIR"/docs/scenario-guides/s*.html "$ROOT_DIR"/docs/learning-phases/p*.html; do
  grep -q '抽象的に何を学ぶか' "$file" || fail "$(basename "$file") missing abstract explanation"
  grep -q '具体例' "$file" || fail "$(basename "$file") missing concrete examples"
  grep -q '初学者の見方' "$file" || fail "$(basename "$file") missing beginner guidance"
  grep -q '経験者の深掘り' "$file" || fail "$(basename "$file") missing experienced guidance"
  grep -q '学習フロー図' "$file" || fail "$(basename "$file") missing learning diagram"
  grep -q '証跡の図' "$file" || fail "$(basename "$file") missing evidence diagram"
  grep -q '事前準備' "$file" || fail "$(basename "$file") missing prerequisites"
  grep -q '安全境界' "$file" || fail "$(basename "$file") missing safety boundary"
  grep -q 'Hands-on Flow' "$file" || fail "$(basename "$file") missing hands-on flow"
  grep -q '観測ポイント' "$file" || fail "$(basename "$file") missing observation points"
  grep -q 'よくある失敗' "$file" || fail "$(basename "$file") missing common mistakes"
  grep -q 'セルフレビュー' "$file" || fail "$(basename "$file") missing self-review prompts"
  grep -q '合格証跡' "$file" || fail "$(basename "$file") missing evidence gate"
done

for file in "$ROOT_DIR"/docs/scenario-guides/s*.html; do
  grep -q 'OSI / HTTP / 到達前の図' "$file" || fail "$(basename "$file") missing protocol layer diagram"
  grep -q 'HTTP通信の中の位置' "$file" || fail "$(basename "$file") missing HTTP request anatomy"
  grep -q 'Server / Middleware 到達前後' "$file" || fail "$(basename "$file") missing pre-app delivery map"
done

echo "World-class curriculum check passed."
