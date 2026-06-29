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
  rg -q "$term" "$ROOT_DIR/learning/phases.json" "$ROOT_DIR/scripts/generate_scenario_html.js" "$ROOT_DIR/docs" || fail "missing required curriculum term: $term"
done

for file in "$ROOT_DIR"/docs/scenario-guides/s*.html "$ROOT_DIR"/docs/learning-phases/p*.html; do
  grep -q '抽象的に何を学ぶか' "$file" || fail "$(basename "$file") missing abstract explanation"
  grep -q '具体例' "$file" || fail "$(basename "$file") missing concrete examples"
  grep -q 'Hands-on Flow' "$file" || fail "$(basename "$file") missing hands-on flow"
  grep -q '合格証跡' "$file" || fail "$(basename "$file") missing evidence gate"
done

echo "World-class curriculum check passed."
