#!/bin/bash
# Canonical static contract gate for curriculum truth and generated coverage.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="$(command -v node || true)"

[[ -x "$NODE_BIN" ]] || {
  echo "curriculum check failed: node is unavailable" >&2
  exit 1
}

"$NODE_BIN" --test \
  "$ROOT_DIR/test/curriculum-contract.test.js" \
  "$ROOT_DIR/test/target-policy.test.js" \
  "$ROOT_DIR/test/evidence-contract.test.js"
"$NODE_BIN" "$ROOT_DIR/scripts/learn" validate
"$NODE_BIN" "$ROOT_DIR/scripts/generate_curriculum_coverage.js" --check

echo "Curriculum check passed."
