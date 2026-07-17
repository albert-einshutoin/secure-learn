#!/bin/bash
# Canonical static contract gate for curriculum truth and generated coverage.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="$(command -v node || true)"

[[ -x "$NODE_BIN" ]] || {
  echo "curriculum check failed: node is unavailable" >&2
  exit 1
}

coverage_fingerprint() {
  "$NODE_BIN" - "$ROOT_DIR/docs/curriculum/coverage.md" <<'NODE'
const crypto = require('node:crypto');
const fs = require('node:fs');
const file = process.argv[2];
const stat = fs.statSync(file, { bigint: true });
process.stdout.write(JSON.stringify({
  ino: String(stat.ino),
  mode: String(stat.mode),
  size: String(stat.size),
  mtimeNs: String(stat.mtimeNs),
  sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
}));
NODE
}

# The contract suite must be read-only with respect to the tracked report;
# otherwise a stale checkout could repair itself before the freshness check.
coverage_before="$(coverage_fingerprint)"
"$NODE_BIN" --test \
  "$ROOT_DIR/test/curriculum-contract.test.js" \
  "$ROOT_DIR/test/target-policy.test.js" \
  "$ROOT_DIR/test/evidence-contract.test.js"
"$NODE_BIN" "$ROOT_DIR/scripts/learn" validate
"$NODE_BIN" "$ROOT_DIR/scripts/generate_curriculum_coverage.js" --check
coverage_after="$(coverage_fingerprint)"
[[ "$coverage_after" == "$coverage_before" ]] || {
  echo "curriculum check failed: tracked coverage changed during validation" >&2
  exit 1
}

echo "Curriculum check passed."
