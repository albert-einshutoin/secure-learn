#!/bin/bash
# Static validation for phase-based learning Docker and generated phase guides.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHASE_FILE="$ROOT_DIR/learning/phases.json"
GUIDE_DIR="$ROOT_DIR/docs/learning-phases"

fail() {
  echo "learning phase check failed: $*" >&2
  exit 1
}

python3 - "$PHASE_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    phases = json.load(fh)

required = {"id", "slug", "level", "title", "profile", "roles", "skills", "objectives", "hands_on", "commands", "evidence", "next_gate"}
profiles = {"base", "phase5-observability", "phase6-release", "phase8-distributed", "capstone"}
ids = set()

if len(phases) != 10:
    raise SystemExit(f"expected 10 phases, found {len(phases)}")

for phase in phases:
    missing = required - phase.keys()
    if missing:
        raise SystemExit(f"{phase.get('id', '<unknown>')} missing keys: {sorted(missing)}")
    if phase["id"] in ids:
        raise SystemExit(f"duplicate phase id: {phase['id']}")
    ids.add(phase["id"])
    if phase["profile"] not in profiles:
        raise SystemExit(f"{phase['id']} has unknown profile: {phase['profile']}")
    for key in ("roles", "skills", "objectives", "hands_on", "commands", "evidence"):
        if not isinstance(phase[key], list) or not phase[key]:
            raise SystemExit(f"{phase['id']} {key} must be a non-empty list")
PY

node --check "$ROOT_DIR/scripts/generate_learning_phase_html.js"
"$ROOT_DIR/scripts/learning_phase.sh" list >/dev/null

for profile in phase5-observability phase6-release phase8-distributed capstone; do
  docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.learning.yml" --profile "$profile" config -q
done

[[ -f "$GUIDE_DIR/index.html" ]] || fail "missing generated index.html"
for slug in $(python3 - "$PHASE_FILE" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as fh:
    print("\n".join(phase["slug"] for phase in json.load(fh)))
PY
); do
  file="$GUIDE_DIR/$slug.html"
  [[ -f "$file" ]] || fail "missing generated guide: $slug.html"
  grep -q '<html lang="ja">' "$file" || fail "$slug.html must declare Japanese language"
  grep -q 'Hands-on Flow' "$file" || fail "$slug.html is missing hands-on flow"
  grep -q '合格証跡' "$file" || fail "$slug.html is missing evidence criteria"
done

if grep -R -n -E 'TODO|TBD|PLACEHOLDER' "$ROOT_DIR/learning" "$GUIDE_DIR"; then
  fail "placeholder text remains in learning phase files"
fi

if grep -R -n ':latest' "$ROOT_DIR/docker-compose.learning.yml" "$ROOT_DIR/learning/toolbox/Dockerfile"; then
  fail "learning Docker files must not use latest tags"
fi

echo "Learning phase check passed."
