#!/bin/bash
# Operate the phase-based learning Docker stack from one stable entry point.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHASE_FILE="$ROOT_DIR/learning/phases.json"

usage() {
  cat <<'USAGE'
Usage:
  scripts/learning_phase.sh list
  scripts/learning_phase.sh guide <p0..p19>
  scripts/learning_phase.sh config <p0..p19>
  scripts/learning_phase.sh start <p0..p19>
  scripts/learning_phase.sh stop <p0..p19>
  scripts/learning_phase.sh status <p0..p19>

Examples:
  scripts/learning_phase.sh list
  scripts/learning_phase.sh start p5
  scripts/learning_phase.sh guide p9
USAGE
}

normalize_phase() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

phase_json() {
  local phase="$1"
  python3 - "$PHASE_FILE" "$phase" <<'PY'
import json
import sys

path, wanted = sys.argv[1], sys.argv[2].lower()
with open(path, encoding="utf-8") as fh:
    phases = json.load(fh)

for phase in phases:
    if phase["id"].lower() == wanted or phase["slug"].lower() == wanted:
        print(json.dumps(phase, ensure_ascii=False))
        sys.exit(0)

print(f"unknown phase: {wanted}", file=sys.stderr)
sys.exit(2)
PY
}

phase_field() {
  local phase="$1"
  local field="$2"
  phase_json "$phase" | python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$field"
}

compose_for_profile() {
  local profile="$1"
  if [[ "$profile" == "base" ]]; then
    docker compose -f "$ROOT_DIR/docker-compose.yml" "${@:2}"
  else
    docker compose -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.learning.yml" --profile "$profile" "${@:2}"
  fi
}

list_phases() {
  python3 - "$PHASE_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    phases = json.load(fh)

print("Phase  Level          Docker profile          Title")
print("-----  -------------  ----------------------  --------------------------------")
for phase in phases:
    print(f'{phase["id"]:<5}  {phase["level"]:<13}  {phase["profile"]:<22}  {phase["title"]}')
PY
}

show_guide() {
  local phase="$1"
  local slug
  slug="$(phase_field "$phase" slug)"
  local file="$ROOT_DIR/docs/learning-phases/${slug}.html"
  [[ -f "$file" ]] || {
    echo "Guide not generated: $file" >&2
    exit 1
  }
  echo "$file"
}

main() {
  local action="${1:-}"
  local phase="${2:-}"

  case "$action" in
    list)
      list_phases
      ;;
    guide)
      [[ -n "$phase" ]] || { usage; exit 2; }
      show_guide "$(normalize_phase "$phase")"
      ;;
    config)
      [[ -n "$phase" ]] || { usage; exit 2; }
      compose_for_profile "$(phase_field "$(normalize_phase "$phase")" profile)" config -q
      ;;
    start)
      [[ -n "$phase" ]] || { usage; exit 2; }
      compose_for_profile "$(phase_field "$(normalize_phase "$phase")" profile)" up -d --build
      ;;
    stop)
      [[ -n "$phase" ]] || { usage; exit 2; }
      compose_for_profile "$(phase_field "$(normalize_phase "$phase")" profile)" down
      ;;
    status)
      [[ -n "$phase" ]] || { usage; exit 2; }
      compose_for_profile "$(phase_field "$(normalize_phase "$phase")" profile)" ps
      ;;
    ""|help|-h|--help)
      usage
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

main "$@"
