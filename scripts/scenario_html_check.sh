#!/bin/bash
# Validate generated scenario guides without requiring a browser runtime.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUIDE_DIR="$ROOT_DIR/docs/scenario-guides"

expected_pages=(
  "index.html"
  "s1-portscan.html"
  "s2-bruteforce.html"
  "s3-sqli.html"
  "s4-dos.html"
  "s5-file-tamper.html"
  "s6-privesc.html"
  "s7-lateral.html"
  "s8-arp.html"
  "s9-icmp.html"
  "s10-tcp-state.html"
  "s11-session-stress.html"
  "s12-tls-boundary.html"
  "s13-dns.html"
  "s14-sre-incident.html"
  "s15-capstone.html"
)

fail() {
  echo "scenario html check failed: $*" >&2
  exit 1
}

[[ -f "$GUIDE_DIR/assets/scenario.css" ]] || fail "missing assets/scenario.css"

for page in "${expected_pages[@]}"; do
  file="$GUIDE_DIR/$page"
  [[ -f "$file" ]] || fail "missing $page"
  grep -q '<!doctype html>' "$file" || fail "$page does not look like HTML"
  grep -q '<html lang="ja">' "$file" || fail "$page must declare Japanese language"
  grep -q '<h1>' "$file" || fail "$page is missing h1"
done

scenario_pages=("$GUIDE_DIR"/s*.html)
[[ "${#scenario_pages[@]}" -eq 15 ]] || fail "expected 15 scenario pages, found ${#scenario_pages[@]}"

for file in "${scenario_pages[@]}"; do
  grep -q 'Hands-on Flow' "$file" || fail "$(basename "$file") is missing hands-on flow"
  grep -q 'ツール活用' "$file" || fail "$(basename "$file") is missing tool guidance"
  grep -q '合格証跡' "$file" || fail "$(basename "$file") is missing evidence criteria"
  grep -q '世界レベルへ足す課題' "$file" || fail "$(basename "$file") is missing world-class extension tasks"
done

if grep -R -n -E 'TODO|TBD|PLACEHOLDER' "$GUIDE_DIR"; then
  fail "placeholder text remains in generated guides"
fi

echo "Scenario HTML check passed."
